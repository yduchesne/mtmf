"""Pure-Python CompiledPolicy control (PR 8G amendment).

The original PR 8G compared approximately:

    P   current Python linear evaluator
    R   current Rust linear evaluator
    RC  Rust CompiledPolicy

That cannot isolate whether the improvement comes from:

    A. compiling/indexing the policy, or
    B. implementing the compiled evaluator in Rust.

This module adds the missing experimental control:

    PC  Python CompiledPolicy

,the same semantic compilation model and indexed lookup algorithm as the
Rust ``CompiledPolicy`` in
``packages/mtmf-permission-engine/src/compiled_policy.rs``, implemented
in pure Python with no FFI:

    exact:
        ExactKey -> EffectAggregate        (namespace, resource, verb, qualifier)

    wildcard:
        WildcardKey -> EffectAggregate     (namespace, resource, verb)

The amended comparison is therefore P / R / PC / RC, and the most
important new comparison is PC vs RC.

PC is **experimental benchmark/control code only** and is never
production code: the Authorizer, the production
``RustPermissionEvaluator``, and the Python reference
``PermissionEvaluator`` are not modified by this module, PC is not
selectable as a backend, and no caching/invalidation/batching exists.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.domain.action import Action
from mtmf_core.domain.permission_matching import MatchSpecificity
from mtmf_core.domain.role import Role

# Semantic compound keys, mirroring the Rust `ExactKey`/`WildcardKey`
# (component text only; no Permission URN strings, no numeric IDs, no
# registry). The definition-namespace component is the canonical
# namespace text (e.g. "system"), which is what the Rust keys carry.
ExactKey = tuple[str, str, str, str]
WildcardKey = tuple[str, str, str]


# Conceptually mirrored from the Rust EffectAggregate; frozen because
# evaluation must never mutate compiled policy.
@dataclass(frozen=True, slots=True)
class EffectAggregate:
    """Pre-aggregated ALLOW/DENY evidence for one semantic key.

    Exactly mirrors the Rust ``EffectAggregate``: two booleans,
    ``matched_allow`` and ``matched_deny``. Duplicates do not vote; the
    flags are OR-accumulated during compilation. Every stored aggregate
    has at least one flag set, because every stored key originates from
    at least one parsed Permission.

    Frozen after construction: evaluation never mutates compiled policy.
    """

    matched_allow: bool
    matched_deny: bool


def _resolve_aggregate(
    specificity: MatchSpecificity, aggregate: EffectAggregate
) -> AuthorizationDecision:
    """Resolve one aggregated effect into the existing decision type.

    Mirrors the Rust resolution: an equal-specificity DENY wins, else a
    present ALLOW wins, with the complete evidence carried. An
    incoherent aggregate (neither flag; impossible under the current
    compiler) fails closed instead of guessing a decision.
    """
    if aggregate.matched_deny:
        return AuthorizationDecision.deny(
            DenyReason.MATCHED_DENY,
            matched_specificity=specificity,
            matched_allow=aggregate.matched_allow,
            matched_deny=True,
        )
    if aggregate.matched_allow:
        return AuthorizationDecision.allow(
            matched_specificity=specificity,
            matched_allow=True,
            matched_deny=False,
        )
    raise PermissionEvaluationError(
        f"incoherent compiled-policy aggregate for {specificity.value}; no ALLOW/DENY evidence"
    )


@dataclass(frozen=True, slots=True)
class PythonCompiledPolicy:
    """An immutable, indexed pure-Python compiled permission policy.

    Construction parses no URN text (the domain ``ActionUrn`` /
    ``PermissionUrn`` value objects are already parsed and validated by
    the domain) and performs every one-time policy cost: ownership
    validation, classification of each Permission as exact or
    qualifier-wildcard, and OR-aggregation of effects into per-key
    :class:`EffectAggregate` values.

    The compiled indexes are structurally immutable: private
    dictionaries wrapped in :class:`types.MappingProxyType` inside a
    frozen dataclass. Nothing can mutate them between evaluations.

    Evaluation performs direct dictionary lookups only: at most one
    EXACT lookup and one WILDCARD lookup per Action. There is no
    iteration over Roles, PermissionSets, Permissions, or index entries
    and no sorting - a hidden linear scan is impossible.
    """

    _exact: Mapping[ExactKey, EffectAggregate]
    _wildcard: Mapping[WildcardKey, EffectAggregate]

    @classmethod
    def compile(cls, roles: Iterable[Role]) -> PythonCompiledPolicy:
        """Compile already-applicable Role policy once.

        Reuses the already-parsed domain ``PermissionUrn`` semantic
        components (definition namespace, resource, verb, qualifier);
        the URN text is never reconstructed or reparsed.

        :raises PermissionEvaluationError: for structurally corrupted
            domain policy (``permission_set.role_urn != role.urn``),
            before any indexing; identical to ``PermissionEvaluator``,
            ``RustPermissionEvaluator``, and the Rust-compiled adapter.
        """
        exact_buckets: dict[ExactKey, tuple[bool, bool]] = {}
        wildcard_buckets: dict[WildcardKey, tuple[bool, bool]] = {}
        for role in roles:
            for permission_set in role.permission_sets:
                if permission_set.role_urn != role.urn:
                    raise PermissionEvaluationError(
                        f"PermissionSet {permission_set.id} is owned by "
                        f"{permission_set.role_urn}, not by supplied Role {role.urn}"
                    )
                is_allow = permission_set.effect.value == "allow"
                is_deny = not is_allow
                for permission in permission_set.permissions:
                    urn = permission.urn
                    namespace = urn.definition_namespace.value
                    resource = urn.resource
                    verb = urn.verb
                    if urn.is_wildcard:
                        key = (namespace, resource, verb)
                        allow, deny = wildcard_buckets.get(key, (False, False))
                        wildcard_buckets[key] = (allow or is_allow, deny or is_deny)
                    else:
                        key = (namespace, resource, verb, urn.qualifier)
                        allow, deny = exact_buckets.get(key, (False, False))
                        exact_buckets[key] = (allow or is_allow, deny or is_deny)
        exact = MappingProxyType(
            {key: EffectAggregate(allow, deny) for key, (allow, deny) in exact_buckets.items()}
        )
        wildcard = MappingProxyType(
            {key: EffectAggregate(allow, deny) for key, (allow, deny) in wildcard_buckets.items()}
        )
        return cls(exact, wildcard)

    def evaluate(self, action: Action) -> AuthorizationDecision:
        """Decide one exact Action against the compiled policy.

        Derives the EXACT Action key from the already-parsed domain
        ``ActionUrn`` components and performs direct index lookups:
        EXACT first (exact beats wildcard), then WILDCARD, then
        ``DENY / NO_MATCH``. No Policy/Permission scan and no sort.

        Deterministic, side-effect-free, and never mutates the policy.
        """
        urn = action.urn
        namespace = urn.definition_namespace.value
        resource = urn.resource
        verb = urn.verb
        qualifier = urn.qualifier
        aggregate = self._exact.get((namespace, resource, verb, qualifier))
        if aggregate is not None:
            return _resolve_aggregate(MatchSpecificity.EXACT, aggregate)
        aggregate = self._wildcard.get((namespace, resource, verb))
        if aggregate is not None:
            return _resolve_aggregate(MatchSpecificity.QUALIFIER_WILDCARD, aggregate)
        return AuthorizationDecision.deny(DenyReason.NO_MATCH)

    @property
    def exact(self) -> Mapping[ExactKey, EffectAggregate]:
        """Read-only EXACT index (testing/observability)."""
        return self._exact

    @property
    def wildcard(self) -> Mapping[WildcardKey, EffectAggregate]:
        """Read-only WILDCARD index (testing/observability)."""
        return self._wildcard

    @property
    def exact_key_count(self) -> int:
        """Number of distinct EXACT keys (testing/observability)."""
        return len(self._exact)

    @property
    def wildcard_key_count(self) -> int:
        """Number of distinct WILDCARD keys (testing/observability)."""
        return len(self._wildcard)
