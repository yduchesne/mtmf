"""Rust-backed domain-facing policy evaluator.

:class:`RustPermissionEvaluator` satisfies the same narrow internal
evaluator protocol as the Python reference
:class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
but delegates the pure policy computation to the private Rust kernel
through the internal ``rust_engine`` adapter.

Python still owns all authorization context, policy applicability,
Tenant/session validation, scope/dominance, stewardship/delegation,
operation-specific constraints, and fail-closed orchestration: this
evaluator converts the already-applicable Role policy it receives into
detached primitive PermissionSets and maps the validated native result
back to an :class:`~mtmf_core.authorization.decision.AuthorizationDecision`.
Role identity is deliberately not sent to Rust, and no authorization
context ever crosses the FFI boundary.

Failure semantics are fail-closed: a native module that is unavailable,
a missing/incapable native evaluator, malformed or incoherent native
output, or an unexpectedly malformed or wrong-typed primitive reaching
the native boundary is an evaluation/infrastructure failure that
propagates as :class:`PermissionEvaluationInfrastructureError`. It is
never converted into a semantic DENY, never becomes an ALLOW, and never
silently falls back to the Python reference implementation.
"""

from __future__ import annotations

from collections.abc import Iterable

from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.evaluator import PermissionEvaluatorProtocol
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.authorization.rust_engine import (
    _NATIVE_ALLOW,
    _NATIVE_DENY,
    _NATIVE_EXACT,
    _NATIVE_MATCHED_DENY,
    _NATIVE_NO_MATCH,
    _NATIVE_QUALIFIER_WILDCARD,
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    RustEvaluation,
    native_evaluate,
)
from mtmf_core.domain.action import Action
from mtmf_core.domain.permission_matching import MatchSpecificity
from mtmf_core.domain.role import Role


class PermissionEvaluationInfrastructureError(RuntimeError):
    """A narrow evaluator/infrastructure failure, never a policy DENY.

    Raised when the Rust-backed evaluator cannot complete because the
    private native module is unavailable, a native capability is
    missing/incapable, the native response is malformed or incoherent,
    or an unexpectedly malformed primitive reached the native parser.

    This is deliberately distinct from :class:`PermissionEvaluationError`
    (structurally corrupted *domain policy*) and from any
    :class:`AuthorizationDecision`: no native failure may masquerade as
    a semantic policy DENY, and no failure path may produce ALLOW.
    """


class RustPermissionEvaluator(PermissionEvaluatorProtocol):
    """Rust-backed policy resolver over already-applicable Role policy.

    Semantically equivalent to the Python reference evaluator: it
    matches every supplied Permission, retains only the maximum
    specificity, discards lower specificity before effect resolution,
    applies equal-specificity DENY precedence, and defaults to DENY when
    nothing matches. Role order, PermissionSet order, Permission order,
    and duplicates never affect the result.

    ``roles`` is consumed exactly once as an iterable; it is never
    assumed to be rewindable and it is never evaluated more than once.
    """

    def evaluate(self, action: Action, roles: Iterable[Role]) -> AuthorizationDecision:
        """Decide one exact Action against caller-supplied applicable Roles.

        Structural validation runs before any native call: a
        PermissionSet whose ``role_urn`` disagrees with its owning Role
        is corrupted domain policy and fails closed with
        :class:`PermissionEvaluationError`.

        :raises PermissionEvaluationError: for structurally corrupted
            domain policy (impossible under PR 3 construction).
        :raises PermissionEvaluationInfrastructureError: for any native
            unavailability, capability, parsing, or malformed/incoherent
            response failure; never a policy decision.
        """
        primitive_sets: list[tuple[str, list[str]]] = []
        for role in roles:
            for permission_set in role.permission_sets:
                if permission_set.role_urn != role.urn:
                    raise PermissionEvaluationError(
                        f"PermissionSet {permission_set.id} is owned by "
                        f"{permission_set.role_urn}, not by supplied Role {role.urn}"
                    )
                primitive_sets.append(
                    (
                        permission_set.effect.value,
                        [permission.urn.value for permission in permission_set.permissions],
                    )
                )
        try:
            evaluation = native_evaluate(action.urn.value, primitive_sets)
        except (
            RustEngineUnavailableError,
            RustEngineCapabilityError,
            ValueError,
            TypeError,
        ) as exc:
            raise PermissionEvaluationInfrastructureError(
                "Rust permission evaluation failed; the protected operation must fail "
                "closed because no ALLOW decision can be produced"
            ) from exc
        return _map_native_evaluation(evaluation)


def _map_native_specificity(specificity: str | None) -> MatchSpecificity | None:
    """Map the validated native specificity text to the Python enum."""
    if specificity is None:
        return None
    if specificity == _NATIVE_EXACT:
        return MatchSpecificity.EXACT
    if specificity == _NATIVE_QUALIFIER_WILDCARD:
        return MatchSpecificity.QUALIFIER_WILDCARD
    # Unreachable through the validated adapter; fail closed anyway so an
    # impossible value can never be misread as a policy outcome.
    raise PermissionEvaluationInfrastructureError(
        f"native evaluation returned an unknown match specificity {specificity!r}"
    )


def _map_native_evaluation(evaluation: RustEvaluation) -> AuthorizationDecision:
    """Map one validated :class:`RustEvaluation` to an :class:`AuthorizationDecision`.

    The lower-level adapter has already rejected malformed/incoherent
    native responses; this mapping remains exhaustive and fail-closed so
    an impossible validated value can never be converted into ALLOW or a
    semantic DENY.
    """
    specificity = _map_native_specificity(evaluation.matched_specificity)
    if evaluation.decision == _NATIVE_ALLOW:
        return AuthorizationDecision.allow(
            matched_specificity=specificity,
            matched_allow=True,
            matched_deny=False,
        )
    if evaluation.decision == _NATIVE_DENY:
        if evaluation.deny_reason == _NATIVE_NO_MATCH:
            return AuthorizationDecision.deny(DenyReason.NO_MATCH)
        if evaluation.deny_reason == _NATIVE_MATCHED_DENY:
            return AuthorizationDecision.deny(
                DenyReason.MATCHED_DENY,
                matched_specificity=specificity,
                matched_allow=evaluation.matched_allow,
                matched_deny=True,
            )
        raise PermissionEvaluationInfrastructureError(
            f"native evaluation returned an unknown deny reason {evaluation.deny_reason!r} "
            "for a DENY decision"
        )
    raise PermissionEvaluationInfrastructureError(
        f"native evaluation returned an unknown decision {evaluation.decision!r}"
    )
