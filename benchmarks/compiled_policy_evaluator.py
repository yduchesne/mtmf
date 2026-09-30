"""Experimental compiled-policy evaluator adapter (PR 8G).

PR 8G tests an architectural hypothesis: compile already-applicable
Role policy once into an opaque immutable native indexed
representation, then evaluate many Actions without repeatedly
traversing Roles/PermissionSets, transferring policy, parsing
Permission URNs, or scanning all Permissions.

This module is **experimental benchmark code only**. It is NOT the
production protocol or default: after 8G the production path remains
::

    Authorizer()
      -> RustPermissionEvaluator
      -> native_evaluate(action, policy)

The :class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
and the :class:`~mtmf_core.authorization.authorizer.Authorizer` are
unchanged by this adapter, no backend selection, environment-var
selection, fallback, or production cache exists, and the native
compiled-policy object is reached only through here.

Conceptual API (per the detailed plan):

    evaluated = CompiledPolicyEvaluator.compile(roles)
    decision = evaluated.evaluate(action)      # repeated, no recompile

The adapter:

- validates Role/PermissionSet ownership before any native call
  (identical structural check to the production evaluator);
- flattens the applicable Roles to the existing PR 8E primitive
  representation and compiles once through the private
  ``_mtmf_permission_engine.compile_policy`` bridge;
- reuses the opaque native policy object unchanged;
- validates the native response (same coherent-state matrix as the
  production adapter) and maps it to the same
  :class:`AuthorizationDecision` value the production evaluator
  returns, so complete-decision differential tests can compare
  ``P == R == C``.

Failures fail closed with
:class:`PermissionEvaluationInfrastructureError`: a native module that
is unavailable, a missing/incapable compiled capability, malformed
compile input, or a malformed/incoherent native result is never a
policy DENY and never an ALLOW, and there is no Python fallback.
Structurally corrupted domain policy (ownership corruption) fails with
:class:`PermissionEvaluationError` before any native call, exactly like
the production Python and Rust evaluators.
"""

from __future__ import annotations

from collections.abc import Iterable

from mtmf_core.authorization.decision import AuthorizationDecision
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    RustEvaluation,
    _validate_native_evaluation,
    native_compile_policy,
)
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    _map_native_evaluation,
)
from mtmf_core.domain.action import Action
from mtmf_core.domain.role import Role

# The opaque native compiled object. Only duck-typed through the
# validated ``evaluate`` capability; no PyO3 type is imported here.
CompiledNativePolicy = object


class CompiledPolicyEvaluator:
    """One immutable compiled policy, constructed once and reused.

    ``compile`` consumes an iterable of already-applicable Roles
    exactly once (never assumed rewindable), validates ownership,
    flattens the policy, and compiles it natively once. ``evaluate``
    then resolves any number of exact Actions against the compiled
    policy without recompiling, retransferring, reparsing, sorting, or
    scanning policy.
    """

    __slots__ = ("_compiled",)

    def __init__(self, compiled: CompiledNativePolicy) -> None:
        self._compiled = compiled

    @classmethod
    def compile(cls, roles: Iterable[Role]) -> CompiledPolicyEvaluator:
        """Compile caller-supplied applicable Roles into one policy.

        :raises PermissionEvaluationError: for structurally corrupted
            domain policy (ownership corruption), before any native call.
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
            compiled = native_compile_policy(primitive_sets)
        except (
            RustEngineUnavailableError,
            RustEngineCapabilityError,
            ValueError,
            TypeError,
        ) as exc:
            raise PermissionEvaluationInfrastructureError(
                "compiled-policy compilation failed; the protected operation must fail "
                "closed because no ALLOW decision can be produced"
            ) from exc
        return cls(compiled)

    def evaluate(self, action: Action) -> AuthorizationDecision:
        """Decide one exact Action against the compiled policy.

        :raises PermissionEvaluationInfrastructureError: for any native
            failure (malformed Action URN, malformed/incoherent native
            response); never a policy decision.
        """
        try:
            native_response = self._compiled.evaluate(action.urn.value)
            evaluation: RustEvaluation = _validate_native_evaluation(native_response)
        except (
            RustEngineUnavailableError,
            RustEngineCapabilityError,
            ValueError,
            TypeError,
        ) as exc:
            raise PermissionEvaluationInfrastructureError(
                "compiled-policy evaluation failed; the protected operation must fail "
                "closed because no ALLOW decision can be produced"
            ) from exc
        return _map_native_evaluation(evaluation)

    @property
    def compiled(self) -> CompiledNativePolicy:
        """The reused opaque native policy object (read-only)."""
        return self._compiled
