"""Authorizer foundation: authoritative core decision orchestration.

The :class:`Authorizer` is the authoritative decision layer of
``mtmf-core``. It validates the supplied structural session/Tenant
context, enforces same-Tenant isolation, delegates policy resolution to
an evaluator behind the narrow
:class:`~mtmf_core.authorization.evaluator.PermissionEvaluatorProtocol`
seam (by default the Rust-backed
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`,
with the Python reference
:class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
explicitly injectable), and applies explicitly requested settled
additional constraints. A policy DENY is final and can never be
converted to ALLOW by another constraint; missing, unsupported, or
unresolved required context fails closed; an unexpected internal
failure propagates as an error and can never become ALLOW.

Context retrieval is deliberately outside the Authorizer: this
foundation consumes caller-supplied, pre-filtered facts and never
queries persistence.
"""

from __future__ import annotations

from mtmf_core.authorization.context import AuthorizationRequest, DominanceRequirement
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.dominance import strictly_dominates
from mtmf_core.authorization.evaluator import PermissionEvaluatorProtocol
from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator
from mtmf_core.domain.errors import SessionContextError
from mtmf_core.domain.session import validate_session_context


class Authorizer:
    """The authoritative internal authorization decision component.

    This is an internal foundation, not a public API/DTO contract. It
    performs no persistence and no authorization-context retrieval. It
    depends only on the narrow :class:`PermissionEvaluatorProtocol`
    policy-evaluation seam; by default it uses the Rust-backed
    :class:`RustPermissionEvaluator`, and the Python reference
    :class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
    remains injectable for tests and reference/comparison work. A native
    evaluation/infrastructure failure propagates fail-closed from the
    evaluator and can never become a semantic DENY or an ALLOW.
    """

    def __init__(self, evaluator: PermissionEvaluatorProtocol | None = None) -> None:
        """Create an Authorizer using ``evaluator`` (default: RustPermissionEvaluator)."""
        self._evaluator = evaluator if evaluator is not None else RustPermissionEvaluator()

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Produce an explicit ALLOW or DENY for one internal request.

        Checks, in order:

        1. structural session validation (reusing the PR 2 validator);
        2. explicit same-Tenant target check (the validator positively
           established ``session.tenant_id == context.tenant.id``, so
           the target check also pins the session Tenant);
        3. policy resolution through :class:`PermissionEvaluator` (any
           policy DENY is final);
        4. declared-but-unresolved required constraints (fail closed);
        5. strict scope dominance when explicitly required.

        Only when every required check succeeds is ALLOW returned.

        :raises Exception: unexpected internal/programmer failures are
            propagated rather than swallowed and mislabeled; callers
            never receive ALLOW from an exception path.
        """
        context = request.context
        try:
            validate_session_context(
                context.session,
                context.tenant,
                context.principal,
                context.identity,
                context.principal_tenant_memberships,
                context.identity_tenant_memberships,
            )
        except SessionContextError:
            # Deterministic structurally invalid/unsupported supplied
            # context produces a semantic DENY, never an ALLOW.
            return AuthorizationDecision.deny(DenyReason.INVALID_CONTEXT)

        # Tenant isolation: no Role/policy from another Tenant may be
        # introduced. A target outside the session/supplied Tenant fails
        # closed; cross-Tenant management belongs to later delegation
        # work and is never enabled here.
        if request.target_tenant_id != context.tenant.id:
            return AuthorizationDecision.deny(DenyReason.TENANT_MISMATCH)

        decision = self._evaluator.evaluate(request.action, context.applicable_roles)
        if not decision.allowed:
            # Policy DENY (no match or matching DENY) is final: no other
            # constraint may turn it into ALLOW.
            return decision

        if request.unsupported_constraints:
            return AuthorizationDecision.deny(DenyReason.UNSUPPORTED_CONSTRAINT)

        if request.dominance_requirement is DominanceRequirement.STRICT:
            if request.subject_scope is None or request.target_scope is None:
                return AuthorizationDecision.deny(DenyReason.INSUFFICIENT_DOMINANCE)
            if not strictly_dominates(request.subject_scope, request.target_scope):
                # No alternate dominance (Stewardship/TenantManagementGroup)
                # fallback exists: strict dominance failure is final.
                return AuthorizationDecision.deny(DenyReason.INSUFFICIENT_DOMINANCE)

        return decision
