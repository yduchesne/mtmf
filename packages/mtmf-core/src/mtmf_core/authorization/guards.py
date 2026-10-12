"""Shared authorization pre/post-policy guards (PR 16 extraction).

These module-level functions are the exact structural and settled
constraint guards the authoritative single-Action
:class:`~mtmf_core.authorization.authorizer.Authorizer` applies around
policy evaluation. They are extracted so the internal ordered batch
authorizer (PR 16) can reuse the *same* security ordering instead of
duplicating potentially divergent logic: a batch must not be able to
weaken, reorder, or bypass a guard the single-Action Authorizer applies.

Extraction is behaviour-preserving. The single-Action Authorizer still
performs, in exactly this order:

1. structural session validation (DENY/``INVALID_CONTEXT`` on failure);
2. same-Tenant target or positively resolved management-scope check
   (DENY/``NO_MANAGEMENT_SCOPE`` on failure);
3. policy resolution and evaluation through the configured resolver;
4. declared-but-unresolved required constraints
   (DENY/``UNSUPPORTED_CONSTRAINT``);
5. strict scope dominance when explicitly required
   (DENY/``INSUFFICIENT_DOMINANCE``).

A policy DENY is final and is never converted to ALLOW by a later guard.
These helpers perform no persistence, no context retrieval, and no
authorization-context unioning.
"""

from __future__ import annotations

from mtmf_core.authorization.context import AuthorizationRequest, DominanceRequirement
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.dominance import strictly_dominates
from mtmf_core.authorization.management import is_extension_action
from mtmf_core.domain.errors import SessionContextError
from mtmf_core.domain.session import validate_session_context


def validate_request_session(request: AuthorizationRequest) -> AuthorizationDecision | None:
    """Validate the request's structural session, once.

    Returns a ``DENY/INVALID_CONTEXT`` decision when the supplied
    structural ``(Tenant, Principal, Identity)`` session facts are
    invalid, otherwise ``None``. It never consults the resolver and
    never produces ALLOW.
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
    return None


def target_is_permitted(request: AuthorizationRequest) -> bool:
    """Return whether the request's target Tenant is permitted.

    A request is permitted when its target is the session/supplied
    Tenant (same-Tenant evaluation) or when it carries a positively
    resolved TenantManagementGroup delegation
    (:func:`management_scope_is_valid`). It performs no policy
    evaluation.
    """
    if request.target_tenant_id == request.context.tenant.id:
        return True
    return management_scope_is_valid(request)


def apply_post_policy_guards(
    request: AuthorizationRequest,
    decision: AuthorizationDecision,
) -> AuthorizationDecision:
    """Apply the settled post-policy guards to one policy decision.

    A policy DENY (no match or matching DENY) is final and returned
    unchanged. Only a policy ALLOW is subject to the settled additional
    constraints, in the documented order: declared-but-unresolved
    required constraints first, then strict scope dominance when
    explicitly required. No guard can turn a DENY into ALLOW.
    """
    if not decision.allowed:
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


def management_scope_is_valid(request: AuthorizationRequest) -> bool:
    """Validate a trusted cross-Tenant TenantManagementGroup delegation.

    A delegated cross-Tenant evaluation is accepted only when:

    - the request carries a resolved management scope whose
      ``elevated_scope`` is established (positive coverage *and* explicit
      actor eligibility);
    - the action is not an application extension mutation, which a
      SYSTEM-defined management Role must never authorize; and
    - ``context.applicable_roles`` is exactly the resolved management Role,
      so no ordinary manager-Tenant Role policy is silently unioned in.

    The management Role still has to produce a matching ALLOW through the
    normal policy evaluation; this check only gates the cross-Tenant
    boundary.
    """
    resolution = request.management_scope
    if resolution is None or resolution.candidate is None:
        return False
    if resolution.elevated_scope is None:
        return False
    if is_extension_action(request.action):
        return False
    expected = resolution.candidate.management_role_urn.value
    return {role.urn.value for role in request.context.applicable_roles} == {expected}
