"""Authorizer foundation: authoritative core decision orchestration.

The :class:`Authorizer` is the authoritative decision layer of
``mtmf-core``. It validates the supplied structural session/Tenant
context, enforces same-Tenant isolation, resolves the applicable policy
through the :class:`~mtmf_core.authorization.policy_resolver.AuthorizationPolicyResolver`
seam and evaluates the exact Action against the resolved
:class:`~mtmf_core.authorization.policy.AuthorizationPolicy`, and
applies explicitly requested settled additional constraints. A policy
DENY is final and can never be converted to ALLOW by another constraint;
missing, unsupported, or unresolved required context fails closed; an
unexpected internal failure propagates as an error and can never become
ALLOW.

Default path:

.. code-block:: text

    Authorizer()
      -> DefaultAuthorizationPolicyResolver
      -> EffectivePolicy(CompiledPolicy.compile(context.applicable_roles), context)
      -> CompiledPolicy.evaluate(action)

The default policy implementation is the pure-Python indexed
:class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`. The
Rust-backed
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
remains available for experimentation and differential testing but is
experimental and non-default; there is no environment selector, backend
selector, automatic fallback, or runtime feature probe.

Context retrieval is deliberately outside the Authorizer: this
foundation consumes caller-supplied, pre-filtered facts and never
queries persistence.
"""

from __future__ import annotations

from mtmf_core.authorization.context import AuthorizationRequest, DominanceRequirement
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.dominance import strictly_dominates
from mtmf_core.authorization.management import is_extension_action
from mtmf_core.authorization.policy_resolver import (
    AuthorizationPolicyResolver,
    DefaultAuthorizationPolicyResolver,
)
from mtmf_core.domain.errors import SessionContextError
from mtmf_core.domain.session import validate_session_context


class Authorizer:
    """The authoritative internal authorization decision component.

    This is an internal foundation, not a public API/DTO contract. It
    performs no persistence and no authorization-context retrieval. It
    depends only on the narrow :class:`AuthorizationPolicyResolver`
    policy-resolution seam; by default it uses the non-caching
    :class:`DefaultAuthorizationPolicyResolver`, which builds the
    production pure-Python indexed
    :class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`
    wrapped in an
    :class:`~mtmf_core.authorization.policy.EffectivePolicy` for
    context-aware diagnostics. A resolver/compilation/policy exception
    propagates fail-closed from the Authorizer and can never become a
    semantic DENY or an ALLOW.
    """

    def __init__(
        self,
        policy_resolver: AuthorizationPolicyResolver | None = None,
    ) -> None:
        """Create an Authorizer using ``policy_resolver`` (default:
        :class:`DefaultAuthorizationPolicyResolver`)."""
        self._policy_resolver = (
            policy_resolver if policy_resolver is not None else DefaultAuthorizationPolicyResolver()
        )

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Produce an explicit ALLOW or DENY for one internal request.

        Checks, in order:

        1. structural session validation (reusing the PR 2 validator);
        2. explicit same-Tenant target check (the validator positively
           established ``session.tenant_id == context.tenant.id``, so
           the target check also pins the session Tenant);
        3. policy resolution through the configured
           :class:`AuthorizationPolicyResolver` and evaluation against
           the produced :class:`AuthorizationPolicy` (any policy DENY is
           final);
        4. declared-but-unresolved required constraints (fail closed);
        5. strict scope dominance when explicitly required.

        Only when every required check succeeds is ALLOW returned.

        The policy is never resolved/compiled before session and
        target-Tenant validation: an invalid session or a cross-Tenant
        target returns its DENY without consulting the resolver.

        :raises Exception: unexpected internal/programmer failures
            (including resolver/compilation and policy-evaluation
            exceptions) are propagated rather than swallowed and
            mislabeled; callers never receive ALLOW from an exception
            path.
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

        # Tenant isolation: ordinary evaluation is same-Tenant. A
        # cross-Tenant target is considered only through an explicitly
        # resolved TenantManagementGroup scope (PR 11), and only when the
        # applicable policy is exactly the approved management Role; no
        # ordinary manager-Tenant Role may be unioned in.
        if request.target_tenant_id != context.tenant.id and not _management_scope_is_valid(
            request
        ):
            return AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)

        policy = self._policy_resolver.resolve(context)
        decision = policy.evaluate(request.action)
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


def _management_scope_is_valid(request: AuthorizationRequest) -> bool:
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
