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

        # Tenant isolation: no Role/policy from another Tenant may be
        # introduced. A target outside the session/supplied Tenant fails
        # closed; cross-Tenant management belongs to later delegation
        # work and is never enabled here.
        if request.target_tenant_id != context.tenant.id:
            return AuthorizationDecision.deny(DenyReason.TENANT_MISMATCH)

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
