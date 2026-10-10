"""MTMF core authorization foundation.

PR 4 implements the first authoritative decision layer over the PR 3
policy primitives:

:class:`PermissionEvaluator` is the pure, deterministic,
side-effect-free *linear* policy resolver and the semantic
reference/oracle. It consumes an exact
:class:`~mtmf_core.domain.action.Action` and already-applicable
:class:`~mtmf_core.domain.role.Role` objects, reuses PR 3 permission
matching, selects the most-specific matching rules, applies
equal-specificity DENY precedence, and defaults to DENY when nothing
matches. It is not the default production evaluator: it remains the
oracle against which every other implementation is differentially
tested.

PR 8H productionizes the compiled-policy architecture:

:class:`CompiledPolicy` is the production pure-Python indexed policy
implementation. It compiles already-applicable Roles once into
immutable exact/wildcard indexes and evaluates each Action with at most
two dictionary lookups; it is the policy the default resolver builds.

:class:`AuthorizationPolicy` is the production policy seam: already
resolved, ``evaluate(action)`` only, plus diagnostics.
:class:`AuthorizationPolicyResolver` resolves a policy for a supplied
context; :class:`DefaultAuthorizationPolicyResolver` compiles
``context.applicable_roles`` into a :class:`CompiledPolicy` and wraps it
in an :class:`EffectivePolicy` (a diagnostics-only wrapper that retains
the context and delegates evaluation unchanged). :class:`Authorizer`
validates the supplied structural session/Tenant context, enforces
same-Tenant isolation, resolves and evaluates policy, and applies
explicitly requested settled additional constraints.

The Rust-backed
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
remains available for experimentation, differential testing, and
Rust/Python integration evidence but is experimental and non-default:
the normally constructed ``Authorizer()`` uses the pure-Python
:class:`CompiledPolicy` through the default resolver, with no backend
selector, environment selector, automatic fallback, or runtime feature
probe.

This is an internal foundation, not the future public service contract:
the exact public/audit decision record, authorization-context
representation, and retrieval layer remain unresolved and are not
invented here.
"""

from __future__ import annotations

from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.authorization.compiled_policy import CompiledPolicy
from mtmf_core.authorization.context import (
    AuthorizationContext,
    AuthorizationRequest,
    DominanceRequirement,
    UnsupportedConstraint,
)
from mtmf_core.authorization.decision import (
    AuthorizationDecision,
    AuthorizationEffect,
    DenyReason,
)
from mtmf_core.authorization.dominance import strictly_dominates
from mtmf_core.authorization.management import (
    ManagementScopeCandidate,
    ManagementScopeResolution,
    is_extension_action,
)
from mtmf_core.authorization.permission_evaluator import (
    PermissionEvaluationError,
    PermissionEvaluator,
)
from mtmf_core.authorization.policy import AuthorizationPolicy, EffectivePolicy
from mtmf_core.authorization.policy_resolver import (
    AuthorizationPolicyResolver,
    DefaultAuthorizationPolicyResolver,
)

__all__ = [
    "AuthorizationContext",
    "AuthorizationDecision",
    "AuthorizationEffect",
    "AuthorizationPolicy",
    "AuthorizationPolicyResolver",
    "AuthorizationRequest",
    "Authorizer",
    "CompiledPolicy",
    "DefaultAuthorizationPolicyResolver",
    "DenyReason",
    "DominanceRequirement",
    "EffectivePolicy",
    "ManagementScopeCandidate",
    "ManagementScopeResolution",
    "PermissionEvaluationError",
    "PermissionEvaluator",
    "UnsupportedConstraint",
    "is_extension_action",
    "strictly_dominates",
]
