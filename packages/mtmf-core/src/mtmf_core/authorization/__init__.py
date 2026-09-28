"""MTMF core authorization foundation.

PR 4 implements the first authoritative decision layer over the PR 3
policy primitives:

:class:`PermissionEvaluator` is the pure, deterministic,
side-effect-free policy resolver. It consumes an exact
:class:`~mtmf_core.domain.action.Action` and already-applicable
:class:`~mtmf_core.domain.role.Role` objects, reuses PR 3 permission
matching, selects the most-specific matching rules, applies
equal-specificity DENY precedence, and defaults to DENY when nothing
matches.

:class:`Authorizer` is the authoritative core decision orchestration.
It validates the supplied structural session/Tenant context, enforces
same-Tenant isolation, delegates policy resolution to the evaluator, and
applies explicitly requested settled additional constraints. Missing,
unknown, unsupported, or unresolved required context fails closed;
unexpected internal failures propagate and can never become ALLOW.

This is an internal foundation, not the future public service contract:
the exact public/audit decision record, authorization-context
representation, and retrieval layer remain unresolved and are not
invented here.
"""

from __future__ import annotations

from mtmf_core.authorization.authorizer import Authorizer
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
from mtmf_core.authorization.permission_evaluator import (
    PermissionEvaluationError,
    PermissionEvaluator,
)

__all__ = [
    "AuthorizationContext",
    "AuthorizationDecision",
    "AuthorizationEffect",
    "AuthorizationRequest",
    "Authorizer",
    "DenyReason",
    "DominanceRequirement",
    "PermissionEvaluationError",
    "PermissionEvaluator",
    "UnsupportedConstraint",
    "strictly_dominates",
]
