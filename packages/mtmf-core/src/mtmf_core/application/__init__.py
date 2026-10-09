"""MTMF application layer.

The application layer coordinates MTMF use cases and transaction
boundaries above the domain/persistence boundary. It owns trusted
context assembly (for example effective-Role resolution) and must not be
mistaken for the authorization decision layer: the
:class:`~mtmf_core.authorization.authorizer.Authorizer` remains the
authoritative decision point.
"""

from __future__ import annotations

from mtmf_core.application.effective_roles import (
    EffectiveRoleIntegrityError,
    EffectiveRoleResolutionError,
    EffectiveRoleResolver,
    ResolvedAuthorizationState,
    build_authorization_context,
)

__all__ = [
    "EffectiveRoleIntegrityError",
    "EffectiveRoleResolutionError",
    "EffectiveRoleResolver",
    "ResolvedAuthorizationState",
    "build_authorization_context",
]
