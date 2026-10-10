"""Typed contextual TenantManagementGroup result consumed by the Authorizer.

This module owns the small, detached value types that describe resolved
TenantManagementGroup coverage and eligibility. They are produced by the
application layer's fail-closed
:func:`~mtmf_core.application.management_scope.resolve_management_scope`
and consumed by the authoritative
:class:`~mtmf_core.authorization.authorizer.Authorizer`.

A candidate is a structural coverage match and never an authorization
grant. ``ManagementScopeResolution.elevated_scope`` is only non-``None``
when both coverage and explicit actor eligibility have been positively
established, and even then it is only an input to the management-Role
policy evaluation: the management Role must still independently authorize
the exact Action.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.management_group import TenantManagementScope

__all__ = [
    "ManagementScopeCandidate",
    "ManagementScopeResolution",
    "is_extension_action",
]


@dataclass(frozen=True, slots=True)
class ManagementScopeCandidate:
    """A structural contextual-coverage match, never an authorization grant."""

    management_group_id: DomainId
    scope: TenantManagementScope
    management_role_urn: RoleUrn


@dataclass(frozen=True, slots=True)
class ManagementScopeResolution:
    """Resolved coverage plus the explicit eligibility outcome."""

    candidate: ManagementScopeCandidate | None
    actor_eligible: bool
    blocked_reason: str | None

    @property
    def elevated_scope(self) -> TenantManagementScope | None:
        """The candidate scope that may be applied, or ``None``.

        Returns the candidate scope only when actor eligibility has been
        positively established. A management relationship alone never
        elevates authorization.
        """
        if self.candidate is not None and self.actor_eligible:
            return self.candidate.scope
        return None


def is_extension_action(action: Action) -> bool:
    """True when ``action`` is a ``<resource>:update-extension`` mutation.

    Extension mutation can never be authorized through a SYSTEM-defined
    management Role (:mod:`docs/SECURITY_MODEL.md` section 21); the
    Authorizer checks this explicitly on the delegated path as defense in
    depth even though the approved management Roles carry no such
    Permission.
    """
    urn = action.urn
    return urn.verb == "update" and urn.qualifier == "extension"
