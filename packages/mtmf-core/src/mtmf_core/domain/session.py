"""Security-significant session context.

Authentication establishes a session of the form ``(Tenant, Principal,
Identity)``. This module holds the plain value object and structural
validation only: no Roles, Permissions, Groups, authorization caches,
tokens, or IdP claims are attached.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from mtmf_core.domain.errors import SessionContextError
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.tenant import Tenant


@dataclass(frozen=True, slots=True)
class SessionContext:
    """The acting (Tenant, Principal, Identity) session.

    Stable IDs are used, never mutable names. The object is a plain
    context identifier and carries no authorization state.
    """

    tenant_id: DomainId
    principal_id: DomainId
    identity_id: DomainId


def validate_session_context(
    session: SessionContext,
    tenant: Tenant,
    principal: Principal,
    identity: Identity,
    principal_tenant_memberships: Iterable[PrincipalTenantMembership],
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
) -> None:
    """Validate the settled structural prerequisites of a session.

    Checks:

    - session IDs match the supplied Tenant, Principal, and Identity;
    - ``Identity.principal_id == Principal.id``;
    - an explicit PrincipalTenantMembership matches the Principal and
      session Tenant;
    - an explicit IdentityTenantMembership matches the Identity and
      session Tenant.

    This is structural validation only. It does not perform
    authentication or authorization, and it deliberately does not resolve
    ACTIVE/INACTIVE membership-admission semantics (unresolved), so it
    must not be presented as complete session admission.

    Authorization state from any other Tenant is never considered.

    :raises SessionContextError: on any structural mismatch.
    """
    if session.tenant_id != tenant.id:
        raise SessionContextError("session Tenant does not match the supplied Tenant")
    if session.principal_id != principal.id:
        raise SessionContextError("session Principal does not match the supplied Principal")
    if session.identity_id != identity.id:
        raise SessionContextError("session Identity does not match the supplied Identity")
    if identity.principal_id != principal.id:
        raise SessionContextError("session Identity does not belong to the session Principal")
    if not any(
        ptm.principal_id == principal.id and ptm.tenant_id == tenant.id
        for ptm in principal_tenant_memberships
    ):
        raise SessionContextError(
            "session Principal lacks a PrincipalTenantMembership in the session Tenant"
        )
    if not any(
        itm.identity_id == identity.id and itm.tenant_id == tenant.id
        for itm in identity_tenant_memberships
    ):
        raise SessionContextError(
            "session Identity lacks an IdentityTenantMembership in the session Tenant"
        )
