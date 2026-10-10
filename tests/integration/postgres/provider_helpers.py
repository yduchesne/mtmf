"""Shared helpers for the PostgreSQL provider integration slices (V1-V6).

The helpers build a canonical domain graph strictly through the
production repositories in prerequisite order (Principal -> Identity ->
Tenant -> Organization/Group), so foreign-key and structural
prerequisites are satisfied without seeding rows directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core import (
    DomainId,
    Group,
    Identity,
    IdentityOrigin,
    Organization,
    Principal,
    SecurityScope,
    Tenant,
    TenantLifecycle,
)
from mtmf_core.persistence.spi import MtmfSpi


@dataclass(frozen=True, slots=True)
class DomainGraph:
    """A detached canonical entity graph created through the repositories."""

    principal: Principal
    identity: Identity
    tenant: Tenant
    organization: Organization
    group: Group


def seed_entity_graph(spi: MtmfSpi) -> DomainGraph:
    """Create and commit one canonical entity graph through the repositories."""
    principal = Principal(DomainId.generate(), "Principal")
    identity = Identity(DomainId.generate(), principal.id, "Identity", IdentityOrigin.LOCAL)
    # New ordinary Tenants start PROVISIONING (non-authorizing); the
    # protected activation path is exercised where authorization matters.
    tenant = Tenant(
        DomainId.generate(),
        "Tenant",
        SecurityScope.TENANT,
        identity.id,
        lifecycle=TenantLifecycle.PROVISIONING,
    )
    organization = Organization(DomainId.generate(), tenant.id, "Organization", identity.id)
    group = Group(DomainId.generate(), tenant.id, "Group")
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        spi.create_tenant_repository(uow).add(tenant)
        spi.create_organization_repository(uow).add(organization)
        spi.create_group_repository(uow).add(group)
        uow.commit()
    return DomainGraph(principal, identity, tenant, organization, group)
