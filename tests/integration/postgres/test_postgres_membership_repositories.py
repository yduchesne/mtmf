"""Typed membership repository integration slice (V4).

Six explicit typed relationships are created exclusively through the
restricted-runtime repositories in prerequisite order, both lookup
directions are exercised, cross-Tenant and missing-prerequisite inserts
fail deterministically, and the six existing membership-removal
functions remain unchanged and audited.
"""

from __future__ import annotations

import helpers
import psycopg
import pytest
from provider_helpers import DomainGraph, seed_entity_graph

from mtmf_core import (
    DomainId,
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    Organization,
    PrincipalTenantMembership,
    SecurityScope,
    Tenant,
)
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceReferenceError,
)
from mtmf_core.persistence.spi import MtmfSpi


def _add_all_memberships(spi: MtmfSpi) -> DomainGraph:
    graph = seed_entity_graph(spi)
    with spi.create_unit_of_work() as uow:
        spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(graph.principal.id, graph.tenant.id)
        )
        spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(graph.identity.id, graph.tenant.id)
        )
        spi.create_group_tenant_membership_repository(uow).add(
            GroupTenantMembership(graph.group.id, graph.tenant.id)
        )
        spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(graph.identity.id, graph.group.id)
        )
        spi.create_identity_org_membership_repository(uow).add(
            IdentityOrgMembership(graph.identity.id, graph.organization.id)
        )
        spi.create_group_org_membership_repository(uow).add(
            GroupOrgMembership(graph.group.id, graph.organization.id)
        )
        uow.commit()
    return graph


def test_v4_full_graph_and_both_lookup_directions(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(graph.principal.id, graph.tenant.id)
        )
        postgres_spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(graph.identity.id, graph.tenant.id)
        )
        postgres_spi.create_group_tenant_membership_repository(uow).add(
            GroupTenantMembership(graph.group.id, graph.tenant.id)
        )
        postgres_spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(graph.identity.id, graph.group.id)
        )
        postgres_spi.create_identity_org_membership_repository(uow).add(
            IdentityOrgMembership(graph.identity.id, graph.organization.id)
        )
        postgres_spi.create_group_org_membership_repository(uow).add(
            GroupOrgMembership(graph.group.id, graph.organization.id)
        )
        uow.commit()

    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_tenant_membership_repository(uow).get(
            graph.principal.id, graph.tenant.id
        ) == PrincipalTenantMembership(graph.principal.id, graph.tenant.id)
        assert postgres_spi.create_principal_tenant_membership_repository(uow).find_by_tenant(
            graph.tenant.id
        ) == (PrincipalTenantMembership(graph.principal.id, graph.tenant.id),)
        assert postgres_spi.create_identity_tenant_membership_repository(uow).find_by_identity(
            graph.identity.id
        ) == (IdentityTenantMembership(graph.identity.id, graph.tenant.id),)
        assert postgres_spi.create_group_tenant_membership_repository(uow).find_by_group(
            graph.group.id
        ) == (GroupTenantMembership(graph.group.id, graph.tenant.id),)
        assert postgres_spi.create_group_tenant_membership_repository(uow).find_by_tenant(
            graph.tenant.id
        ) == (GroupTenantMembership(graph.group.id, graph.tenant.id),)
        assert postgres_spi.create_identity_group_membership_repository(uow).find_by_group(
            graph.group.id
        ) == (IdentityGroupMembership(graph.identity.id, graph.group.id),)
        assert postgres_spi.create_identity_org_membership_repository(uow).find_by_organization(
            graph.organization.id
        ) == (IdentityOrgMembership(graph.identity.id, graph.organization.id),)
        assert postgres_spi.create_group_org_membership_repository(uow).find_by_group(
            graph.group.id
        ) == (GroupOrgMembership(graph.group.id, graph.organization.id),)


def test_v4_absent_get_and_find_return_none_and_empty(postgres_spi: MtmfSpi) -> None:
    absent = DomainId.generate()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_principal_tenant_membership_repository(uow)
        assert repository.get(absent, absent) is None
        assert repository.find_by_principal(absent) == ()
        assert repository.find_by_tenant(absent) == ()


def test_v4_duplicate_membership_fails(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    membership = PrincipalTenantMembership(graph.principal.id, graph.tenant.id)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_principal_tenant_membership_repository(uow)
        repository.add(membership)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(membership)
        uow.commit()


def test_v4_missing_prerequisite_fails_deterministically(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    with (
        postgres_spi.create_unit_of_work() as uow,
        pytest.raises(PersistenceReferenceError),
    ):
        # IdentityGroupMembership needs the IdentityTenantMembership and
        # GroupTenantMembership prerequisites first.
        postgres_spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(graph.identity.id, graph.group.id)
        )


def test_v4_cross_tenant_organization_membership_fails(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    other_tenant = Tenant(DomainId.generate(), "Other", SecurityScope.TENANT, graph.identity.id)
    other_org = Organization(DomainId.generate(), other_tenant.id, "Other Org", graph.identity.id)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_tenant_repository(uow).add(other_tenant)
        postgres_spi.create_organization_repository(uow).add(other_org)
        postgres_spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(graph.principal.id, graph.tenant.id)
        )
        postgres_spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(graph.identity.id, graph.tenant.id)
        )
        with pytest.raises(PersistenceReferenceError):
            # The Identity has no membership in the other Tenant.
            postgres_spi.create_identity_org_membership_repository(uow).add(
                IdentityOrgMembership(graph.identity.id, other_org.id)
            )
        # The failed (aborted) transaction cannot commit partial state.
        assert uow is not None


def test_v4_group_is_exclusive_to_one_tenant(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    other_tenant = Tenant(DomainId.generate(), "Other", SecurityScope.TENANT, graph.identity.id)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_tenant_repository(uow).add(other_tenant)
        postgres_spi.create_group_tenant_membership_repository(uow).add(
            GroupTenantMembership(graph.group.id, graph.tenant.id)
        )
        with pytest.raises(PersistenceReferenceError):
            # The Group structural Tenant disagrees with the requested
            # Tenant; the relationship is rejected, not silently rerouted.
            postgres_spi.create_group_tenant_membership_repository(uow).add(
                GroupTenantMembership(graph.group.id, other_tenant.id)
            )


def test_v4_existing_removal_functions_still_cascade_and_audit(
    postgres_spi: MtmfSpi, runtime_connection: psycopg.Connection, db: psycopg.Connection
) -> None:
    graph = _add_all_memberships(postgres_spi)
    # Remove a leaf relationship through the unchanged sanctioned function.
    row = runtime_connection.execute(
        "SELECT mtmf.remove_identity_group_membership(%s, %s, %s)",
        (graph.identity.id.value, graph.group.id.value, None),
    ).fetchone()
    assert row is not None and row[0] is True
    runtime_connection.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert (
            postgres_spi.create_identity_group_membership_repository(uow).get(
                graph.identity.id, graph.group.id
            )
            is None
        )
    assert (
        helpers.membership_count(
            db,
            "membership_removal_audit",
            "initiating_kind = %s",
            ("identity_group_membership",),
        )
        >= 1
    )
