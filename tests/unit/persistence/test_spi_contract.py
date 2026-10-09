"""MtmfSpi contract tests (plan matrix S01-S11).

Repository factories require an explicit UnitOfWork, reject foreign
UnitOfWorks, and share one transactional view per UnitOfWork. The SPI
must carry no migration, IdP, or database-driver surface.
"""

from __future__ import annotations

import pytest
from helpers import make_id, make_organization, make_tenant

from mtmf_core.persistence import (
    ActionRepository,
    ForeignUnitOfWorkError,
    GroupOrgMembershipRepository,
    GroupRepository,
    GroupRoleAssignmentRepository,
    GroupTenantMembershipRepository,
    IdentityGroupMembershipRepository,
    IdentityOrgMembershipRepository,
    IdentityRepository,
    IdentityRoleAssignmentRepository,
    IdentityTenantMembershipRepository,
    MtmfSpi,
    OrganizationRepository,
    PrincipalRepository,
    PrincipalTenantMembershipRepository,
    RoleRepository,
    TenantRepository,
    UnitOfWork,
)
from mtmf_core.persistence.testing import InMemoryMtmfSpi


def test_s01_create_unit_of_work_returns_independent_instances(spi: MtmfSpi) -> None:
    first = spi.create_unit_of_work()
    second = spi.create_unit_of_work()
    assert first is not second


def test_s02_create_repository_with_own_unit_of_work_succeeds(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    repositories = [
        spi.create_tenant_repository,
        spi.create_organization_repository,
        spi.create_principal_repository,
        spi.create_identity_repository,
        spi.create_group_repository,
        spi.create_role_repository,
        spi.create_action_repository,
        spi.create_identity_role_assignment_repository,
        spi.create_group_role_assignment_repository,
        spi.create_principal_tenant_membership_repository,
        spi.create_identity_tenant_membership_repository,
        spi.create_group_tenant_membership_repository,
        spi.create_identity_group_membership_repository,
        spi.create_identity_org_membership_repository,
        spi.create_group_org_membership_repository,
    ]
    for factory in repositories:
        assert factory(uow) is not None


def test_s03_multiple_repositories_share_one_transaction(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    organization = make_organization(tenant_id=tenant.id)
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        organizations = spi.create_organization_repository(uow)
        tenants.add(tenant)
        organizations.add(organization)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_repository(uow).get(tenant.id) == tenant
        assert spi.create_organization_repository(uow).get(organization.id) == organization


def test_s04_create_all_defined_repositories(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        tenant_repo = spi.create_tenant_repository(uow)
        organization_repo = spi.create_organization_repository(uow)
        principal_repo = spi.create_principal_repository(uow)
        identity_repo = spi.create_identity_repository(uow)
        group_repo = spi.create_group_repository(uow)
        role_repo = spi.create_role_repository(uow)
        action_repo = spi.create_action_repository(uow)
        iram = spi.create_identity_role_assignment_repository(uow)
        gram = spi.create_group_role_assignment_repository(uow)
        ptm = spi.create_principal_tenant_membership_repository(uow)
        itm = spi.create_identity_tenant_membership_repository(uow)
        gtm = spi.create_group_tenant_membership_repository(uow)
        igm = spi.create_identity_group_membership_repository(uow)
        iom = spi.create_identity_org_membership_repository(uow)
        gom = spi.create_group_org_membership_repository(uow)
    assert isinstance(tenant_repo, TenantRepository)
    assert isinstance(organization_repo, OrganizationRepository)
    assert isinstance(principal_repo, PrincipalRepository)
    assert isinstance(identity_repo, IdentityRepository)
    assert isinstance(group_repo, GroupRepository)
    assert isinstance(role_repo, RoleRepository)
    assert isinstance(action_repo, ActionRepository)
    assert isinstance(iram, IdentityRoleAssignmentRepository)
    assert isinstance(gram, GroupRoleAssignmentRepository)
    assert isinstance(ptm, PrincipalTenantMembershipRepository)
    assert isinstance(itm, IdentityTenantMembershipRepository)
    assert isinstance(gtm, GroupTenantMembershipRepository)
    assert isinstance(igm, IdentityGroupMembershipRepository)
    assert isinstance(iom, IdentityOrgMembershipRepository)
    assert isinstance(gom, GroupOrgMembershipRepository)


def test_s05_foreign_provider_unit_of_work_is_rejected() -> None:
    spi_a = InMemoryMtmfSpi()
    spi_b = InMemoryMtmfSpi()
    with spi_b.create_unit_of_work() as foreign_uow:
        with pytest.raises(ForeignUnitOfWorkError):
            spi_a.create_tenant_repository(foreign_uow)
        with pytest.raises(ForeignUnitOfWorkError):
            spi_a.create_organization_repository(foreign_uow)
        with pytest.raises(ForeignUnitOfWorkError):
            spi_a.create_role_repository(foreign_uow)


def test_s05b_foreign_object_is_rejected_as_a_unit_of_work(spi: MtmfSpi) -> None:
    with pytest.raises(ForeignUnitOfWorkError):
        spi.create_tenant_repository(object())  # type: ignore[arg-type]


def test_s06_multi_repository_commit_is_atomic(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    organization = make_organization(tenant_id=tenant.id)
    membership = __import__("mtmf_core", fromlist=["IdentityOrgMembership"]).IdentityOrgMembership(
        make_id(), organization.id
    )
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        spi.create_organization_repository(uow).add(organization)
        spi.create_identity_org_membership_repository(uow).add(membership)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_repository(uow).get(tenant.id) == tenant
        assert spi.create_organization_repository(uow).get(organization.id) == organization
        assert (
            spi.create_identity_org_membership_repository(uow).get(
                membership.identity_id, membership.organization_id
            )
            == membership
        )


def test_s07_multi_repository_rollback_commits_none(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    organization = make_organization(tenant_id=tenant.id)
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        spi.create_organization_repository(uow).add(organization)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_repository(uow).get(tenant.id) is None
        assert spi.create_organization_repository(uow).get(organization.id) is None


def test_s08_repository_without_unit_of_work_is_structurally_impossible() -> None:
    # Every factory demands its UnitOfWork as an explicit positional
    # parameter: a repository cannot be created detached from one.
    import inspect

    for name in (
        "create_tenant_repository",
        "create_organization_repository",
        "create_principal_repository",
        "create_identity_repository",
        "create_group_repository",
        "create_role_repository",
        "create_action_repository",
        "create_principal_tenant_membership_repository",
        "create_identity_tenant_membership_repository",
        "create_group_tenant_membership_repository",
        "create_identity_group_membership_repository",
        "create_identity_org_membership_repository",
        "create_group_org_membership_repository",
    ):
        signature = inspect.signature(getattr(MtmfSpi, name))
        parameters = list(signature.parameters)
        assert parameters == ["self", "uow"], f"{name} must require an explicit uow"


def test_s09_and_s10_spi_has_no_migration_or_idp_surface(spi: MtmfSpi) -> None:
    for name in (
        "upgrade",
        "downgrade",
        "migrate",
        "migration",
        "revision",
        "schema_version",
        "create_schema",
        "drop_schema",
        "idp",
        "oidc",
        "saml",
        "oauth",
        "federate",
        "federation",
        "google",
        "identity_provider",
    ):
        assert not hasattr(spi, name), f"MtmfSpi must not expose {name!r}"
        assert not hasattr(MtmfSpi, name), f"MtmfSpi contract must not declare {name!r}"


def test_s11_spi_exposes_no_database_driver_handle(spi: MtmfSpi) -> None:
    for name in (
        "connection",
        "cursor",
        "session",
        "engine",
        "pool",
        "transaction",
        "transaction_handle",
        "connection_handle",
        "execute",
        "query",
        "sql",
    ):
        assert not hasattr(spi, name), f"MtmfSpi must not expose {name!r}"
        assert not hasattr(MtmfSpi, name), f"MtmfSpi contract must not declare {name!r}"


def test_spi_contract_declares_only_factories_and_unit_of_work(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    assert isinstance(uow, UnitOfWork)
    assert isinstance(spi, MtmfSpi)
