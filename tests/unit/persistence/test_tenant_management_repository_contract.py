"""TenantManagementGroup persistence contract tests (PR 11).

These run against the provider-neutral ``spi`` fixture (currently the
deterministic in-memory provider). They prove read-your-writes, commit
durability, deterministic duplicate handling, logical uniqueness, and
physical removal for the three new repositories.
"""

from __future__ import annotations

import pytest
from helpers import make_id, make_role_urn

from mtmf_core import (
    ROOT_MANAGEMENT_ROLE_URN,
    SYSTEM_MANAGEMENT_ROLE_URN,
    DuplicatePersistenceIdentityError,
    MtmfSpi,
    RoleUrn,
    TenantManagementGroup,
    TenantManagementGroupActorEligibility,
    TenantManagementGroupMembership,
    TenantManagementScope,
    UnknownPersistenceIdentityError,
)


def _system_group(manager_tenant_id):
    return TenantManagementGroup(
        make_id(),
        manager_tenant_id,
        RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN),
        TenantManagementScope.SYSTEM,
    )


def test_group_add_get_find_by_manager(spi: MtmfSpi) -> None:
    manager_a = make_id()
    manager_b = make_id()
    group_a = _system_group(manager_a)
    group_b = _system_group(manager_b)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_repository(uow)
        repository.add(group_a)
        repository.add(group_b)
        # Read-your-writes before commit.
        assert repository.get(group_a.id) == group_a
        assert repository.find_by_manager(manager_a) == (group_a,)
        assert repository.find_by_manager(manager_b) == (group_b,)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_repository(uow)
        assert repository.get(group_a.id) == group_a
        assert repository.find_by_manager(manager_a) == (group_a,)


def test_group_duplicate_identity_is_rejected(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_repository(uow)
        repository.add(group)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(group)


def test_group_rollback_discards_staged_group(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_management_group_repository(uow).add(group)
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_management_group_repository(uow).get(group.id) is None


def test_membership_add_get_find_and_remove(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    target = make_id()
    other = make_id()
    membership = TenantManagementGroupMembership(make_id(), group.id, target)
    with spi.create_unit_of_work() as uow:
        groups = spi.create_tenant_management_group_repository(uow)
        repository = spi.create_tenant_management_group_membership_repository(uow)
        groups.add(group)
        repository.add(membership)
        assert repository.get(group.id, target) == membership
        assert repository.find_by_group(group.id) == (membership,)
        assert repository.find_by_tenant(target) == (membership,)
        assert repository.find_by_tenant(other) == ()
        repository.remove(group.id, target)
        assert repository.get(group.id, target) is None
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_membership_repository(uow)
        assert repository.get(group.id, target) is None


def test_membership_duplicate_logical_pair_is_rejected(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    target = make_id()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_management_group_repository(uow).add(group)
        repository = spi.create_tenant_management_group_membership_repository(uow)
        repository.add(TenantManagementGroupMembership(make_id(), group.id, target))
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(TenantManagementGroupMembership(make_id(), group.id, target))


def test_membership_remove_unknown_pair_is_rejected(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_membership_repository(uow)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.remove(make_id(), make_id())


def test_eligibility_add_get_find_and_remove(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    identity = make_id()
    other = make_id()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity)
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_management_group_repository(uow).add(group)
        repository = spi.create_tenant_management_group_actor_eligibility_repository(uow)
        repository.add(eligibility)
        assert repository.get(group.id, identity) == eligibility
        assert repository.find_by_group(group.id) == (eligibility,)
        assert repository.find_by_identity(identity) == (eligibility,)
        assert repository.find_by_identity(other) == ()
        repository.remove(group.id, identity)
        assert repository.get(group.id, identity) is None
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_management_group_actor_eligibility_repository(uow)
        assert repository.get(group.id, identity) is None


def test_eligibility_duplicate_logical_pair_is_rejected(spi: MtmfSpi) -> None:
    group = _system_group(make_id())
    identity = make_id()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_management_group_repository(uow).add(group)
        repository = spi.create_tenant_management_group_actor_eligibility_repository(uow)
        repository.add(TenantManagementGroupActorEligibility(make_id(), group.id, identity))
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(TenantManagementGroupActorEligibility(make_id(), group.id, identity))


def test_root_and_system_role_urns_are_distinct() -> None:
    assert ROOT_MANAGEMENT_ROLE_URN != SYSTEM_MANAGEMENT_ROLE_URN
    assert make_role_urn().value.startswith("urn:mtmf:iam:roles:system:")
