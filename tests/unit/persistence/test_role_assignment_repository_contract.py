"""Typed Role-assignment persistence contract tests (plan matrix P01-P06).

These run against the provider-neutral ``spi`` fixture (currently the
deterministic in-memory provider). Every factory takes its UnitOfWork
explicitly, duplicate immutable identity and duplicate logical tuple are
deterministic conflicts, and a removed assignment is physically gone.
"""

from __future__ import annotations

import pytest
from helpers import make_id, make_role_urn

from mtmf_core import (
    DuplicatePersistenceIdentityError,
    GroupRoleAssignment,
    IdentityRoleAssignment,
    ImmutabilityError,
    MtmfSpi,
    UnknownPersistenceIdentityError,
)


def test_p01_direct_assignment_add_get_and_tenant_scoped_find(spi: MtmfSpi) -> None:
    tenant_a = make_id()
    tenant_b = make_id()
    identity = make_id()
    other_identity = make_id()
    assignment = IdentityRoleAssignment(make_id(), tenant_a, identity, make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        assert repository.get(assignment.id) == assignment
        assert repository.find_by_tenant_and_identity(tenant_a, identity) == (assignment,)
        # Exact Tenant and subject filtering; nothing leaks across either.
        assert repository.find_by_tenant_and_identity(tenant_b, identity) == ()
        assert repository.find_by_tenant_and_identity(tenant_a, other_identity) == ()
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        assert repository.get(assignment.id) == assignment


def test_p02_group_assignment_add_get_and_tenant_scoped_find(spi: MtmfSpi) -> None:
    tenant_a = make_id()
    tenant_b = make_id()
    group = make_id()
    assignment = GroupRoleAssignment(make_id(), tenant_a, group, make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_group_role_assignment_repository(uow)
        repository.add(assignment)
        assert repository.get(assignment.id) == assignment
        assert repository.find_by_tenant_and_group(tenant_a, group) == (assignment,)
        assert repository.find_by_tenant_and_group(tenant_b, group) == ()
        uow.commit()


def test_p01b_tenant_wide_and_organization_refined_are_distinct(spi: MtmfSpi) -> None:
    tenant = make_id()
    identity = make_id()
    organization = make_id()
    role_urn = make_role_urn()
    tenant_wide = IdentityRoleAssignment(make_id(), tenant, identity, role_urn)
    refined = IdentityRoleAssignment(make_id(), tenant, identity, role_urn, organization)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(tenant_wide)
        repository.add(refined)
        found = repository.find_by_tenant_and_identity(tenant, identity)
        assert {assignment.id for assignment in found} == {tenant_wide.id, refined.id}
        uow.commit()


def test_p03_duplicate_surrogate_identity_is_rejected(spi: MtmfSpi) -> None:
    tenant = make_id()
    identity = make_id()
    assignment = IdentityRoleAssignment(make_id(), tenant, identity, make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        duplicate = IdentityRoleAssignment(assignment.id, tenant, identity, make_role_urn())
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(duplicate)
        uow.rollback()


def test_p03b_duplicate_logical_tuple_is_rejected(spi: MtmfSpi) -> None:
    tenant = make_id()
    identity = make_id()
    role_urn = make_role_urn()
    organization = make_id()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(IdentityRoleAssignment(make_id(), tenant, identity, role_urn))
        # Same logical tuple, fresh surrogate id.
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(IdentityRoleAssignment(make_id(), tenant, identity, role_urn))
        # A NULL organization is a real, distinct logical value.
        repository.add(IdentityRoleAssignment(make_id(), tenant, identity, role_urn, organization))
        uow.commit()


def test_p03c_duplicate_logical_tuple_for_groups_is_rejected(spi: MtmfSpi) -> None:
    tenant = make_id()
    group = make_id()
    role_urn = make_role_urn()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_group_role_assignment_repository(uow)
        repository.add(GroupRoleAssignment(make_id(), tenant, group, role_urn))
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(GroupRoleAssignment(make_id(), tenant, group, role_urn))
        uow.rollback()


def test_p04_multi_repository_write_then_rollback_persists_nothing(spi: MtmfSpi) -> None:
    tenant = make_id()
    identity = make_id()
    group = make_id()
    direct = IdentityRoleAssignment(make_id(), tenant, identity, make_role_urn())
    group_assignment = GroupRoleAssignment(make_id(), tenant, group, make_role_urn())
    with spi.create_unit_of_work() as uow:
        spi.create_identity_role_assignment_repository(uow).add(direct)
        spi.create_group_role_assignment_repository(uow).add(group_assignment)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert spi.create_identity_role_assignment_repository(uow).get(direct.id) is None
        assert spi.create_group_role_assignment_repository(uow).get(group_assignment.id) is None


def test_p04b_uncommitted_context_exit_discards_writes(spi: MtmfSpi) -> None:
    assignment = IdentityRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with spi.create_unit_of_work() as uow:
        spi.create_identity_role_assignment_repository(uow).add(assignment)
        # no explicit commit
    with spi.create_unit_of_work() as uow:
        assert spi.create_identity_role_assignment_repository(uow).get(assignment.id) is None


def test_p06_returned_assignment_is_immutable_and_does_not_mutate_state(spi: MtmfSpi) -> None:
    assignment = IdentityRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        loaded = repository.get(assignment.id)
        assert loaded is not None
        with pytest.raises(ImmutabilityError):
            loaded.tenant_id = make_id()
        assert repository.get(assignment.id) == assignment


def test_p09_remove_is_physical_and_unknown_remove_is_rejected(spi: MtmfSpi) -> None:
    assignment = IdentityRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.remove(assignment.id)
        assert repository.get(assignment.id) is None
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        assert repository.get(assignment.id) is None
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.remove(assignment.id)
        uow.rollback()


def test_p09b_removed_assignment_is_invisible_before_commit(spi: MtmfSpi) -> None:
    assignment = IdentityRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with spi.create_unit_of_work() as uow:
        spi.create_identity_role_assignment_repository(uow).add(assignment)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_role_assignment_repository(uow)
        repository.remove(assignment.id)
        # The transaction-local view hides it...
        assert repository.get(assignment.id) is None
        uow.rollback()
    # ...and rollback restores it.
    with spi.create_unit_of_work() as uow:
        assert spi.create_identity_role_assignment_repository(uow).get(assignment.id) == assignment


def test_p03d_group_duplicate_surrogate_identity_is_rejected(spi: MtmfSpi) -> None:
    assignment = GroupRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with spi.create_unit_of_work() as uow:
        repository = spi.create_group_role_assignment_repository(uow)
        repository.add(assignment)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(
                GroupRoleAssignment(assignment.id, assignment.tenant_id, make_id(), make_role_urn())
            )
        uow.rollback()
