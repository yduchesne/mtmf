"""Typed membership repository contract tests (plan matrix M01-M08).

Memberships stay explicit typed relationships: add/get/find operate on
the typed relationship facts and there is no polymorphic
``member_type``/``member_id`` record and no surrogate ID.
"""

from __future__ import annotations

import dataclasses

import pytest
from helpers import make_id

from mtmf_core import (
    DomainId,
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    PrincipalTenantMembership,
)
from mtmf_core.persistence import (
    DuplicatePersistenceIdentityError,
    MtmfSpi,
)

MEMBERSHIP_KINDS = (
    "principal_tenant",
    "identity_tenant",
    "group_tenant",
    "identity_group",
    "identity_org",
    "group_org",
)

FACTORY_NAMES = {
    "principal_tenant": "create_principal_tenant_membership_repository",
    "identity_tenant": "create_identity_tenant_membership_repository",
    "group_tenant": "create_group_tenant_membership_repository",
    "identity_group": "create_identity_group_membership_repository",
    "identity_org": "create_identity_org_membership_repository",
    "group_org": "create_group_org_membership_repository",
}

MEMBERSHIP_TYPES = {
    "principal_tenant": PrincipalTenantMembership,
    "identity_tenant": IdentityTenantMembership,
    "group_tenant": GroupTenantMembership,
    "identity_group": IdentityGroupMembership,
    "identity_org": IdentityOrgMembership,
    "group_org": GroupOrgMembership,
}

FIRST_FIELD = {
    "principal_tenant": "principal_id",
    "identity_tenant": "identity_id",
    "group_tenant": "group_id",
    "identity_group": "identity_id",
    "identity_org": "identity_id",
    "group_org": "group_id",
}

SECOND_FIELD = {
    "principal_tenant": "tenant_id",
    "identity_tenant": "tenant_id",
    "group_tenant": "tenant_id",
    "identity_group": "group_id",
    "identity_org": "organization_id",
    "group_org": "organization_id",
}

FIRST_FIND = {
    "principal_tenant": "find_by_principal",
    "identity_tenant": "find_by_identity",
    "group_tenant": "find_by_group",
    "identity_group": "find_by_identity",
    "identity_org": "find_by_identity",
    "group_org": "find_by_group",
}

SECOND_FIND = {
    "principal_tenant": "find_by_tenant",
    "identity_tenant": "find_by_tenant",
    "group_tenant": "find_by_tenant",
    "identity_group": "find_by_group",
    "identity_org": "find_by_organization",
    "group_org": "find_by_organization",
}

TENANT_BEARING_KINDS = ("principal_tenant", "identity_tenant", "group_tenant")


def _make(kind: str, first: DomainId, second: DomainId):
    """Build a typed membership fact from two raw DomainIds."""
    return MEMBERSHIP_TYPES[kind](first, second)


def _repo(spi: MtmfSpi, uow: object, kind: str) -> object:
    return getattr(spi, FACTORY_NAMES[kind])(uow)


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m01_add_commit_get_round_trip(spi: MtmfSpi, kind: str) -> None:
    membership = _make(kind, make_id(), make_id())
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, kind).add(membership)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = _repo(spi, uow, kind).get(
            getattr(membership, FIRST_FIELD[kind]),
            getattr(membership, SECOND_FIELD[kind]),
        )
        assert stored == membership
        assert type(stored) is MEMBERSHIP_TYPES[kind]


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m02_rollback_discards_membership(spi: MtmfSpi, kind: str) -> None:
    membership = _make(kind, make_id(), make_id())
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, kind).add(membership)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert (
            _repo(spi, uow, kind).get(
                getattr(membership, FIRST_FIELD[kind]),
                getattr(membership, SECOND_FIELD[kind]),
            )
            is None
        )


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m02b_membership_added_without_commit_discarded(spi: MtmfSpi, kind: str) -> None:
    membership = _make(kind, make_id(), make_id())
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, kind).add(membership)
    with spi.create_unit_of_work() as uow:
        assert (
            _repo(spi, uow, kind).get(
                getattr(membership, FIRST_FIELD[kind]),
                getattr(membership, SECOND_FIELD[kind]),
            )
            is None
        )


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m03_duplicate_relationship_fails(spi: MtmfSpi, kind: str) -> None:
    membership = _make(kind, make_id(), make_id())
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        repo.add(membership)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(membership)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(membership)


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m04_find_returns_exact_typed_results(spi: MtmfSpi, kind: str) -> None:
    first = make_id()
    other_first = make_id()
    second_one = make_id()
    second_two = make_id()
    expected_first = (_make(kind, first, second_one), _make(kind, first, second_two))
    expected_second = (_make(kind, first, second_one), _make(kind, other_first, second_one))
    all_facts = (
        _make(kind, first, second_one),
        _make(kind, first, second_two),
        _make(kind, other_first, second_one),
        _make(kind, other_first, second_two),
    )
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        for membership in all_facts:
            repo.add(membership)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        by_first = getattr(repo, FIRST_FIND[kind])(first)
        assert set(by_first) == set(expected_first)
        assert all(type(item) is MEMBERSHIP_TYPES[kind] for item in by_first)
        by_second = getattr(repo, SECOND_FIND[kind])(second_one)
        assert set(by_second) == set(expected_second)


@pytest.mark.parametrize("kind", TENANT_BEARING_KINDS)
def test_m05_tenant_scoped_lookup_has_no_other_tenant_leakage(spi: MtmfSpi, kind: str) -> None:
    tenant_a = make_id()
    tenant_b = make_id()
    member = make_id()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        repo.add(_make(kind, member, tenant_a))
        repo.add(_make(kind, member, tenant_b))
        repo.add(_make(kind, make_id(), tenant_b))
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        found = getattr(repo, SECOND_FIND[kind])(tenant_a)
        assert len(found) == 1
        assert getattr(found[0], SECOND_FIELD[kind]) == tenant_a
        assert getattr(found[0], SECOND_FIELD[kind]) != tenant_b


def test_m06_no_polymorphic_member_record() -> None:
    for membership_type in MEMBERSHIP_TYPES.values():
        field_names = {field.name for field in dataclasses.fields(membership_type)}
        assert "member_type" not in field_names
        assert "member_id" not in field_names
    import mtmf_core.persistence as persistence

    assert not hasattr(persistence, "MembershipRepository")
    assert not hasattr(persistence, "TypedMembershipRepository")


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m07_typed_ids_are_preserved(spi: MtmfSpi, kind: str) -> None:
    first = make_id()
    second = make_id()
    membership = _make(kind, first, second)
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, kind).add(membership)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = _repo(spi, uow, kind).get(first, second)
        assert getattr(stored, FIRST_FIELD[kind]) == first
        assert getattr(stored, SECOND_FIELD[kind]) == second


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_m08_membership_facts_are_immutable_value_objects(spi: MtmfSpi, kind: str) -> None:
    first = make_id()
    second = make_id()
    membership = _make(kind, first, second)
    with pytest.raises(AttributeError):
        setattr(membership, FIRST_FIELD[kind], make_id())
    # The repository neither mutates nor reuses relationship records.
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        repo.add(_make(kind, first, second))
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        loaded = repo.get(first, second)
        also_loaded = repo.get(first, second)
        assert loaded == also_loaded
        assert loaded is not None


@pytest.mark.parametrize("kind", MEMBERSHIP_KINDS)
def test_read_your_writes_within_one_transaction(spi: MtmfSpi, kind: str) -> None:
    first = make_id()
    second = make_id()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, kind)
        repo.add(_make(kind, first, second))
        assert repo.get(first, second) is not None
        assert getattr(repo, FIRST_FIND[kind])(first)


def test_membership_repositories_expose_no_hard_delete(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        for kind in MEMBERSHIP_KINDS:
            repo = _repo(spi, uow, kind)
            for name in ("delete", "remove", "delete_by_id"):
                assert not hasattr(repo, name), f"membership repo must not expose {name!r}"
