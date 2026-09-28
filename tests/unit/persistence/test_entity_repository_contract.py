"""Entity repository contract tests (plan matrix E01-E15).

Parametrized over every UUID-identified mutable aggregate root
(Tenant, Organization, Principal, Identity, Group): add/get/save
semantics, detached snapshots, duplicate identity handling, mutable-name
non-uniqueness, lifecycle and provenance round-trips, and extension
data.

Only the provider-neutral contract is exercised; the tests are
reusable by the future PostgreSQL provider.
"""

from __future__ import annotations

import pytest
from helpers import make_group, make_identity, make_organization, make_principal, make_tenant

from mtmf_core import (
    DeletionStatus,
    DomainId,
    JsonObject,
)
from mtmf_core.persistence import (
    DuplicatePersistenceIdentityError,
    MtmfSpi,
    UnknownPersistenceIdentityError,
)

ENTITY_CASES = [
    pytest.param("tenant", "create_tenant_repository", make_tenant, True, id="tenant"),
    pytest.param(
        "organization", "create_organization_repository", make_organization, True, id="organization"
    ),
    pytest.param("principal", "create_principal_repository", make_principal, False, id="principal"),
    pytest.param("identity", "create_identity_repository", make_identity, False, id="identity"),
    pytest.param("group", "create_group_repository", make_group, False, id="group"),
]


def _repo(spi: MtmfSpi, uow: object, factory_name: str) -> object:
    return getattr(spi, factory_name)(uow)


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e01_add_commit_get_returns_equivalent_detached_object(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = _repo(spi, uow, factory_name).get(entity.id)
        assert stored == entity
        assert stored is not entity
        assert type(stored) is type(entity)


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e02_add_rollback_leaves_absent(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        repo.add(entity)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id) is None


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e03_add_without_commit_leaves_absent(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id) is None


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e04_unknown_identity_returns_none(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(DomainId.generate()) is None


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e05_duplicate_immutable_identity_fails(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    duplicate = make_entity()
    # Same identity as ``entity`` is achieved by copying the immutable id.
    object.__setattr__(duplicate, "id", entity.id)
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        repo.add(entity)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(duplicate)
        uow.commit()
    # The committed identity is still closed to re-adding in a new UoW.
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(duplicate)


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e06_duplicate_mutable_name_is_allowed(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    first = make_entity()
    second = make_entity()
    first.name = "shared-name"
    second.name = "shared-name"
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        repo.add(first)
        repo.add(second)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        loaded_first = repo.get(first.id)
        loaded_second = repo.get(second.id)
        assert loaded_first == first
        assert loaded_second == second
        assert loaded_first is not loaded_second


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e07_mutate_original_after_commit_without_save_visits_no_durable_change(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    original_name = entity.name
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    entity.name = "mutated-without-save"
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        assert loaded.name == original_name


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e08_mutate_loaded_object_without_save_visits_no_durable_change(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    original_name = entity.name
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        loaded.name = "mutated-loaded"
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id).name == original_name


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e09_save_change_and_commit_updates(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    entity.name = "updated"
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).save(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        assert loaded.name == "updated"
        assert loaded == entity


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e10_save_change_and_rollback_leaves_original(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    entity.name = "updated"
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).save(entity)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        assert loaded.name != "updated"


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e11_extension_empty_object_is_preserved(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    assert entity.extension == {}
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id).extension == {}


NESTED_EXTENSION: JsonObject = {
    "outer": {"inner": [1, "x", None, {"deep": None}]},
    "flag": True,
    "count": 3,
    "ratio": 3.5,
    "empty_list": [],
}


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e12_nested_extension_json_is_preserved(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    entity.extension = NESTED_EXTENSION
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        assert loaded.extension == NESTED_EXTENSION
        assert loaded.extension is not entity.extension
        assert loaded.extension["outer"] is not entity.extension["outer"]


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e13_soft_deletion_state_is_preserved(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    entity.soft_delete()
    assert entity.deleted
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        assert loaded.deletion_status is DeletionStatus.DELETED
        assert loaded.deleted


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_e15_ownership_and_provenance_are_preserved(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        _repo(spi, uow, factory_name).add(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = _repo(spi, uow, factory_name).get(entity.id)
        if has_owner:
            assert loaded.owner_identity_id == entity.owner_identity_id
        assert loaded.id == entity.id


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_read_your_writes_within_one_transaction(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        repo.add(entity)
        assert repo.get(entity.id) == entity
        entity.name = "staged-rename"
        repo.save(entity)
        assert repo.get(entity.id).name == "staged-rename"
        # Rollback discards both the add and the staged rename.
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id) is None


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_save_of_unknown_identity_fails_deterministically(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        with pytest.raises(UnknownPersistenceIdentityError):
            repo.save(make_entity())
        # Nothing was staged, so an empty commit stays clean.
        uow.commit()
    with spi.create_unit_of_work() as uow:
        # And a rollback path also reports the same deterministic failure.
        repo = _repo(spi, uow, factory_name)
        with pytest.raises(UnknownPersistenceIdentityError):
            repo.save(make_entity())


@pytest.mark.parametrize(("kind", "factory_name", "make_entity", "has_owner"), ENTITY_CASES)
def test_save_replaces_previous_staged_write_within_one_transaction(
    spi: MtmfSpi, kind: str, factory_name: str, make_entity, has_owner: bool
) -> None:
    entity = make_entity()
    with spi.create_unit_of_work() as uow:
        repo = _repo(spi, uow, factory_name)
        repo.add(entity)
        entity.name = "first"
        repo.save(entity)
        entity.name = "second"
        repo.save(entity)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert _repo(spi, uow, factory_name).get(entity.id).name == "second"
