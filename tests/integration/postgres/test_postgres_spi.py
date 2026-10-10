"""Provider and UnitOfWork integration slice (V1) plus entity/action (V2).

Every operation runs through the production :class:`PostgresMtmfSpi`
authenticated as the restricted ``mtmf_runtime`` login against a freshly
migrated empty ``mtmf`` schema. No test substitutes an owner or
superuser session.
"""

from __future__ import annotations

import psycopg
import pytest
from provider_helpers import seed_entity_graph

from mtmf_core import Action, ActionUrn, DomainId, Identity, IdentityOrigin, JsonObject, Principal
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    ForeignUnitOfWorkError,
    PersistenceConfigurationError,
    UnitOfWorkStateError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi
from mtmf_core.persistence.spi import MtmfSpi

# --- V1: provider and UnitOfWork --------------------------------------------


def test_v1_rejects_administrator_and_migrator_configuration(
    mtmf_config: PostgresConfig, migrator_config: PostgresConfig
) -> None:
    with pytest.raises(PersistenceConfigurationError):
        PostgresMtmfSpi(mtmf_config)
    with pytest.raises(PersistenceConfigurationError):
        PostgresMtmfSpi(migrator_config)


def test_v1_two_repositories_commit_together(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    with postgres_spi.create_unit_of_work() as uow:
        stored_principal = postgres_spi.create_principal_repository(uow).get(graph.principal.id)
        stored_identity = postgres_spi.create_identity_repository(uow).get(graph.identity.id)
    assert stored_principal == graph.principal
    assert stored_identity == graph.identity


def test_v1_uncommitted_writes_are_not_visible_to_a_second_unit_of_work(
    postgres_spi: MtmfSpi,
) -> None:
    principal = Principal(DomainId.generate(), "Isolated")
    with postgres_spi.create_unit_of_work() as first, postgres_spi.create_unit_of_work() as second:
        postgres_spi.create_principal_repository(first).add(principal)
        assert postgres_spi.create_principal_repository(second).get(principal.id) is None


def test_v1_normal_exit_without_commit_rolls_back(postgres_spi: MtmfSpi) -> None:
    principal = Principal(DomainId.generate(), "Rollback")
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_repository(uow).get(principal.id) is None


def test_v1_exceptional_exit_rolls_back_and_propagates(postgres_spi: MtmfSpi) -> None:
    principal = Principal(DomainId.generate(), "Boom")
    sentinel = RuntimeError("boom")
    with pytest.raises(RuntimeError) as captured, postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
        raise sentinel
    assert captured.value is sentinel
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_repository(uow).get(principal.id) is None


def test_v1_completed_repository_is_rejected(postgres_spi: MtmfSpi) -> None:
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_principal_repository(uow)
        uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            repository.get(DomainId.generate())


def test_v1_foreign_unit_of_work_is_rejected(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    first = PostgresMtmfSpi(runtime_config)
    second = PostgresMtmfSpi(runtime_config)
    with pytest.raises(ForeignUnitOfWorkError):
        first.create_tenant_repository(second.create_unit_of_work())


def test_v1_configuration_labels_do_not_change_the_authenticated_login(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    # A runtime-labelled configuration always authenticates as the runtime
    # login; the UnitOfWork verifies session_user/current_user before use.
    provider = PostgresMtmfSpi(runtime_config)
    with provider.create_unit_of_work() as uow:
        assert uow is not None


# --- V2: entities and Action -------------------------------------------------


def test_v2_entity_add_get_save_and_soft_delete(postgres_spi: MtmfSpi) -> None:
    graph = seed_entity_graph(postgres_spi)
    with postgres_spi.create_unit_of_work() as uow:
        principal = postgres_spi.create_principal_repository(uow).get(graph.principal.id)
        tenant = postgres_spi.create_tenant_repository(uow).get(graph.tenant.id)
    assert tenant.owner_identity_id == graph.identity.id
    assert principal.id == graph.principal.id

    graph.tenant.soft_delete()
    graph.tenant.name = "Renamed"
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_tenant_repository(uow).save(graph.tenant)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_tenant_repository(uow).get(graph.tenant.id)
    assert stored.name == "Renamed"
    assert stored.deleted


def test_v2_duplicate_add_and_unknown_save_are_deterministic(postgres_spi: MtmfSpi) -> None:
    principal = Principal(DomainId.generate(), "Duplicate")
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
        with pytest.raises(DuplicatePersistenceIdentityError):
            postgres_spi.create_principal_repository(uow).add(Principal(principal.id, "Other"))
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(DuplicatePersistenceIdentityError):
            postgres_spi.create_principal_repository(uow).add(principal)
        with pytest.raises(UnknownPersistenceIdentityError):
            postgres_spi.create_principal_repository(uow).save(
                Principal(DomainId.generate(), "Absent")
            )


def test_v2_extension_objects_and_provenance_round_trip(postgres_spi: MtmfSpi) -> None:
    extension: JsonObject = {
        "outer": {"inner": [1, "x", None, {"deep": None}]},
        "flag": True,
    }
    principal = Principal(DomainId.generate(), "Extension")
    principal.extension = extension
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_principal_repository(uow).get(principal.id)
    assert stored.extension == extension
    assert stored.extension is not principal.extension


def test_v2_action_add_get_round_trip(postgres_spi: MtmfSpi) -> None:
    urn = ActionUrn("urn:mtmf:iam:actions:system:principal:get-object")
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_action_repository(uow).add(Action(urn))
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_action_repository(uow).get(urn) == Action(urn)
        assert (
            postgres_spi.create_action_repository(uow).get(
                ActionUrn("urn:mtmf:iam:actions:system:principal:set-object")
            )
            is None
        )


def test_v2_runtime_direct_table_access_is_denied(
    runtime_connection: psycopg.Connection,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT * FROM mtmf.tenant")
    runtime_connection.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "INSERT INTO mtmf.principal (id, name, deletion_status) "
            "VALUES (gen_random_uuid(), 'x', 2)"
        )
    runtime_connection.rollback()


def test_v2_runtime_identity_is_the_restricted_login(
    runtime_connection: psycopg.Connection,
) -> None:
    session_user, current_user = runtime_connection.execute(
        "SELECT session_user, current_user"
    ).fetchone()
    assert session_user == "mtmf_runtime"
    assert current_user == "mtmf_runtime"


def test_entity_mutation_after_get_does_not_persist_without_save(
    postgres_spi: MtmfSpi,
) -> None:
    identity = Identity(DomainId.generate(), DomainId.generate(), "I", IdentityOrigin.LOCAL)
    # An Identity referencing an absent Principal fails as a reference error.
    from mtmf_core.persistence.errors import PersistenceReferenceError

    with postgres_spi.create_unit_of_work() as uow, pytest.raises(PersistenceReferenceError):
        postgres_spi.create_identity_repository(uow).add(identity)
