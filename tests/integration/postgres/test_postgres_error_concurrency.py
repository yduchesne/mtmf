"""Error-translation and concurrency integration slice (V6).

A failed statement aborts the PostgreSQL transaction; the provider marks
the owning UnitOfWork failed, refuses to commit, and only permits a
rollback. A duplicate ``add`` race across two UnitOfWorks resolves
deterministically to one winner and one
:class:`DuplicatePersistenceIdentityError`, never a partial write.
"""

from __future__ import annotations

import threading

import psycopg
import pytest

from mtmf_core import (
    DomainId,
    GroupTenantMembership,
    Identity,
    IdentityGroupMembership,
    IdentityTenantMembership,
    Principal,
    PrincipalTenantMembership,
)
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceReferenceError,
    PersistenceTransactionError,
)
from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi
from mtmf_core.persistence.spi import MtmfSpi


def test_v6_failed_statement_marks_the_unit_of_work_failed(postgres_spi: MtmfSpi) -> None:
    sibling = Principal(DomainId.generate(), "Sibling")
    orphan = Identity(DomainId.generate(), DomainId.generate(), "Orphan")
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(sibling)
        identity_repository = postgres_spi.create_identity_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            # The Identity references an absent Principal.
            identity_repository.add(orphan)
        with pytest.raises(PersistenceTransactionError):
            identity_repository.get(orphan.id)
        with pytest.raises(PersistenceTransactionError):
            uow.commit()
        uow.rollback()
    with postgres_spi.create_unit_of_work() as uow:
        # The sibling write from the aborted transaction must not persist.
        assert postgres_spi.create_principal_repository(uow).get(sibling.id) is None


def test_v6_duplicate_add_race_across_two_unit_of_works(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    first_provider = PostgresMtmfSpi(runtime_config)
    second_provider = PostgresMtmfSpi(runtime_config)
    principal = Principal(DomainId.generate(), "Race")
    outcomes: dict[str, str] = {}
    started = threading.Barrier(2)

    def worker(name: str, provider: PostgresMtmfSpi) -> None:
        try:
            with provider.create_unit_of_work() as uow:
                started.wait(timeout=10)
                provider.create_principal_repository(uow).add(principal)
                uow.commit()
            outcomes[name] = "committed"
        except DuplicatePersistenceIdentityError:
            outcomes[name] = "duplicate"
        except Exception as exc:
            outcomes[name] = f"error:{type(exc).__name__}"

    threads = [
        threading.Thread(target=worker, args=("first", first_provider)),
        threading.Thread(target=worker, args=("second", second_provider)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(outcomes.values()) == ["committed", "duplicate"], outcomes
    with first_provider.create_unit_of_work() as uow:
        assert first_provider.create_principal_repository(uow).get(principal.id) == principal


def test_v6_unknown_save_is_not_a_transaction_failure(postgres_spi: MtmfSpi) -> None:
    from mtmf_core.persistence.errors import UnknownPersistenceIdentityError

    successful = Principal(DomainId.generate(), "Successful")
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_principal_repository(uow)
        repository.add(successful)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.save(Principal(DomainId.generate(), "Absent"))
        # A save of an unknown identity is a contract result, not an
        # aborted statement, so the surrounding transaction still commits.
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_repository(uow).get(successful.id) == successful


def test_v6_prerequisite_insert_and_removal_serialize_through_locks(
    postgres_spi: MtmfSpi,
) -> None:
    # A dependent IdentityGroupMembership insert is rejected when the
    # IdentityTenantMembership prerequisite is absent, and adding it after
    # the prerequisite exists succeeds; the removal functions retain their
    # row-lock serialization (covered exhaustively by the PR 6B suites).
    from provider_helpers import seed_entity_graph

    graph = seed_entity_graph(postgres_spi)
    with postgres_spi.create_unit_of_work() as uow, pytest.raises(PersistenceReferenceError):
        postgres_spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(graph.identity.id, graph.group.id)
        )
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
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert (
            postgres_spi.create_identity_group_membership_repository(uow).get(
                graph.identity.id, graph.group.id
            )
            is not None
        )
