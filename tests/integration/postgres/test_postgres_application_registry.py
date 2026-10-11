"""Application-registry and Tenant-subscription integration tests (0010).

These run on real PostgreSQL with the established administrator/migrator/
runtime topology (P01-P09). Privileged registry mutation is exercised
through the administrator connection against the operator-only stored
functions; the restricted ``mtmf_runtime`` login is used for the eligibility
read path and to prove that untrusted mutation is denied.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from mtmf_core import (
    DomainId,
    EligibilityReason,
    RegistrationLifecycle,
    SubscriptionLifecycle,
)
from mtmf_core.application import ApplicationTenantEligibilityService
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMtmfSpi,
)

_ACTIVE = 1
_NOT_DELETED = 2
_SUBSCRIPTION_ACTIVE = int(SubscriptionLifecycle.ACTIVE)
_REGISTRATION_ACTIVE = int(RegistrationLifecycle.ACTIVE)


def _uuid() -> str:
    return str(uuid.uuid4())


def _seed_identity_tenant(db: psycopg.Connection) -> tuple[str, str]:
    principal_id, identity_id, tenant_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal_id,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, 2)",
        (identity_id, principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 1, 2)",
        (tenant_id, identity_id),
    )
    db.execute(
        "INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id) VALUES (%s, %s)",
        (principal_id, tenant_id),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
        (identity_id, tenant_id),
    )
    return tenant_id, identity_id


def _create_application(
    db: psycopg.Connection,
    key: str,
    owner_identity_id: str,
    *,
    lifecycle: int = 1,
) -> str:
    application_id = _uuid()
    added = db.execute(
        "SELECT mtmf.application_add(%s, %s, %s, %s, %s::smallint, %s::jsonb)",
        (application_id, key, "Application", owner_identity_id, lifecycle, "{}"),
    ).fetchone()[0]
    assert added is True
    return application_id


def _register(
    db: psycopg.Connection,
    application_id: str,
    tenant_id: str,
    identity_id: str,
    *,
    lifecycle: int = _REGISTRATION_ACTIVE,
) -> str:
    registration_id = _uuid()
    added = db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, %s::smallint, now())",
        (registration_id, application_id, tenant_id, identity_id, lifecycle),
    ).fetchone()[0]
    assert added is True
    return registration_id


def _subscribe(
    db: psycopg.Connection,
    application_id: str,
    tenant_id: str,
    identity_id: str,
    *,
    lifecycle: int = _SUBSCRIPTION_ACTIVE,
    starts_at: datetime | None = None,
    ends_at: datetime | None = None,
) -> str:
    subscription_id = _uuid()
    starts = starts_at if starts_at is not None else datetime.now(UTC) - timedelta(days=1)
    added = db.execute(
        "SELECT mtmf.tenant_application_subscription_add("
        "%s, %s, %s, %s, %s::smallint, %s, %s, now())",
        (subscription_id, application_id, tenant_id, identity_id, lifecycle, starts, ends_at),
    ).fetchone()[0]
    assert added is True
    return subscription_id


def _service_evaluate(
    spi: PostgresMtmfSpi, application_id: str, tenant_id: str, at: datetime | None = None
) -> object:
    service = ApplicationTenantEligibilityService(spi)
    with spi.create_unit_of_work() as uow:
        return service.evaluate(
            uow,
            application_id=DomainId.from_str(application_id),
            tenant_id=DomainId.from_str(tenant_id),
            at=at if at is not None else datetime.now(UTC),
        )


def test_pr13_01_migration_creates_registry_tables(db: psycopg.Connection) -> None:
    rows = db.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'mtmf' AND table_name IN ("
        "'application', 'application_tenant_registration', 'tenant_application_subscription')"
    ).fetchall()
    assert {row[0] for row in rows} == {
        "application",
        "application_tenant_registration",
        "tenant_application_subscription",
    }


def test_pr13_02_repository_round_trip_through_runtime(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-round-trip", identity_id)
    registration_id = _register(db, application_id, tenant_id, identity_id)
    subscription_id = _subscribe(db, application_id, tenant_id, identity_id)

    with postgres_spi.create_unit_of_work() as uow:
        applications = postgres_spi.create_application_repository(uow)
        application = applications.get(DomainId.from_str(application_id))
        assert application is not None
        assert application.application_key == "ati-round-trip"
        assert applications.get_by_key("ATI-Round-Trip") == application
        registrations = postgres_spi.create_application_tenant_registration_repository(uow)
        registration = registrations.get(DomainId.from_str(registration_id))
        assert registration is not None
        assert registration.lifecycle is RegistrationLifecycle.ACTIVE
        subscriptions = postgres_spi.create_tenant_application_subscription_repository(uow)
        subscription = subscriptions.get(DomainId.from_str(subscription_id))
        assert subscription is not None
        assert subscription.lifecycle is SubscriptionLifecycle.ACTIVE


def test_pr13_03_constraints_reject_duplicate_and_illegal_state(db: psycopg.Connection) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-constraints", identity_id)

    # Duplicate application key is a deterministic no-op, never a second row.
    duplicate = db.execute(
        "SELECT mtmf.application_add(%s, %s, %s, %s, 1::smallint, '{}'::jsonb)",
        (_uuid(), "ATI-Constraints", "Other", identity_id),
    ).fetchone()[0]
    assert duplicate is False

    _register(db, application_id, tenant_id, identity_id)
    # A second current registration for the same pair is rejected.
    duplicate_registration = db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, 1::smallint, now())",
        (_uuid(), application_id, tenant_id, identity_id),
    ).fetchone()[0]
    assert duplicate_registration is False

    # A malformed subscription window is rejected with the reviewed SQLSTATE.
    with pytest.raises(psycopg.Error) as window_error:
        db.execute(
            "SELECT mtmf.tenant_application_subscription_add("
            "%s, %s, %s, %s, 1::smallint, now(), now(), now())",
            (_uuid(), application_id, tenant_id, identity_id),
        )
    assert window_error.value.sqlstate == "MT042"

    # An illegal lifecycle transition is rejected by the guard (ACTIVE -> PENDING).
    subscription_id = _subscribe(db, application_id, tenant_id, identity_id)
    with pytest.raises(psycopg.Error) as transition_error:
        db.execute(
            "SELECT mtmf.tenant_application_subscription_save(%s, 0::smallint, NULL)",
            (subscription_id,),
        )
    assert transition_error.value.sqlstate == "MT042"

    # Immutable identity/provenance columns cannot be updated.
    with pytest.raises(psycopg.Error) as immutable_error:
        db.execute(
            "UPDATE mtmf.application SET application_key = 'other' WHERE id = %s",
            (application_id,),
        )
    assert immutable_error.value.sqlstate == "MT043"


def test_pr13_04_runtime_cannot_mutate_or_read_tables(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-runtime", identity_id)
    _register(db, application_id, tenant_id, identity_id)
    _subscribe(db, application_id, tenant_id, identity_id)

    for statement, params in (
        (
            "SELECT mtmf.application_add(%s, %s, %s, %s, 1::smallint, '{}'::jsonb)",
            (_uuid(), "ati-runtime-new", "App", identity_id),
        ),
        (
            "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, 1::smallint, now())",
            (_uuid(), application_id, tenant_id, identity_id),
        ),
        (
            "SELECT mtmf.tenant_application_subscription_save(%s, 2::smallint, NULL)",
            (_uuid(),),
        ),
    ):
        with pytest.raises(psycopg.Error):
            runtime_connection.execute(statement, params)
        runtime_connection.rollback()

    for statement, params in (
        ("SELECT count(*) FROM mtmf.application", ()),
        (
            "INSERT INTO mtmf.application "
            "(id, application_key, name, owner_identity_id, lifecycle, extension) "
            "VALUES (%s, 'x', 'x', %s, 1, '{}'::jsonb)",
            (_uuid(), identity_id),
        ),
        (
            "UPDATE mtmf.tenant_application_subscription SET lifecycle = 1 WHERE id = %s",
            (_uuid(),),
        ),
    ):
        with pytest.raises(psycopg.Error):
            runtime_connection.execute(statement, params)
        runtime_connection.rollback()


def test_pr13_05_postcommit_revocation_is_effective(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-revoke", identity_id)
    registration_id = _register(db, application_id, tenant_id, identity_id)
    _subscribe(db, application_id, tenant_id, identity_id)

    assert _service_evaluate(postgres_spi, application_id, tenant_id).reason is (
        EligibilityReason.ELIGIBLE
    )

    db.execute(
        "SELECT mtmf.application_tenant_registration_save(%s, %s::smallint)",
        (registration_id, int(RegistrationLifecycle.REVOKED)),
    )
    assert _service_evaluate(postgres_spi, application_id, tenant_id).reason is (
        EligibilityReason.REGISTRATION_NOT_ACTIVE
    )


def test_pr13_06_time_window_and_expiry(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-window", identity_id)
    _register(db, application_id, tenant_id, identity_id)
    starts = datetime.now(UTC)
    ends = starts + timedelta(hours=1)
    _subscribe(db, application_id, tenant_id, identity_id, starts_at=starts, ends_at=ends)

    assert _service_evaluate(postgres_spi, application_id, tenant_id, starts).eligible is True
    assert _service_evaluate(postgres_spi, application_id, tenant_id, ends).reason is (
        EligibilityReason.SUBSCRIPTION_EXPIRED
    )
    assert (
        _service_evaluate(
            postgres_spi, application_id, tenant_id, starts - timedelta(seconds=1)
        ).reason
        is EligibilityReason.SUBSCRIPTION_NOT_YET_STARTED
    )


def test_pr13_07_duplicate_current_registration_is_rejected(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-duplicate", identity_id)
    _register(db, application_id, tenant_id, identity_id)
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as other:
        second = other.execute(
            "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, 1::smallint, now())",
            (_uuid(), application_id, tenant_id, identity_id),
        ).fetchone()[0]
    assert second is False
    active = db.execute(
        "SELECT count(*) FROM mtmf.application_tenant_registration "
        "WHERE application_id = %s AND tenant_id = %s AND lifecycle = 1",
        (application_id, tenant_id),
    ).fetchone()[0]
    assert active == 1


def test_pr13_08_concurrent_registration_race_has_one_winner(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-race", identity_id)
    barrier = threading.Barrier(2)
    results: list[bool] = []
    lock = threading.Lock()

    def insert() -> None:
        with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
            barrier.wait()
            added = connection.execute(
                "SELECT mtmf.application_tenant_registration_add("
                "%s, %s, %s, %s, 1::smallint, now())",
                (_uuid(), application_id, tenant_id, identity_id),
            ).fetchone()[0]
            with lock:
                results.append(bool(added))

    threads = [threading.Thread(target=insert) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    active = db.execute(
        "SELECT count(*) FROM mtmf.application_tenant_registration "
        "WHERE application_id = %s AND tenant_id = %s AND lifecycle = 1",
        (application_id, tenant_id),
    ).fetchone()[0]
    assert active == 1


def test_pr13_09_terminal_history_allows_replacement(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-history", identity_id)
    registration_id = _register(db, application_id, tenant_id, identity_id)
    _subscribe(db, application_id, tenant_id, identity_id)
    db.execute(
        "SELECT mtmf.application_tenant_registration_save(%s, %s::smallint)",
        (registration_id, int(RegistrationLifecycle.REVOKED)),
    )
    replacement_id = _register(db, application_id, tenant_id, identity_id)
    with postgres_spi.create_unit_of_work() as uow:
        rows = postgres_spi.create_application_tenant_registration_repository(
            uow
        ).find_by_application_and_tenant(
            DomainId.from_str(application_id), DomainId.from_str(tenant_id)
        )
    assert len(rows) == 2
    assert any(row.id == DomainId.from_str(replacement_id) for row in rows)
    assert _service_evaluate(postgres_spi, application_id, tenant_id).reason is (
        EligibilityReason.ELIGIBLE
    )


def test_pr13_10_missing_registration_and_subscription_are_ineligible(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "ati-none", identity_id)
    assert _service_evaluate(postgres_spi, application_id, tenant_id).reason is (
        EligibilityReason.REGISTRATION_MISSING
    )
    _register(db, application_id, tenant_id, identity_id)
    assert _service_evaluate(postgres_spi, application_id, tenant_id).reason is (
        EligibilityReason.SUBSCRIPTION_MISSING
    )
