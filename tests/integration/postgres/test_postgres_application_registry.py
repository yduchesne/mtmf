"""Application-registry and Tenant-subscription integration tests (0010).

These run on real PostgreSQL with the established administrator/migrator/
runtime topology (P01-P09). Privileged registry mutation is exercised
through the administrator connection against the operator-only stored
functions; the restricted ``mtmf_runtime`` login is used for the eligibility
read path and to prove that untrusted mutation is denied.
"""

from __future__ import annotations

import contextlib
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


# --- PR 13-1 A1 subscription mutation hardening (M01-M24) -------------------

_PENDING = int(SubscriptionLifecycle.PENDING)
_CANCELLED = int(SubscriptionLifecycle.CANCELLED)
_EXPIRED = int(SubscriptionLifecycle.EXPIRED)
_SUSPENDED = int(SubscriptionLifecycle.SUSPENDED)
_APP_RETIRED = 3


def _save_subscription(
    db: psycopg.Connection,
    subscription_id: str,
    lifecycle: int,
    ends_at: datetime | None,
) -> bool:
    return db.execute(
        "SELECT mtmf.tenant_application_subscription_save(%s, %s::smallint, %s)",
        (subscription_id, lifecycle, ends_at),
    ).fetchone()[0]


def _read_subscription(
    db: psycopg.Connection, subscription_id: str
) -> tuple[int, datetime | None, datetime]:
    row = db.execute(
        "SELECT lifecycle, ends_at, starts_at FROM mtmf.tenant_application_subscription "
        "WHERE id = %s",
        (subscription_id,),
    ).fetchone()
    return int(row[0]), row[1], row[2]


def _save_application(db: psycopg.Connection, application_id: str, lifecycle: int) -> bool:
    return db.execute(
        "SELECT mtmf.application_save(%s, %s, %s::smallint, '{}'::jsonb)",
        (application_id, "Application", lifecycle),
    ).fetchone()[0]


def _save_registration(db: psycopg.Connection, registration_id: str, lifecycle: int) -> bool:
    return db.execute(
        "SELECT mtmf.application_tenant_registration_save(%s, %s::smallint)",
        (registration_id, lifecycle),
    ).fetchone()[0]


def _window(db: psycopg.Connection, key: str) -> tuple[str, str, datetime, datetime, str]:
    """Seed Tenant/Application/registration/subscription on ``[t0, t3)``."""
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, key, identity_id)
    _register(db, application_id, tenant_id, identity_id)
    starts_at = datetime.now(UTC)
    ends_at = starts_at + timedelta(hours=3)
    subscription_id = _subscribe(
        db, application_id, tenant_id, identity_id, starts_at=starts_at, ends_at=ends_at
    )
    return tenant_id, application_id, starts_at, ends_at, subscription_id


def test_a1_m01_m22_shortening_is_accepted_and_effective_at_the_new_bound(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, application_id, _starts, ends_at, subscription_id = _window(db, "a1-m01")
    shortened = ends_at - timedelta(hours=1)
    assert _save_subscription(db, subscription_id, _SUBSCRIPTION_ACTIVE, shortened) is True
    assert _read_subscription(db, subscription_id)[1] == shortened
    assert _service_evaluate(postgres_spi, application_id, tenant_id, shortened).reason is (
        EligibilityReason.SUBSCRIPTION_EXPIRED
    )


def test_a1_m02_open_ended_can_be_given_a_finite_end(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "a1-m02", identity_id)
    _register(db, application_id, tenant_id, identity_id)
    starts_at = datetime.now(UTC)
    subscription_id = _subscribe(db, application_id, tenant_id, identity_id, starts_at=starts_at)
    finite = starts_at + timedelta(hours=1)
    assert _save_subscription(db, subscription_id, _SUBSCRIPTION_ACTIVE, finite) is True
    assert _read_subscription(db, subscription_id)[1] == finite


def test_a1_m03_m04_m06_non_restrictive_amendments_are_rejected(
    db: psycopg.Connection,
) -> None:
    _tenant, _app, starts_at, ends_at, subscription_id = _window(db, "a1-m03")
    for bad in (ends_at + timedelta(hours=1), None, starts_at):
        with pytest.raises(psycopg.Error) as error:
            _save_subscription(db, subscription_id, _SUBSCRIPTION_ACTIVE, bad)
        assert error.value.sqlstate == "MT042"
        assert _read_subscription(db, subscription_id)[1] == ends_at


def test_a1_m05_identical_no_op_does_not_change_the_row(db: psycopg.Connection) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m05")
    assert _save_subscription(db, subscription_id, _SUBSCRIPTION_ACTIVE, ends_at) is True
    lifecycle, stored_end, _starts_at = _read_subscription(db, subscription_id)
    assert lifecycle == _SUBSCRIPTION_ACTIVE
    assert stored_end == ends_at


def test_a1_m07_legal_transition_plus_shortening_is_atomic(db: psycopg.Connection) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "a1-m07", identity_id)
    _register(db, application_id, tenant_id, identity_id)
    starts_at = datetime.now(UTC)
    ends_at = starts_at + timedelta(hours=3)
    subscription_id = _subscribe(
        db,
        application_id,
        tenant_id,
        identity_id,
        lifecycle=_PENDING,
        starts_at=starts_at,
        ends_at=ends_at,
    )
    shortened = ends_at - timedelta(hours=1)
    assert _save_subscription(db, subscription_id, _SUBSCRIPTION_ACTIVE, shortened) is True
    lifecycle, stored_end, _ = _read_subscription(db, subscription_id)
    assert lifecycle == _SUBSCRIPTION_ACTIVE
    assert stored_end == shortened


def test_a1_m08_illegal_transition_plus_shortening_leaves_both_unchanged(
    db: psycopg.Connection,
) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m08")
    with pytest.raises(psycopg.Error) as error:
        _save_subscription(db, subscription_id, _PENDING, ends_at - timedelta(hours=1))
    assert error.value.sqlstate == "MT042"
    lifecycle, stored_end, _ = _read_subscription(db, subscription_id)
    assert lifecycle == _SUBSCRIPTION_ACTIVE
    assert stored_end == ends_at


def test_a1_m09_terminal_transition_plus_shortening_is_atomic(db: psycopg.Connection) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m09")
    shortened = ends_at - timedelta(hours=1)
    assert _save_subscription(db, subscription_id, _CANCELLED, shortened) is True
    lifecycle, stored_end, _ = _read_subscription(db, subscription_id)
    assert lifecycle == _CANCELLED
    assert stored_end == shortened


def test_a1_m10_m11_m12_terminal_rows_reject_all_updates(db: psycopg.Connection) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m10")
    assert _save_subscription(db, subscription_id, _CANCELLED, ends_at) is True
    for lifecycle, target_end in (
        (_CANCELLED, None),
        (_CANCELLED, ends_at - timedelta(hours=1)),
        (_SUBSCRIPTION_ACTIVE, ends_at),
    ):
        with pytest.raises(psycopg.Error) as error:
            _save_subscription(db, subscription_id, lifecycle, target_end)
        assert error.value.sqlstate == "MT042"
    stored_lifecycle, stored_end, _ = _read_subscription(db, subscription_id)
    assert stored_lifecycle == _CANCELLED
    assert stored_end == ends_at
    # A direct owner UPDATE on a terminal row is rejected by the same guard.
    with pytest.raises(psycopg.Error) as error:
        db.execute(
            "UPDATE mtmf.tenant_application_subscription SET lifecycle = %s WHERE id = %s",
            (_EXPIRED, subscription_id),
        )
    assert error.value.sqlstate == "MT042"


def test_a1_m13_immutable_starts_at_cannot_be_updated(db: psycopg.Connection) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m13")
    with pytest.raises(psycopg.Error) as error:
        db.execute(
            "UPDATE mtmf.tenant_application_subscription SET starts_at = %s WHERE id = %s",
            (ends_at - timedelta(hours=4), subscription_id),
        )
    assert error.value.sqlstate == "MT043"


def test_a1_m14_m15_m16_direct_owner_update_guard_parity(db: psycopg.Connection) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m14")
    shortened = ends_at - timedelta(hours=1)
    # M14: a direct restrictive UPDATE is accepted.
    db.execute(
        "UPDATE mtmf.tenant_application_subscription SET ends_at = %s WHERE id = %s",
        (shortened, subscription_id),
    )
    assert _read_subscription(db, subscription_id)[1] == shortened
    # M15/M16: extension and clearing are rejected and roll back.
    for bad in (ends_at, None):
        with pytest.raises(psycopg.Error) as error:
            db.execute(
                "UPDATE mtmf.tenant_application_subscription SET ends_at = %s WHERE id = %s",
                (bad, subscription_id),
            )
        assert error.value.sqlstate == "MT042"
        assert _read_subscription(db, subscription_id)[1] == shortened


def test_a1_m17_m19_application_terminal_and_metadata_updates(db: psycopg.Connection) -> None:
    _tenant, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "a1-m17", identity_id)
    # M19: an ordinary metadata update on an ACTIVE Application is accepted.
    assert _save_application(db, application_id, _SUBSCRIPTION_ACTIVE) is True
    # M17: a same-state update of a RETIRED Application is rejected.
    assert _save_application(db, application_id, _APP_RETIRED) is True
    with pytest.raises(psycopg.Error) as error:
        _save_application(db, application_id, _APP_RETIRED)
    assert error.value.sqlstate == "MT040"


def test_a1_m18_m20_registration_terminal_and_same_state(db: psycopg.Connection) -> None:
    tenant_id, identity_id = _seed_identity_tenant(db)
    application_id = _create_application(db, "a1-m18", identity_id)
    registration_id = _register(db, application_id, tenant_id, identity_id)
    # M20: a same-state ACTIVE registration update is allowed (no new authority).
    assert _save_registration(db, registration_id, _REGISTRATION_ACTIVE) is True
    # M18: a same-state REVOKED registration update is rejected.
    assert _save_registration(db, registration_id, int(RegistrationLifecycle.REVOKED)) is True
    with pytest.raises(psycopg.Error) as error:
        _save_registration(db, registration_id, int(RegistrationLifecycle.REVOKED))
    assert error.value.sqlstate == "MT041"


def test_a1_m23_rejected_shortening_rolls_back_to_original(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m23")
    with psycopg.connect(mtmf_config.psycopg_dsn) as connection:
        connection.execute(
            "SELECT mtmf.tenant_application_subscription_save(%s, %s::smallint, %s)",
            (subscription_id, _SUBSCRIPTION_ACTIVE, ends_at - timedelta(hours=1)),
        )
        connection.rollback()
    assert _read_subscription(db, subscription_id)[1] == ends_at


def test_a1_m24_concurrent_shortenings_never_extend_the_bound(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m24")
    tighter = ends_at - timedelta(hours=2)
    looser = ends_at - timedelta(hours=1)
    barrier = threading.Barrier(2)

    def shorten(target: datetime) -> None:
        with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
            barrier.wait()
            # A concurrent tighter shortening can legitimately reject a loser
            # that would otherwise extend the bound.
            with contextlib.suppress(psycopg.Error):
                connection.execute(
                    "SELECT mtmf.tenant_application_subscription_save(%s, %s::smallint, %s)",
                    (subscription_id, _SUBSCRIPTION_ACTIVE, target),
                )

    threads = [threading.Thread(target=shorten, args=(target,)) for target in (tighter, looser)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    final = _read_subscription(db, subscription_id)[1]
    assert final is not None
    assert final <= tighter
    assert final <= ends_at


def test_a1_m21_runtime_cannot_save_or_update_subscription(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    _tenant, _app, _starts, ends_at, subscription_id = _window(db, "a1-m21")
    with pytest.raises(psycopg.Error):
        runtime_connection.execute(
            "SELECT mtmf.tenant_application_subscription_save(%s, %s::smallint, %s)",
            (subscription_id, _SUBSCRIPTION_ACTIVE, ends_at),
        )
    runtime_connection.rollback()
    with pytest.raises(psycopg.Error):
        runtime_connection.execute(
            "UPDATE mtmf.tenant_application_subscription SET ends_at = %s WHERE id = %s",
            (ends_at - timedelta(hours=1), subscription_id),
        )
    runtime_connection.rollback()
