"""Onboarding-entitlement foundation integration tests (PR 22, revision 0014).

These run on real PostgreSQL with the established administrator/migrator/
runtime topology. The operator-only entitlement primitives are exercised
through the privileged owner/migrator connection (the ``db`` fixture); the
restricted ``mtmf_runtime`` login is used to prove that every v014 function is
denied and that no runtime grant was introduced.

They cover the PR 22-owned subset of the P22 matrix: P22-01, P22-02, P22-03,
P22-04, P22-05, P22-06, P22-16 and P22-18. The first-Tenant composite
(P22-10..P22-15) is deliberately BLOCKED and is not tested here (see
``docs/pr-artifacts/pr-22/PR22_STOP_REPORT.md``).
"""

from __future__ import annotations

import threading
import uuid

import psycopg
import pytest

from mtmf_core.persistence.postgres import PostgresConfig

_ACTIVE_APPLICATION = 1
_NOT_DELETED = 2


def _uuid() -> str:
    return str(uuid.uuid4())


def _seed_application(db: psycopg.Connection, *, lifecycle: int = _ACTIVE_APPLICATION) -> str:
    """Seed one principal/identity and one Application owned by that identity."""
    principal_id, identity_id, application_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', %s)",
        (principal_id, _NOT_DELETED),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, %s)",
        (identity_id, principal_id, _NOT_DELETED),
    )
    added = db.execute(
        "SELECT mtmf.application_add(%s, %s, 'Application', %s, %s::smallint, '{}'::jsonb)",
        (application_id, f"app-{application_id[:8]}", identity_id, lifecycle),
    ).fetchone()[0]
    assert added is True
    return application_id


def _seed_principal(db: psycopg.Connection) -> str:
    principal_id = _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'OP', %s)",
        (principal_id, _NOT_DELETED),
    )
    return principal_id


def _grant(
    db: psycopg.Connection,
    application_id: str,
    operator_id: str,
    *,
    quota_total: int = 3,
    reason: str = "approved onboarding",
) -> str:
    entitlement_id = _uuid()
    granted = db.execute(
        "SELECT mtmf.application_onboarding_entitlement_grant(%s, %s, %s, %s, %s, %s)",
        (entitlement_id, application_id, operator_id, reason, quota_total, _uuid()),
    ).fetchone()[0]
    assert granted is True
    return entitlement_id


def _events(db: psycopg.Connection, entitlement_id: str) -> list[tuple[int, int | None, int]]:
    rows = db.execute(
        "SELECT event_type, old_state, new_state, reason "
        "FROM mtmf.application_onboarding_entitlement_event "
        "WHERE entitlement_id = %s ORDER BY occurred_at, id",
        (entitlement_id,),
    ).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]


# --- P22-01: operator grant with explicit quota -------------------------------


def test_p22_01_operator_grant_with_explicit_quota(db: psycopg.Connection) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    entitlement_id = _grant(db, application_id, operator_id, quota_total=5)

    row = db.execute(
        "SELECT state, quota_total, quota_consumed, version, grant_reason, "
        "granted_by_operator_principal_id, revoked_at "
        "FROM mtmf.application_onboarding_entitlement WHERE id = %s",
        (entitlement_id,),
    ).fetchone()
    assert row is not None
    state, quota_total, quota_consumed, version, reason, granted_by, revoked_at = row
    assert state == 1
    assert quota_total == 5
    assert quota_consumed == 0
    assert version == 0
    assert reason == "approved onboarding"
    assert str(granted_by) == operator_id
    assert revoked_at is None

    # Exactly one immutable GRANTED event.
    assert _events(db, entitlement_id) == [(1, None, 1)]

    # A duplicate ACTIVE grant for the same Application is rejected (returns
    # false, no second row, no extra event).
    duplicate = db.execute(
        "SELECT mtmf.application_onboarding_entitlement_grant(%s, %s, %s, %s, %s, %s)",
        (_uuid(), application_id, operator_id, "dup", 1, _uuid()),
    ).fetchone()[0]
    assert duplicate is False
    active_count = db.execute(
        "SELECT count(*) FROM mtmf.application_onboarding_entitlement "
        "WHERE application_id = %s AND state = 1",
        (application_id,),
    ).fetchone()[0]
    assert active_count == 1
    assert len(_events(db, entitlement_id)) == 1


# --- P22-05 / P22-06: deny on inactive Application or invalid quota -----------


def test_p22_05_inactive_application_is_denied(db: psycopg.Connection) -> None:
    application_id = _seed_application(db, lifecycle=2)  # SUSPENDED
    operator_id = _seed_principal(db)
    with pytest.raises(psycopg.Error) as excinfo:
        _grant(db, application_id, operator_id)
    assert excinfo.value.sqlstate == "MT046"
    assert (
        db.execute("SELECT count(*) FROM mtmf.application_onboarding_entitlement").fetchone()[0]
        == 0
    )


def test_p22_05_unknown_application_is_denied(db: psycopg.Connection) -> None:
    operator_id = _seed_principal(db)
    with pytest.raises(psycopg.Error) as excinfo:
        _grant(db, _uuid(), operator_id)
    assert excinfo.value.sqlstate == "MT046"


def test_p22_06_nonpositive_quota_is_denied(db: psycopg.Connection) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    with pytest.raises(psycopg.Error) as excinfo:
        _grant(db, application_id, operator_id, quota_total=0)
    assert excinfo.value.sqlstate == "MT046"

    # A direct INSERT bypassing the explicit-limit check is rejected by the
    # table CHECK constraint.
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO mtmf.application_onboarding_entitlement "
            "(id, application_id, state, granted_at, granted_by_operator_principal_id, "
            " grant_reason, quota_total, quota_consumed, version) "
            "VALUES (%s, %s, 1, now(), %s, 'x', -1, 0, 0)",
            (_uuid(), application_id, operator_id),
        )


# --- P22-03 / P22-04: terminal revoke and fresh-UUID replacement --------------


def test_p22_03_revoke_is_terminal(db: psycopg.Connection) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    entitlement_id = _grant(db, application_id, operator_id)

    revoked = db.execute(
        "SELECT mtmf.application_onboarding_entitlement_revoke(%s, %s, %s, %s)",
        (entitlement_id, operator_id, "policy revoked", _uuid()),
    ).fetchone()[0]
    assert revoked is True

    row = db.execute(
        "SELECT state, revoked_at, revoked_by_operator_principal_id, revocation_reason, version "
        "FROM mtmf.application_onboarding_entitlement WHERE id = %s",
        (entitlement_id,),
    ).fetchone()
    assert row[0] == 2
    assert row[1] is not None
    assert str(row[2]) == operator_id
    assert row[3] == "policy revoked"
    assert row[4] == 1
    assert _events(db, entitlement_id) == [(1, None, 1), (2, 1, 2)]

    # A second revoke returns false (already terminal).
    again = db.execute(
        "SELECT mtmf.application_onboarding_entitlement_revoke(%s, %s, %s, %s)",
        (entitlement_id, operator_id, "again", _uuid()),
    ).fetchone()[0]
    assert again is False

    # Direct owner reactivation is rejected by the terminal guard.
    with pytest.raises(psycopg.Error) as excinfo:
        db.execute(
            "UPDATE mtmf.application_onboarding_entitlement SET state = 1 WHERE id = %s",
            (entitlement_id,),
        )
    assert excinfo.value.sqlstate == "MT046"

    # Immutable grant provenance cannot be rewritten.
    with pytest.raises(psycopg.Error) as excinfo:
        db.execute(
            "UPDATE mtmf.application_onboarding_entitlement "
            "SET granted_by_operator_principal_id = %s "
            "WHERE id = %s",
            (operator_id, entitlement_id),
        )
    assert excinfo.value.sqlstate == "MT046"


def test_p22_04_regrant_after_revoke_uses_fresh_uuid(db: psycopg.Connection) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    first_id = _grant(db, application_id, operator_id, quota_total=1)
    db.execute(
        "SELECT mtmf.application_onboarding_entitlement_revoke(%s, %s, %s, %s)",
        (first_id, operator_id, "superseded", _uuid()),
    )
    second_id = _grant(db, application_id, operator_id, quota_total=2)

    assert second_id != first_id
    rows = [
        (str(row[0]), row[1])
        for row in db.execute(
            "SELECT id, state FROM mtmf.application_onboarding_entitlement "
            "WHERE application_id = %s ORDER BY granted_at, id",
            (application_id,),
        ).fetchall()
    ]
    assert (first_id, 2) in rows
    assert (second_id, 1) in rows
    # Both histories are intact and independent.
    assert _events(db, first_id) == [(1, None, 1), (2, 1, 2)]
    assert _events(db, second_id) == [(1, None, 1)]


# --- P22-18: append-only history and no runtime grants ------------------------


def test_p22_18_history_is_append_only(db: psycopg.Connection) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    entitlement_id = _grant(db, application_id, operator_id)
    event_id = db.execute(
        "SELECT id FROM mtmf.application_onboarding_entitlement_event WHERE entitlement_id = %s",
        (entitlement_id,),
    ).fetchone()[0]
    with pytest.raises(psycopg.Error) as excinfo:
        db.execute(
            "UPDATE mtmf.application_onboarding_entitlement_event "
            "SET reason = 'tamper' WHERE id = %s",
            (event_id,),
        )
    assert excinfo.value.sqlstate == "MT046"


# --- P22-02 / P22-16: restricted runtime is denied ----------------------------


def test_p22_02_runtime_cannot_grant_entitlement(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.application_onboarding_entitlement_grant(%s, %s, %s, %s, %s, %s)",
            (_uuid(), application_id, operator_id, "x", 1, _uuid()),
        )


def test_p22_16_runtime_cannot_read_or_revoke_entitlement(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    entitlement_id = _grant(db, application_id, operator_id)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.application_onboarding_entitlement_get(%s)", (entitlement_id,)
        )
    runtime_connection.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.application_onboarding_entitlement_revoke(%s, %s, %s, %s)",
            (entitlement_id, operator_id, "x", _uuid()),
        )
    runtime_connection.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT * FROM mtmf.application_onboarding_entitlement")


def test_p22_17_migration_postflight_and_runtime_allowlist_unchanged(
    runtime_connection: psycopg.Connection,
) -> None:
    """The restricted runtime still has exactly the approved 78 signatures."""
    count = runtime_connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
    ).fetchone()[0]
    assert count == 78


# --- PR 22A Step 22A-2: concurrency, no-linkage, and nil-UUID invariants --------


def test_p22a_concurrent_duplicate_grant_has_one_active(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    """Two concurrent grants for one Application yield exactly one ACTIVE row."""
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    barrier = threading.Barrier(2)
    results: list[bool] = []
    lock = threading.Lock()

    def grant() -> None:
        with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
            barrier.wait()
            granted = connection.execute(
                "SELECT mtmf.application_onboarding_entitlement_grant(%s, %s, %s, %s, %s, %s)",
                (_uuid(), application_id, operator_id, "race", 1, _uuid()),
            ).fetchone()[0]
            with lock:
                results.append(bool(granted))

    threads = [threading.Thread(target=grant) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    active = db.execute(
        "SELECT count(*) FROM mtmf.application_onboarding_entitlement "
        "WHERE application_id = %s AND state = 1",
        (application_id,),
    ).fetchone()[0]
    assert active == 1
    events = db.execute(
        "SELECT count(*) FROM mtmf.application_onboarding_entitlement_event "
        "WHERE entitlement_id IN ("
        "  SELECT id FROM mtmf.application_onboarding_entitlement "
        "  WHERE application_id = %s AND state = 1)",
        (application_id,),
    ).fetchone()[0]
    assert events == 1


def test_p22a_entitlement_functions_create_no_tenant_or_linkage(db: psycopg.Connection) -> None:
    """The entitlement primitives never create a Tenant, registration, or subscription."""
    application_id = _seed_application(db)
    operator_id = _seed_principal(db)
    entitlement_id = _grant(db, application_id, operator_id)
    db.execute(
        "SELECT mtmf.application_onboarding_entitlement_revoke(%s, %s, %s, %s)",
        (entitlement_id, operator_id, "done", _uuid()),
    )
    for statement in (
        "SELECT count(*) FROM mtmf.tenant",
        "SELECT count(*) FROM mtmf.application_tenant_registration",
        "SELECT count(*) FROM mtmf.tenant_application_subscription",
    ):
        assert db.execute(statement).fetchone()[0] == 0


def test_p22a_nil_application_and_operator_uuids_are_denied(db: psycopg.Connection) -> None:
    """Nil/unknown foreign keys fail closed through the reviewed constraints."""
    operator_id = _seed_principal(db)
    nil = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(psycopg.Error):
        _grant(db, nil, operator_id)
    application_id = _seed_application(db)
    with pytest.raises(psycopg.Error):
        _grant(db, application_id, nil)
