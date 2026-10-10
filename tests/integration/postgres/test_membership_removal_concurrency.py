"""Concurrent removal/insertion integrity tests (TXN-03..TXN-06).

Proves, on real PostgreSQL, that duplicate removals serialize to one
effective removal with one audit row, and that a dependent INSERT cannot
commit an orphan while its prerequisite is being removed. Synchronization
uses row locks and a bounded wait for the database to report a lock wait;
there are no correctness sleeps.
"""

from __future__ import annotations

import threading
import time

import helpers
import psycopg
import psycopg.errors

_INSERTER = "mtmf-race-inserter"
_REMOVER = "mtmf-race-remover"


def _wait_for_lock_wait(observer: psycopg.Connection, application_name: str) -> None:
    """Wait (bounded) until the named backend is blocked on a lock."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE application_name = %s AND wait_event_type = 'Lock'",
            (application_name,),
        ).fetchone()
        if row[0] > 0:
            return
        time.sleep(0.02)
    raise AssertionError(f"backend {application_name!r} never blocked on a lock")


def test_txn03_concurrent_double_removal_yields_one_removal_and_one_audit(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    barrier = threading.Barrier(2)
    outcomes: list[bool] = []
    guard = threading.Lock()

    def worker() -> None:
        connection = psycopg.connect(dsn, autocommit=True)
        try:
            barrier.wait(timeout=10)
            removed = helpers.remove_membership(
                connection,
                "identity_tenant_membership",
                helpers.IDENTITY_A,
                helpers.TENANT_A,
            )
            with guard:
                outcomes.append(removed)
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert sorted(outcomes) == [False, True]
    assert len(helpers.audit_rows(db)) == 1


def test_txn04_dependent_insert_loses_to_parent_delete(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    extra_org = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.organization "
        "(id, tenant_id, name, owner_identity_id, deletion_status) "
        "VALUES (%s, %s, 'X', %s, 2)",
        (extra_org, helpers.TENANT_A, helpers.IDENTITY_A),
    )
    db.commit()

    # Hold the prerequisite lock exactly as the removal function does.
    remover = psycopg.connect(dsn)
    remover.execute(
        "SELECT 1 FROM mtmf.identity_tenant_membership "
        "WHERE identity_id = %s AND tenant_id = %s FOR UPDATE",
        (helpers.IDENTITY_A, helpers.TENANT_A),
    )
    observer = psycopg.connect(dsn, autocommit=True)
    outcome: dict[str, str] = {}

    def inserter() -> None:
        connection = psycopg.connect(dsn, application_name=_INSERTER)
        try:
            connection.execute(
                "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, extra_org),
            )
            connection.commit()
            outcome["result"] = "committed"
        except psycopg.errors.RaiseException:
            connection.rollback()
            outcome["result"] = "rejected"
        finally:
            connection.close()

    thread = threading.Thread(target=inserter)
    thread.start()
    _wait_for_lock_wait(observer, _INSERTER)
    remover.execute(
        "SELECT mtmf.remove_identity_tenant_membership(%s, %s)",
        (helpers.IDENTITY_A, helpers.TENANT_A),
    )
    remover.commit()
    thread.join(timeout=15)
    observer.close()
    remover.close()

    assert outcome["result"] == "rejected"
    assert (
        helpers.membership_count(
            db,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, extra_org),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            db,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 0
    )
    assert len(helpers.audit_rows(db)) == 1


def test_txn04b_committed_dependent_is_still_cascaded_away(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    extra_org = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.organization "
        "(id, tenant_id, name, owner_identity_id, deletion_status) "
        "VALUES (%s, %s, 'X', %s, 2)",
        (extra_org, helpers.TENANT_A, helpers.IDENTITY_A),
    )
    db.commit()

    holder = psycopg.connect(dsn, application_name=_INSERTER)
    holder.execute(
        "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
        (helpers.IDENTITY_A, extra_org),
    )
    observer = psycopg.connect(dsn, autocommit=True)
    removed: dict[str, object] = {}

    def remover() -> None:
        connection = psycopg.connect(dsn, application_name=_REMOVER)
        try:
            connection.execute(
                "SELECT mtmf.remove_identity_tenant_membership(%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.commit()
            removed["ok"] = True
        finally:
            connection.close()

    thread = threading.Thread(target=remover)
    thread.start()
    _wait_for_lock_wait(observer, _REMOVER)
    holder.commit()
    thread.join(timeout=15)
    observer.close()
    holder.close()

    assert removed.get("ok") is True
    assert (
        helpers.membership_count(
            db,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, extra_org),
        )
        == 0
    )
    row = helpers.audit_rows(db)[0]
    # The only remaining IdentityOrgMembership is the unrelated Tenant B row;
    # both Tenant A rows (ORG_A and the raced-in extra organization) were
    # physically deleted and counted.
    assert helpers.membership_count(db, "identity_org_membership") == 1
    assert row[13] == 2


def test_txn05_identity_group_insert_loses_to_group_tenant_delete(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    extra_group = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'G2', 2)",
        (extra_group, helpers.TENANT_A),
    )
    helpers.insert_memberships(db, group_tenant=(extra_group, helpers.TENANT_A))
    db.commit()

    remover = psycopg.connect(dsn)
    remover.execute(
        "SELECT 1 FROM mtmf.group_tenant_membership "
        "WHERE group_id = %s AND tenant_id = %s FOR UPDATE",
        (extra_group, helpers.TENANT_A),
    )
    observer = psycopg.connect(dsn, autocommit=True)
    outcome: dict[str, str] = {}

    def inserter() -> None:
        connection = psycopg.connect(dsn, application_name=_INSERTER)
        try:
            connection.execute(
                "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, extra_group),
            )
            connection.commit()
            outcome["result"] = "committed"
        except psycopg.errors.RaiseException:
            connection.rollback()
            outcome["result"] = "rejected"
        finally:
            connection.close()

    thread = threading.Thread(target=inserter)
    thread.start()
    _wait_for_lock_wait(observer, _INSERTER)
    remover.execute(
        "SELECT mtmf.remove_group_tenant_membership(%s, %s)",
        (extra_group, helpers.TENANT_A),
    )
    remover.commit()
    thread.join(timeout=15)
    observer.close()
    remover.close()

    assert outcome["result"] == "rejected"
    assert (
        helpers.membership_count(
            db,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, extra_group),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            db,
            "group_tenant_membership",
            "group_id = %s",
            (extra_group,),
        )
        == 0
    )


def test_txn06_identity_tenant_insert_loses_to_principal_tenant_delete(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    new_identity = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I9', 1, 2)",
        (new_identity, helpers.PRINCIPAL),
    )
    db.commit()

    remover = psycopg.connect(dsn)
    remover.execute(
        "SELECT 1 FROM mtmf.principal_tenant_membership "
        "WHERE principal_id = %s AND tenant_id = %s FOR UPDATE",
        (helpers.PRINCIPAL, helpers.TENANT_A),
    )
    observer = psycopg.connect(dsn, autocommit=True)
    outcome: dict[str, str] = {}

    def inserter() -> None:
        connection = psycopg.connect(dsn, application_name=_INSERTER)
        try:
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (new_identity, helpers.TENANT_A),
            )
            connection.commit()
            outcome["result"] = "committed"
        except psycopg.errors.RaiseException:
            connection.rollback()
            outcome["result"] = "rejected"
        finally:
            connection.close()

    thread = threading.Thread(target=inserter)
    thread.start()
    _wait_for_lock_wait(observer, _INSERTER)
    remover.execute(
        "SELECT mtmf.remove_principal_tenant_membership(%s, %s)",
        (helpers.PRINCIPAL, helpers.TENANT_A),
    )
    remover.commit()
    thread.join(timeout=15)
    observer.close()
    remover.close()

    assert outcome["result"] == "rejected"
    assert (
        helpers.membership_count(
            db,
            "identity_tenant_membership",
            "identity_id = %s",
            (new_identity,),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            db,
            "principal_tenant_membership",
            "principal_id = %s AND tenant_id = %s",
            (helpers.PRINCIPAL, helpers.TENANT_A),
        )
        == 0
    )


def test_leaf13_concurrent_double_leaf_removal_yields_one_audit(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    barrier = threading.Barrier(2)
    outcomes: list[bool] = []
    guard = threading.Lock()

    def worker() -> None:
        connection = psycopg.connect(dsn, autocommit=True)
        try:
            barrier.wait(timeout=10)
            removed = helpers.remove_identity_group_membership(
                connection, helpers.IDENTITY_A, helpers.GROUP_A
            )
            with guard:
                outcomes.append(removed)
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert sorted(outcomes) == [False, True]
    assert len(helpers.audit_rows(db)) == 1
    # The removed leaf's prerequisite and the sibling identity's membership
    # are untouched by the duplicate attempt.
    assert (
        helpers.membership_count(
            db,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            db,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_B, helpers.GROUP_B),
        )
        == 1
    )
