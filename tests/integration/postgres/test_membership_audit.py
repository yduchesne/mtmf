"""Compact membership-removal audit tests (AUD).

One initiating removal writes exactly one operation-level audit row with
actual affected-row counts by typed membership. The record never
enumerates affected members, never fabricates an actor, and is
append-only at the database boundary.
"""

from __future__ import annotations

import datetime as dt

import helpers
import psycopg
import psycopg.errors
import pytest


@pytest.fixture
def graph(db) -> psycopg.Connection:
    helpers.seed_full_membership_graph(db)
    return db


def test_aud01_one_audit_row_for_thousands_of_dependents(db) -> None:
    helpers.seed_base_entities(db)
    helpers.insert_memberships(
        db,
        principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A),
        identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A),
    )
    org_ids = [helpers.new_id() for _ in range(1000)]
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO mtmf.organization "
            "(id, tenant_id, name, owner_identity_id, deletion_status) "
            "VALUES (%s, %s, 'O', %s, 2)",
            [(org_id, helpers.TENANT_A, helpers.IDENTITY_A) for org_id in org_ids],
        )
        cursor.executemany(
            "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
            [(helpers.IDENTITY_A, org_id) for org_id in org_ids],
        )
    db.commit()

    assert helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert helpers.membership_count(db, "identity_org_membership") == 0
    rows = helpers.audit_rows(db)
    assert len(rows) == 1
    assert rows[0][13] == 1000  # identity_org_count


@pytest.mark.parametrize(
    ("initiating_kind", "participant", "tenant", "participant_index"),
    [
        ("principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A, 4),
        ("identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A, 5),
        ("group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A, 6),
    ],
)
def test_aud02_audit_identifies_initiator_participants_tenant_actor_and_time(
    graph: psycopg.Connection,
    initiating_kind: str,
    participant: str,
    tenant: str,
    participant_index: int,
) -> None:
    before = dt.datetime.now(tz=dt.UTC)
    assert helpers.remove_membership(
        graph, initiating_kind, participant, tenant, actor=helpers.IDENTITY_B
    )
    after = dt.datetime.now(tz=dt.UTC)

    rows = helpers.audit_rows(graph)
    assert len(rows) == 1
    row = rows[0]
    assert row[2] == initiating_kind
    assert str(row[3]) == tenant
    assert str(row[participant_index]) == participant
    assert str(row[8]) == helpers.IDENTITY_B
    assert before <= row[1] <= after


def test_aud03_counts_match_actual_deleted_rows_for_all_types(
    graph: psycopg.Connection,
) -> None:
    before = {table: helpers.membership_count(graph, table) for table in helpers.MEMBERSHIP_TABLES}
    helpers.remove_membership(
        graph, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    after = {table: helpers.membership_count(graph, table) for table in helpers.MEMBERSHIP_TABLES}
    row = helpers.audit_rows(graph)[0]
    counts = {
        "principal_tenant_membership": row[9],
        "identity_tenant_membership": row[10],
        "group_tenant_membership": row[11],
        "identity_group_membership": row[12],
        "identity_org_membership": row[13],
        "group_org_membership": row[14],
    }
    for table in helpers.MEMBERSHIP_TABLES:
        assert counts[table] == before[table] - after[table]
    assert counts["principal_tenant_membership"] == 1
    assert counts["identity_tenant_membership"] == 1
    assert counts["identity_org_membership"] == 1
    assert counts["identity_group_membership"] == 1


def test_aud04_audit_stores_no_member_arrays_or_history(db) -> None:
    helpers.seed_full_membership_graph(db)
    helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    columns = db.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s",
        (helpers.SCHEMA, helpers.AUDIT_TABLE),
    ).fetchall()
    for name, data_type in columns:
        assert data_type != "ARRAY", f"{name} must not be an array"
        assert "json" not in data_type
        assert "affected" not in name
        assert "members" not in name
    assert "history" not in {name for name, _ in columns}


def test_aud05_missing_actor_is_null_never_invented(db) -> None:
    helpers.seed_full_membership_graph(db)
    helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    row = helpers.audit_rows(db)[0]
    assert row[8] is None


def test_aud06_audit_rows_cannot_be_updated_or_deleted(db) -> None:
    helpers.seed_full_membership_graph(db)
    helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        db.execute(
            "UPDATE mtmf.membership_removal_audit SET tenant_id = %s",
            (helpers.TENANT_B,),
        )
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        db.execute("DELETE FROM mtmf.membership_removal_audit")


def test_aud07_audit_schema_rejects_invalid_kind_and_shape(db) -> None:
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, principal_id, principal_tenant_count) "
            "VALUES ('not_a_membership_kind', %s, %s, 1)",
            (helpers.TENANT_A, helpers.PRINCIPAL),
        )
    # principal_tenant_membership must not carry a group participant.
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, principal_id, group_id, principal_tenant_count) "
            "VALUES ('principal_tenant_membership', %s, %s, %s, 1)",
            (helpers.TENANT_A, helpers.PRINCIPAL, helpers.GROUP_A),
        )
    # Counts are nonnegative and the initiating type must be at least one.
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, identity_id, identity_tenant_count) "
            "VALUES ('identity_tenant_membership', %s, %s, -1)",
            (helpers.TENANT_A, helpers.IDENTITY_A),
        )
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, identity_id, identity_tenant_count) "
            "VALUES ('identity_tenant_membership', %s, %s, 0)",
            (helpers.TENANT_A, helpers.IDENTITY_A),
        )
