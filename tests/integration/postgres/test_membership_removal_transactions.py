"""Removal transaction rollback tests (TXN-01, TXN-02)."""

from __future__ import annotations

import helpers
import psycopg
import pytest


def test_txn01_failed_audit_insert_rolls_back_all_deletions(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    before = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    connection = psycopg.connect(dsn)
    try:
        # An unknown actor violates the audit FK, so the final INSERT fails
        # after every DELETE has already run in the same transaction.
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute(
                "SELECT mtmf.remove_identity_tenant_membership(%s, %s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A, helpers.new_id()),
            )
        connection.rollback()
    finally:
        connection.close()

    after = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    assert after == before
    assert helpers.audit_rows(db) == []


def test_txn02_failed_cascade_rolls_back_deletions_and_audit(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    before = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    connection = psycopg.connect(dsn)
    try:
        connection.execute(
            "CREATE FUNCTION mtmf.force_cascade_failure() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced cascade failure'; END; $$"
        )
        connection.execute(
            "CREATE TRIGGER force_cascade_failure "
            "BEFORE DELETE ON mtmf.identity_org_membership "
            "FOR EACH ROW EXECUTE FUNCTION mtmf.force_cascade_failure()"
        )
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute(
                "SELECT mtmf.remove_identity_tenant_membership(%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
        connection.rollback()
    finally:
        connection.close()

    after = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    assert after == before
    assert helpers.audit_rows(db) == []


_LEAF_CASES = [
    ("identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_A),
    ("identity_org_membership", helpers.IDENTITY_A, helpers.ORG_A),
    ("group_org_membership", helpers.GROUP_A, helpers.ORG_A),
]


@pytest.mark.parametrize(("kind", "first_id", "second_id"), _LEAF_CASES)
def test_leaf10_invalid_actor_rolls_back_leaf_removal(
    db, dsn: str, kind: str, first_id: str, second_id: str
) -> None:
    helpers.seed_full_membership_graph(db)
    before = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            helpers.remove_membership(connection, kind, first_id, second_id, actor=helpers.new_id())
        connection.rollback()
    finally:
        connection.close()

    after = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}
    assert after == before
    assert helpers.audit_rows(db) == []


def test_leaf11_forced_audit_failure_preserves_leaf_membership(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    connection = psycopg.connect(dsn)
    try:
        connection.execute(
            "CREATE FUNCTION mtmf.force_audit_failure() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced audit failure'; END; $$"
        )
        connection.execute(
            "CREATE TRIGGER force_audit_failure "
            "BEFORE INSERT ON mtmf.membership_removal_audit "
            "FOR EACH ROW EXECUTE FUNCTION mtmf.force_audit_failure()"
        )
        with pytest.raises(psycopg.errors.RaiseException):
            helpers.remove_identity_group_membership(
                connection, helpers.IDENTITY_A, helpers.GROUP_A
            )
        connection.rollback()
    finally:
        connection.close()

    assert (
        helpers.membership_count(
            db,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 1
    )
    assert helpers.audit_rows(db) == []


def test_leaf12_caller_rollback_restores_membership_and_audit(db, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    connection = psycopg.connect(dsn)
    try:
        assert helpers.remove_identity_org_membership(connection, helpers.IDENTITY_A, helpers.ORG_A)
        # The function does not commit; a caller rollback must undo both the
        # deletion and the audit insertion.
        connection.rollback()
    finally:
        connection.close()

    assert (
        helpers.membership_count(
            db,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 1
    )
    assert helpers.audit_rows(db) == []
