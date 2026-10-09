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
