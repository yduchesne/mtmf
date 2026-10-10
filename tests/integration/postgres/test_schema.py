"""Schema shape tests (SCH).

Verifies the physical ``mtmf`` schema: expected tables exist, forbidden
tables do not, UUID identities map to PostgreSQL ``uuid``, URN
identities are primary keys, and membership facts use composite
identities with no surrogate IDs.
"""

from __future__ import annotations

import helpers
import pytest

EXPECTED_TABLES = {
    "tenant",
    "organization",
    "principal",
    "identity",
    "group",
    "role",
    "permission_set",
    "permission",
    "action",
    *helpers.MEMBERSHIP_TABLES,
    helpers.AUDIT_TABLE,
}


def test_sch01_mtmf_schema_exists(db) -> None:
    row = db.execute(
        "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = %s", (helpers.SCHEMA,)
    ).fetchone()
    assert row is not None


@pytest.mark.parametrize("table", sorted(EXPECTED_TABLES))
def test_sch02_to_sch04_expected_tables_exist(db, table: str) -> None:
    assert table in helpers.tables(db)


@pytest.mark.parametrize(
    ("table", "reason"),
    [
        ("generic_membership", "no generic membership table"),
        ("membership", "no generic membership table"),
        ("principal_org_membership", "Principal Organization membership is UNRESOLVED"),
        ("principal_group_membership", "no Principal Group membership"),
        ("role_assignment", "Role assignments belong to PR 9"),
        ("tenant_stewardship", "stewardship belongs to later PRs"),
        ("audit_event", "audit schema is not part of PR 6"),
    ],
)
def test_sch05_to_sch07_forbidden_tables_are_absent(db, table: str, reason: str) -> None:
    assert table not in helpers.tables(db), reason


@pytest.mark.parametrize(
    "table",
    [
        "tenant",
        "organization",
        "principal",
        "identity",
        "group",
        "permission_set",
        "permission",
    ],
)
def test_sch08_uuid_identities_use_postgres_uuid(db, table: str) -> None:
    assert helpers.columns_of(db, table)["id"] == "uuid"


@pytest.mark.parametrize("table", ("role", "action"))
def test_sch09_urn_identities_are_primary_keys(db, table: str) -> None:
    assertive = helpers.primary_key_columns(db, table)
    assert assertive == {"urn"}


@pytest.mark.parametrize("table", sorted(helpers.MEMBERSHIP_TABLES))
def test_sch10_memberships_use_composite_identities_without_surrogate_ids(db, table: str) -> None:
    columns = helpers.columns_of(db, table)
    assert "id" not in columns, "membership rows must not carry a surrogate identity"
    pkey = helpers.primary_key_columns(db, table)
    assert len(pkey) == 2
    assert all(name in columns for name in pkey)
