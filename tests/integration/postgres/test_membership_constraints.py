"""Typed membership constraint tests (MEM).

Proves the settled structural Tenant semantics at the database trusted
boundary: prerequisites are required immediately at write time (MTMF
write paths insert prerequisite facts before dependent facts inside one
transaction), cross-Tenant membership is rejected, duplicates are
rejected, sibling Identities never inherit membership, membership facts
are immutable (frozen value objects), and no polymorphic membership or
Principal-Organization surface exists.
"""

from __future__ import annotations

import helpers
import psycopg
import psycopg.errors
import psycopg.sql
import pytest


def _new_connection(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn)


def test_mem01_valid_principal_tenant_membership_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("principal", "tenant"),
    [
        (helpers.new_id(), helpers.TENANT_A),  # missing Principal
        (helpers.PRINCIPAL, helpers.new_id()),  # missing Tenant
    ],
)
def test_mem02_missing_principal_or_tenant_rejected(
    db, dsn: str, principal: str, tenant: str
) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (principal, tenant),
            )
    finally:
        connection.close()


def test_mem03_valid_identity_tenant_membership_with_predecessor_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            # Prerequisite rows are written before the dependent row, per
            # the documented immediate-validation ordering contract.
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
    finally:
        connection.close()


def test_mem04_missing_principal_tenant_membership_predecessor_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
    finally:
        connection.close()


def test_mem05_valid_group_tenant_membership_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.TENANT_A),
            )
    finally:
        connection.close()


def test_mem06_group_tenant_membership_wrong_tenant_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.TENANT_B),
            )
    finally:
        connection.close()


def test_mem07_identity_group_membership_requires_identity_tenant_membership(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.GROUP_A),
            )
    finally:
        connection.close()


def test_mem07b_valid_identity_group_membership_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.GROUP_A),
            )
    finally:
        connection.close()


def test_mem08_cross_tenant_identity_group_membership_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            # I_A is only Tenanted in Tenant A; Group B belongs to Tenant B.
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.GROUP_B),
            )
    finally:
        connection.close()


def test_mem09_identity_org_membership_requires_identity_tenant_membership(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.ORG_A),
            )
    finally:
        connection.close()


def test_mem10_cross_tenant_identity_org_membership_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.ORG_B),  # Org B is in Tenant B
            )
    finally:
        connection.close()


def test_mem10b_valid_identity_org_membership_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.ORG_A),
            )
    finally:
        connection.close()


def test_mem11_group_org_membership_requires_same_tenant(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.group_org_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.ORG_B),  # Group A in Tenant A, Org B in Tenant B
            )
    finally:
        connection.close()


def test_mem12_group_org_membership_requires_group_tenant_membership(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group_org_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.ORG_A),
            )
    finally:
        connection.close()


def test_mem12b_valid_group_org_membership_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.group_org_membership VALUES (%s, %s)",
                (helpers.GROUP_A, helpers.ORG_A),
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("table", "values"),
    [
        (
            "principal_tenant_membership",
            (helpers.PRINCIPAL, helpers.TENANT_A),
        ),
        ("identity_tenant_membership", (helpers.IDENTITY_A, helpers.TENANT_A)),
        ("group_tenant_membership", (helpers.GROUP_A, helpers.TENANT_A)),
        ("identity_group_membership", (helpers.IDENTITY_A, helpers.GROUP_A)),
        ("identity_org_membership", (helpers.IDENTITY_A, helpers.ORG_A)),
        ("group_org_membership", (helpers.GROUP_A, helpers.ORG_A)),
    ],
)
def test_mem13_duplicate_typed_membership_rejected(db, dsn: str, table: str, values) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    prereq = _PREREQUISITES[table]
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            for statement, params in prereq:
                connection.execute(statement, params)
            connection.execute(_membership_insert(table), values)
            connection.execute(_membership_insert(table), values)
    finally:
        connection.close()


def test_mem14_valid_multi_tenant_principal_identity_membership_supported(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            # The Principal is member of both Tenants; each Identity is
            # usable only where its own membership says so.
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_B),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_B, helpers.TENANT_B),
            )
    finally:
        connection.close()


def test_mem15_sibling_identity_membership_not_inherited(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            # I_A belongs to Group A; sibling I_B cannot inherit I_A's
            # Tenant usability to join Group A.
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
                (helpers.IDENTITY_A, helpers.TENANT_A),
            )
            connection.execute(
                "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
                (helpers.IDENTITY_B, helpers.GROUP_A),
            )
    finally:
        connection.close()


def test_mem16_no_principal_org_membership_persistence_surface(db) -> None:
    assert "principal_org_membership" not in helpers.tables(db)


def test_membership_rows_are_immutable_facts(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = _new_connection(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
                (helpers.PRINCIPAL, helpers.TENANT_A),
            )
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "UPDATE mtmf.principal_tenant_membership SET tenant_id = %s",
                (helpers.TENANT_B,),
            )
    finally:
        connection.close()


def _membership_insert(table: str) -> psycopg.sql.SQL:
    """Compose a parameterized membership INSERT for a typed table."""
    return psycopg.sql.SQL("INSERT INTO mtmf.{} VALUES (%s, %s)").format(
        psycopg.sql.Identifier(table)
    )


_PREREQUISITES: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "principal_tenant_membership": (),
    "identity_tenant_membership": (
        (
            "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
            (helpers.PRINCIPAL, helpers.TENANT_A),
        ),
    ),
    "group_tenant_membership": (),
    "identity_group_membership": (
        (
            "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
            (helpers.PRINCIPAL, helpers.TENANT_A),
        ),
        (
            "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        ),
        (
            "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
            (helpers.GROUP_A, helpers.TENANT_A),
        ),
    ),
    "identity_org_membership": (
        (
            "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
            (helpers.PRINCIPAL, helpers.TENANT_A),
        ),
        (
            "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        ),
    ),
    "group_org_membership": (
        (
            "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
            (helpers.GROUP_A, helpers.TENANT_A),
        ),
    ),
}
