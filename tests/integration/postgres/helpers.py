"""Helpers shared by the MTMF PostgreSQL integration tests.

The canonical structural graph mirrors the unit-test domain graph: two
Tenants, one Principal with two Identities, one Organization and one
Group per Tenant. Entity rows (never memberships) can be seeded by
:func:`seed_base_entities`; membership facts are added by each test so
that precondition expectations remain controlled.
"""

from __future__ import annotations

import uuid

import psycopg

SCHEMA = "mtmf"

# Fixed canonical UUIDs for deterministic tests.
PRINCIPAL = "11111111-1111-4111-8111-111111111111"
IDENTITY_A = "22222222-2222-4222-8222-222222222222"
IDENTITY_B = "33333333-3333-4333-8333-333333333333"
TENANT_A = "44444444-4444-4444-8444-444444444444"
TENANT_B = "55555555-5555-4555-8555-555555555555"
ORG_A = "66666666-6666-4666-8666-666666666666"
ORG_B = "77777777-7777-4777-8777-777777777777"
GROUP_A = "88888888-8888-4888-8888-888888888888"
GROUP_B = "99999999-9999-4999-8999-999999999999"

# d3d3d3d3-d3d3-4d3d-8d3d-d3d3d3d3d3d3 reserved for per-test synthetic IDs.
ROLE_URN = "urn:mtmf:iam:roles:system:integration-role"
ACTION_URN = "urn:mtmf:iam:actions:system:principal:get-object"
PERMISSION_URN_EXACT = "urn:mtmf:iam:permissions:system:principal:get-object"
PERMISSION_URN_WILDCARD = "urn:mtmf:iam:permissions:system:principal:get-*"

ENTITY_TABLES = ("tenant", "organization", "principal", "identity", "group")
DELETION_TABLES = ENTITY_TABLES
EXTENSION_TABLES = ("tenant", "organization", "principal", "identity", "group", "role")
MEMBERSHIP_TABLES = (
    "principal_tenant_membership",
    "identity_tenant_membership",
    "group_tenant_membership",
    "identity_group_membership",
    "identity_org_membership",
    "group_org_membership",
)


def new_id() -> str:
    """Return a fresh canonical (lowercase) UUIDv4 string."""
    return str(uuid.uuid4())


def reset_and_migrate(connection: psycopg.Connection, config: object) -> None:
    """Drop the MTMF schema (owned by the MTMF user) and upgrade to head.

    Only the ``mtmf`` schema inside the explicitly configured MTMF
    database is touched; nothing outside it is dropped.
    """
    from mtmf_core.persistence.postgres import PostgresMigrationManager

    connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
    PostgresMigrationManager(config).upgrade_to_head()


def seed_base_entities(connection: psycopg.Connection) -> None:
    """Insert the canonical entity graph (no membership rows)."""
    connection.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (PRINCIPAL,),
    )
    for identity_id, name in ((IDENTITY_A, "I1"), (IDENTITY_B, "I2")):
        connection.execute(
            "INSERT INTO mtmf.identity (id, principal_id, name, deletion_status) "
            "VALUES (%s, %s, %s, 2)",
            (identity_id, PRINCIPAL, name),
        )
    for tenant_id, name in ((TENANT_A, "Tenant A"), (TENANT_B, "Tenant B")):
        connection.execute(
            "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, deletion_status) "
            "VALUES (%s, %s, 2, %s, 2)",
            (tenant_id, name, IDENTITY_A),
        )
    for org_id, tenant_id, name in (
        (ORG_A, TENANT_A, "Org A"),
        (ORG_B, TENANT_B, "Org B"),
    ):
        connection.execute(
            "INSERT INTO mtmf.organization "
            "(id, tenant_id, name, owner_identity_id, deletion_status) "
            "VALUES (%s, %s, %s, %s, 2)",
            (org_id, tenant_id, name, IDENTITY_A),
        )
    for group_id, tenant_id, name in (
        (GROUP_A, TENANT_A, "Group A"),
        (GROUP_B, TENANT_B, "Group B"),
    ):
        connection.execute(
            "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, %s, 2)",
            (group_id, tenant_id, name),
        )
    connection.commit()


def tables(connection: psycopg.Connection, schema: str = SCHEMA) -> set[str]:
    rows = connection.execute(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = %s",
        (schema,),
    ).fetchall()
    return {row[0] for row in rows}


def columns_of(connection: psycopg.Connection, table: str) -> dict[str, str]:
    """Map column name -> data_type for one ``mtmf`` table."""
    rows = connection.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s",
        (SCHEMA, table),
    ).fetchall()
    return {row[0]: row[1] for row in rows}


def primary_key_columns(connection: psycopg.Connection, table: str) -> set[str]:
    rows = connection.execute(
        "SELECT a.attname "
        "FROM pg_catalog.pg_index i "
        "JOIN pg_catalog.pg_class c ON c.oid = i.indrelid "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey) "
        "WHERE n.nspname = %s AND c.relname = %s AND i.indisprimary",
        (SCHEMA, table),
    ).fetchall()
    return {row[0] for row in rows}


def functions_in_schema(connection: psycopg.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT p.proname FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s",
        (SCHEMA,),
    ).fetchall()
    return {row[0] for row in rows}


# --- Membership removal helpers (PR 6B) --------------------------------------

AUDIT_TABLE = "membership_removal_audit"

# Mapping from the initiating typed membership to its sanctioned removal
# function. The three tenant memberships cascade to their dependents; the
# three leaf memberships remove only their own row.
REMOVAL_FUNCTIONS = {
    "principal_tenant_membership": "mtmf.remove_principal_tenant_membership",
    "identity_tenant_membership": "mtmf.remove_identity_tenant_membership",
    "group_tenant_membership": "mtmf.remove_group_tenant_membership",
    "identity_group_membership": "mtmf.remove_identity_group_membership",
    "identity_org_membership": "mtmf.remove_identity_org_membership",
    "group_org_membership": "mtmf.remove_group_org_membership",
}

# First participant column for each typed membership.
INITIATOR_PARTICIPANT_COLUMN = {
    "principal_tenant_membership": "principal_id",
    "identity_tenant_membership": "identity_id",
    "group_tenant_membership": "group_id",
    "identity_group_membership": "identity_id",
    "identity_org_membership": "identity_id",
    "group_org_membership": "group_id",
}

# Second participant column: the Tenant for the three tenant memberships,
# the other entity for the three leaf memberships.
INITIATOR_SECOND_PARTICIPANT_COLUMN = {
    "principal_tenant_membership": "tenant_id",
    "identity_tenant_membership": "tenant_id",
    "group_tenant_membership": "tenant_id",
    "identity_group_membership": "group_id",
    "identity_org_membership": "organization_id",
    "group_org_membership": "organization_id",
}

# The membership table whose count column records the initiating row.
INITIATOR_COUNT_COLUMN = {
    "principal_tenant_membership": "principal_tenant_count",
    "identity_tenant_membership": "identity_tenant_count",
    "group_tenant_membership": "group_tenant_count",
    "identity_group_membership": "identity_group_count",
    "identity_org_membership": "identity_org_count",
    "group_org_membership": "group_org_count",
}


def insert_memberships(connection: psycopg.Connection, **memberships: tuple[str, ...]) -> None:
    """Insert typed membership rows by keyword (caller commits).

    Recognized keywords: ``principal_tenant``, ``identity_tenant``,
    ``group_tenant``, ``identity_org``, ``identity_group``, ``group_org``.
    Each value is the participant pair expected by the table.
    """
    inserts = {
        "principal_tenant": "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
        "identity_tenant": "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
        "group_tenant": "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
        "identity_org": "INSERT INTO mtmf.identity_org_membership VALUES (%s, %s)",
        "identity_group": "INSERT INTO mtmf.identity_group_membership VALUES (%s, %s)",
        "group_org": "INSERT INTO mtmf.group_org_membership VALUES (%s, %s)",
    }
    for name, values in memberships.items():
        connection.execute(inserts[name], values)


def membership_count(
    connection: psycopg.Connection,
    table: str,
    where: str = "TRUE",
    params: tuple[object, ...] = (),
) -> int:
    """Count rows in one ``mtmf`` table with an optional predicate."""
    row = connection.execute(
        psycopg.sql.SQL("SELECT count(*) FROM mtmf.{} WHERE ").format(psycopg.sql.Identifier(table))
        + psycopg.sql.SQL(where),
        params,
    ).fetchone()
    return int(row[0])


def remove_membership(
    connection: psycopg.Connection,
    initiating_kind: str,
    first_id: str,
    second_id: str,
    actor: str | None = None,
) -> bool:
    """Call the sanctioned removal function for one typed membership.

    ``first_id``/``second_id`` are the two participants: for a tenant
    membership ``(participant, tenant)``; for a leaf membership the exact
    ``(first_entity, second_entity)`` pair. Leaf functions derive the Tenant
    themselves and take no caller Tenant.
    """
    function = REMOVAL_FUNCTIONS[initiating_kind]
    row = connection.execute(
        psycopg.sql.SQL("SELECT {}(%s, %s, %s)").format(psycopg.sql.SQL(function)),
        (first_id, second_id, actor),
    ).fetchone()
    return bool(row[0])


def remove_identity_group_membership(
    connection: psycopg.Connection, identity: str, group: str, actor: str | None = None
) -> bool:
    """Remove exactly one IdentityGroupMembership (leaf, no cascade)."""
    return remove_membership(connection, "identity_group_membership", identity, group, actor=actor)


def remove_identity_org_membership(
    connection: psycopg.Connection,
    identity: str,
    organization: str,
    actor: str | None = None,
) -> bool:
    """Remove exactly one IdentityOrgMembership (leaf, no cascade)."""
    return remove_membership(
        connection, "identity_org_membership", identity, organization, actor=actor
    )


def remove_group_org_membership(
    connection: psycopg.Connection, group: str, organization: str, actor: str | None = None
) -> bool:
    """Remove exactly one GroupOrgMembership (leaf, no cascade)."""
    return remove_membership(connection, "group_org_membership", group, organization, actor=actor)


def audit_rows(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    """Return all membership-removal audit rows in insertion (id) order."""
    return list(
        connection.execute(
            "SELECT id, occurred_at, initiating_kind, tenant_id, principal_id, "
            "identity_id, group_id, organization_id, actor_identity_id, "
            "principal_tenant_count, identity_tenant_count, group_tenant_count, "
            "identity_group_count, identity_org_count, group_org_count "
            "FROM mtmf.membership_removal_audit ORDER BY occurred_at, id"
        ).fetchall()
    )


def seed_full_membership_graph(connection: psycopg.Connection) -> None:
    """Seed the canonical two-Tenant entity graph with every membership.

    Tenant A: P/IA/ORG_A/GROUP_A; Tenant B: P/IB/ORG_B/GROUP_B. Both
    Tenant memberships exist for the Principal, and each Identity, Org,
    Group, and cross relationship is complete in its own Tenant.
    """
    seed_base_entities(connection)
    insert_memberships(
        connection,
        principal_tenant=(PRINCIPAL, TENANT_A),
        identity_tenant=(IDENTITY_A, TENANT_A),
        identity_org=(IDENTITY_A, ORG_A),
        group_tenant=(GROUP_A, TENANT_A),
        identity_group=(IDENTITY_A, GROUP_A),
        group_org=(GROUP_A, ORG_A),
    )
    insert_memberships(
        connection,
        principal_tenant=(PRINCIPAL, TENANT_B),
        identity_tenant=(IDENTITY_B, TENANT_B),
        identity_org=(IDENTITY_B, ORG_B),
        group_tenant=(GROUP_B, TENANT_B),
        identity_group=(IDENTITY_B, GROUP_B),
        group_org=(GROUP_B, ORG_B),
    )
    connection.commit()


def upgrade_to_revision(config: object, revision: str) -> None:
    """Run packaged Alembic migrations to an explicit revision (test-only).

    The production contract only supports ``upgrade_to_head``; this helper
    lets the migration test build a populated revision-``0001`` database and
    then verify an in-place upgrade to head.
    """
    from alembic import command
    from alembic.config import Config

    from mtmf_core.persistence.postgres.resources import migrations_script_directory

    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_script_directory()))
    cfg.attributes["mtmf_url"] = config.sqlalchemy_url  # type: ignore[attr-defined]
    command.upgrade(cfg, revision)
