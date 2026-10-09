"""Idempotent MTMF PostgreSQL role provisioning (administrator-invoked).

MTMF separates three cluster-wide login/ownership roles:

- ``mtmf_owner`` — ``NOLOGIN``; owns the ``mtmf`` schema and every MTMF
  object. It is only ever assumed through a controlled ``SET ROLE``.
- ``mtmf_migrator`` — deployment-only ``LOGIN`` with membership in
  ``mtmf_owner`` that permits ``SET ROLE`` but does **not** inherit owner
  privileges automatically (PostgreSQL ``INHERIT FALSE`` / ``SET TRUE``).
- ``mtmf_runtime`` — restricted application ``LOGIN`` with no ownership
  and no membership in the owner or migrator roles.

Role creation is a cluster-level administrator operation and is
deliberately **outside** Alembic: a deployment runs
:func:`provision_roles` (repeatably) before migrating. The functions here
never drop roles and never touch a non-MTMF role.

``adopt_existing_schema`` is the administrator-approved one-time
ownership handoff for a database whose ``mtmf`` objects predate this
model (for example, objects created by a single trusted migration login).
It is an explicit operator action, never part of a normal runtime path.

All SQL is composed with :mod:`psycopg.sql` identifiers and literals,
which are safely quoted by the driver; no caller-controlled value is ever
interpolated as SQL text. Statements are built by small helpers so the
composition is reviewable and testable.
"""

from __future__ import annotations

import psycopg
from psycopg import sql

SCHEMA = "mtmf"
OWNER_ROLE = "mtmf_owner"
MIGRATOR_ROLE = "mtmf_migrator"
RUNTIME_ROLE = "mtmf_runtime"

_LOGIN_ATTRIBUTES = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"


def _role_exists(connection: psycopg.Connection, role: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (role,)
    ).fetchone()
    return row is not None


def _create_role_statement(role: str, *, can_login: bool) -> sql.Composed:
    login = sql.SQL("LOGIN" if can_login else "NOLOGIN")
    return sql.SQL(f"CREATE ROLE {{}} {{}} {_LOGIN_ATTRIBUTES}").format(sql.Identifier(role), login)


def _normalize_role_statement(role: str, *, can_login: bool) -> sql.Composed:
    login = sql.SQL("LOGIN" if can_login else "NOLOGIN")
    return sql.SQL(f"ALTER ROLE {{}} WITH {{}} {_LOGIN_ATTRIBUTES}").format(
        sql.Identifier(role), login
    )


def _set_password_statement(role: str, password: str) -> sql.Composed:
    return sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
        sql.Identifier(role), sql.Literal(password)
    )


def _grant_owner_statement() -> sql.Composed:
    return sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET TRUE").format(
        sql.Identifier(OWNER_ROLE), sql.Identifier(MIGRATOR_ROLE)
    )


def _revoke_membership_statement(granted: str, grantee: str) -> sql.Composed:
    return sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(granted), sql.Identifier(grantee))


def _grant_database_statement(privilege: str, database: str, role: str) -> sql.Composed:
    return sql.SQL("GRANT {} ON DATABASE {} TO {}").format(
        sql.SQL(privilege), sql.Identifier(database), sql.Identifier(role)
    )


def _adopt_schema_statement() -> sql.Composed:
    return sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(
        sql.Identifier(SCHEMA), sql.Identifier(OWNER_ROLE)
    )


def _adopt_relation_statement(relation: str, *, sequence: bool) -> sql.Composed:
    verb = sql.SQL("ALTER SEQUENCE" if sequence else "ALTER TABLE")
    return sql.SQL("{} {}.{} OWNER TO {}").format(
        verb, sql.Identifier(SCHEMA), sql.Identifier(relation), sql.Identifier(OWNER_ROLE)
    )


def _adopt_function_statement(signature: str) -> sql.Composed:
    return sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(
        sql.SQL(signature), sql.Identifier(OWNER_ROLE)
    )


def provision_roles(
    connection: psycopg.Connection,
    *,
    migrator_password: str,
    runtime_password: str,
) -> None:
    """Create or normalize the three MTMF roles, idempotently.

    Re-running this function never errors and never escalates rights: it
    creates missing roles, re-asserts restrictive attributes, sets the
    deployment passwords, grants owner membership to the migrator with
    ``INHERIT FALSE`` / ``SET TRUE``, and ensures the runtime role is not
    a member of the owner or migrator roles.
    """
    for role, can_login in (
        (OWNER_ROLE, False),
        (MIGRATOR_ROLE, True),
        (RUNTIME_ROLE, True),
    ):
        if not _role_exists(connection, role):
            _create_role = _create_role_statement(role, can_login=can_login)
            connection.execute(_create_role)
        _normalize_role = _normalize_role_statement(role, can_login=can_login)
        connection.execute(_normalize_role)

    _set_migrator_password = _set_password_statement(MIGRATOR_ROLE, migrator_password)
    connection.execute(_set_migrator_password)
    _set_runtime_password = _set_password_statement(RUNTIME_ROLE, runtime_password)
    connection.execute(_set_runtime_password)

    # The migrator may assume the owner only through an explicit SET ROLE;
    # INHERIT FALSE keeps its own session least-privileged.
    connection.execute(_grant_owner_statement())
    # The runtime role must never hold either elevated membership.
    connection.execute(_revoke_membership_statement(OWNER_ROLE, RUNTIME_ROLE))
    connection.execute(_revoke_membership_statement(MIGRATOR_ROLE, RUNTIME_ROLE))

    # The owner creates the MTMF schema itself, which requires database-level
    # CREATE. This is granted to the owner only; the runtime role gets none.
    # Every MTMF identity also receives an explicit database CONNECT.
    database = connection.execute("SELECT current_database()").fetchone()
    if database is not None:
        name = str(database[0])
        connection.execute(_grant_database_statement("CREATE", name, OWNER_ROLE))
        for role in (OWNER_ROLE, MIGRATOR_ROLE, RUNTIME_ROLE):
            connection.execute(_grant_database_statement("CONNECT", name, role))


def adopt_existing_schema(connection: psycopg.Connection) -> None:
    """Administrator-only ownership handoff for a pre-existing ``mtmf`` schema.

    Transfers the ``mtmf`` schema, its tables/views/sequences, and its
    functions to ``mtmf_owner``. Only objects inside the ``mtmf`` schema
    are touched; no other schema, role, or database is modified. Running
    this when objects already belong to the owner is a harmless no-op.
    """
    schema_exists = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = %s", (SCHEMA,)
    ).fetchone()
    if schema_exists is None:
        return
    connection.execute(_adopt_schema_statement())
    relations = connection.execute(
        "SELECT c.relname, c.relkind FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relkind IN ('r', 'p', 'v', 'm', 'S')",
        (SCHEMA,),
    ).fetchall()
    for name, kind in relations:
        relation = _adopt_relation_statement(str(name), sequence=kind == "S")
        connection.execute(relation)
    functions = connection.execute(
        "SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s",
        (SCHEMA,),
    ).fetchall()
    for (signature,) in functions:
        function = _adopt_function_statement(str(signature))
        connection.execute(function)
