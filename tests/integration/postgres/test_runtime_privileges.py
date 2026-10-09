"""Real-role runtime privilege tests (PRIV-01..PRIV-20).

Every action described as "runtime" runs on a fresh connection
authenticated as the actual ``mtmf_runtime`` login; all verification
reads use the administrator connection. No test simulates the runtime
role with ``SET ROLE`` from an owner or superuser session, and the
runtime fixture fails setup if the connected identity is elevated.

These tests assert *effective* privileges (``has_*_privilege`` and actual
SQL behavior), not merely the absence of ACL text. PRIV-14 is a
boundary-disclosure test: it shows that the audit ``actor_identity_id``
is an unverified caller assertion, **not** authentication, Tenant
authorization, or proof that the caller was authorized by MTMF.
"""

from __future__ import annotations

import threading
import uuid

import helpers
import psycopg
import psycopg.errors
import psycopg.sql
import pytest

from mtmf_core.persistence.postgres import MigrationError, PostgresMigrationManager
from mtmf_core.persistence.postgres.roles import adopt_existing_schema

_AUDIT_ACTOR_INDEX = 8
_AUDIT_KIND_INDEX = 2
_AUDIT_COUNT_INDEX = {
    "principal_tenant_membership": 9,
    "identity_tenant_membership": 10,
    "group_tenant_membership": 11,
    "identity_group_membership": 12,
    "identity_org_membership": 13,
    "group_org_membership": 14,
}

_TENANT_REMOVALS = (
    ("identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A),
    ("group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A),
    ("principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A),
)
_LEAF_REMOVALS = (
    ("identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_A),
    ("identity_org_membership", helpers.IDENTITY_A, helpers.ORG_A),
    ("group_org_membership", helpers.GROUP_A, helpers.ORG_A),
)
_REMOVALS = _TENANT_REMOVALS + _LEAF_REMOVALS

_EXPECTED_COUNTS = {
    "identity_tenant_membership": {
        "identity_tenant_membership": 1,
        "identity_group_membership": 1,
        "identity_org_membership": 1,
    },
    "group_tenant_membership": {
        "group_tenant_membership": 1,
        "identity_group_membership": 1,
        "group_org_membership": 1,
    },
    "principal_tenant_membership": {
        "principal_tenant_membership": 1,
        "identity_tenant_membership": 1,
        "identity_group_membership": 1,
        "identity_org_membership": 1,
    },
    "identity_group_membership": {"identity_group_membership": 1},
    "identity_org_membership": {"identity_org_membership": 1},
    "group_org_membership": {"group_org_membership": 1},
}


def _table(identifier: str) -> psycopg.sql.Identifier:
    return psycopg.sql.Identifier(identifier)


def _membership_snapshot(connection: psycopg.Connection) -> dict[str, int]:
    return {
        table: helpers.membership_count(connection, table) for table in helpers.MEMBERSHIP_TABLES
    }


def _audit_counts(row: tuple[object, ...]) -> dict[str, int]:
    return {name: int(row[index]) for name, index in _AUDIT_COUNT_INDEX.items()}


# --- PRIV-01 / PRIV-02: direct DML is denied --------------------------------


@pytest.mark.parametrize("table", sorted(helpers.MEMBERSHIP_TABLES))
def test_priv01_runtime_cannot_mutate_membership_tables(
    db: psycopg.Connection, runtime_connection: psycopg.Connection, table: str
) -> None:
    helpers.seed_full_membership_graph(db)
    before = _membership_snapshot(db)
    column = helpers.INITIATOR_PARTICIPANT_COLUMN[table]
    statements = (
        (
            psycopg.sql.SQL("INSERT INTO mtmf.{} VALUES (%s, %s)").format(_table(table)),
            (helpers.new_id(), helpers.new_id()),
        ),
        (
            psycopg.sql.SQL("UPDATE mtmf.{} SET {} = {}").format(
                _table(table),
                psycopg.sql.Identifier(column),
                psycopg.sql.Identifier(column),
            ),
            None,
        ),
        (
            psycopg.sql.SQL("DELETE FROM mtmf.{}").format(_table(table)),
            None,
        ),
        (
            psycopg.sql.SQL("TRUNCATE mtmf.{}").format(_table(table)),
            None,
        ),
    )
    for statement, parameters in statements:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement, parameters)
        runtime_connection.rollback()
    assert _membership_snapshot(db) == before


def test_priv02_runtime_cannot_mutate_audit(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    assert helpers.remove_membership(
        db, "identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_A
    )
    before = len(helpers.audit_rows(db))
    statements = (
        (
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, identity_group_count) "
            "VALUES ('identity_group_membership', %s, 1)",
            (helpers.TENANT_A,),
        ),
        (
            "UPDATE mtmf.membership_removal_audit SET actor_identity_id = actor_identity_id",
            None,
        ),
        ("DELETE FROM mtmf.membership_removal_audit", None),
        ("TRUNCATE mtmf.membership_removal_audit", None),
    )
    for statement, parameters in statements:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement, parameters)
        runtime_connection.rollback()
    assert len(helpers.audit_rows(db)) == before


# --- PRIV-03: approved removals work with exact audit -----------------------


@pytest.mark.parametrize(("kind", "first_id", "second_id"), _REMOVALS)
def test_priv03_approved_removal_succeeds_with_one_audit(
    db: psycopg.Connection,
    runtime_connection: psycopg.Connection,
    kind: str,
    first_id: str,
    second_id: str,
) -> None:
    helpers.seed_full_membership_graph(db)
    assert helpers.remove_membership(runtime_connection, kind, first_id, second_id) is True
    runtime_connection.commit()

    rows = helpers.audit_rows(db)
    assert len(rows) == 1
    row = rows[0]
    assert row[_AUDIT_KIND_INDEX] == kind
    nonzero = {name: count for name, count in _audit_counts(row).items() if count}
    assert nonzero == _EXPECTED_COUNTS[kind]


def test_priv03b_runtime_default_argument_resolves_to_granted_signature(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    # The granted signature is the three-argument form. A two-argument
    # invocation uses the declared ``actor_identity_id_value DEFAULT NULL``
    # and must resolve to that same granted signature.
    helpers.seed_full_membership_graph(db)
    result = runtime_connection.execute(
        "SELECT mtmf.remove_identity_group_membership(%s, %s)",
        (helpers.IDENTITY_A, helpers.GROUP_A),
    ).fetchone()[0]
    runtime_connection.commit()
    assert result is True
    assert len(helpers.audit_rows(db)) == 1


# --- PRIV-04: internal helpers are not runtime-executable -------------------


@pytest.mark.parametrize(
    ("statement", "parameters"),
    (
        ("SELECT mtmf.membership_delete_guard()", None),
        ("SELECT mtmf.guard_membership_removal_audit()", None),
        ("SELECT mtmf.block_membership_updates()", None),
        (
            "SELECT mtmf.identity_tenant_membership_precondition(%s, %s)",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        ),
        (
            "SELECT mtmf.group_org_membership_precondition(%s, %s)",
            (helpers.GROUP_A, helpers.ORG_A),
        ),
    ),
)
def test_priv04_internal_helpers_are_denied(
    runtime_connection: psycopg.Connection, statement: str, parameters: object
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(statement, parameters)
    runtime_connection.rollback()


# --- PRIV-05 / PRIV-20: DDL and escalation are denied -----------------------


@pytest.mark.parametrize(
    ("statement", "parameters"),
    (
        ("SELECT mtmf.mtf_schema_version()", None),
        ("CREATE TABLE mtmf.pr7a_evil (x int)", None),
        ("CREATE FUNCTION mtmf.pr7a_evil_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'", None),
        ("ALTER TABLE mtmf.tenant ADD COLUMN pr7a_evil int", None),
        ("ALTER TABLE mtmf.identity DISABLE TRIGGER ALL", None),
        ("DROP TABLE mtmf.tenant", None),
        (
            "ALTER FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid) "
            "SECURITY INVOKER",
            None,
        ),
        ("GRANT EXECUTE ON FUNCTION mtmf.mtf_schema_version() TO mtmf_runtime", None),
        (
            "INSERT INTO mtmf.membership_removal_audit "
            "(initiating_kind, tenant_id, identity_group_count) "
            "VALUES ('identity_group_membership', %s, 1)",
            (helpers.TENANT_A,),
        ),
    ),
)
def test_priv05_ddl_and_escalation_are_denied(
    runtime_connection: psycopg.Connection, statement: str, parameters: object
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(statement, parameters)
    runtime_connection.rollback()


# --- PRIV-06: a forged transaction marker does not bypass privileges --------


def test_priv06_forged_marker_cannot_bypass_privileges(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    before = _membership_snapshot(db)
    runtime_connection.execute("SELECT set_config('mtmf.membership_removal', 'on', true)")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("DELETE FROM mtmf.identity_group_membership")
    runtime_connection.rollback()
    assert _membership_snapshot(db) == before
    assert helpers.audit_rows(db) == []


# --- PRIV-07: runtime cannot assume owner or migrator -----------------------


@pytest.mark.parametrize("role", ("mtmf_owner", "mtmf_migrator"))
def test_priv07_runtime_cannot_set_role(runtime_connection: psycopg.Connection, role: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            psycopg.sql.SQL("SET ROLE {}").format(psycopg.sql.Identifier(role))
        )
    runtime_connection.rollback()


# --- PRIV-08: migration state and triggers are inaccessible -----------------


@pytest.mark.parametrize(
    "statement",
    (
        "SELECT version_num FROM mtmf.alembic_version",
        "UPDATE mtmf.alembic_version SET version_num = version_num",
        "ALTER TABLE mtmf.identity DISABLE TRIGGER ALL",
    ),
)
def test_priv08_runtime_cannot_touch_migration_or_triggers(
    runtime_connection: psycopg.Connection, statement: str
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(statement)
    runtime_connection.rollback()


# --- PRIV-09 / PRIV-18: new owner functions stay default-deny ---------------


def test_priv09_and_priv18_new_owner_function_is_default_deny(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    db.execute("SET ROLE mtmf_owner")
    try:
        db.execute(
            "CREATE OR REPLACE FUNCTION mtmf.pr7a_probe_fn() RETURNS int "
            "LANGUAGE sql IMMUTABLE SET search_path = '' AS $$ SELECT 7 $$"
        )
        public_executable = db.execute(
            "SELECT EXISTS ("
            "  SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
            "  WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'mtmf' AND p.proname = 'pr7a_probe_fn'"
        ).fetchone()[0]
    finally:
        db.execute("RESET ROLE")
    try:
        assert public_executable is False
        assert (
            db.execute(
                "SELECT has_function_privilege('mtmf_runtime', 'mtmf.pr7a_probe_fn()', 'EXECUTE')"
            ).fetchone()[0]
            is False
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute("SELECT mtmf.pr7a_probe_fn()")
        runtime_connection.rollback()

        db.execute("GRANT EXECUTE ON FUNCTION mtmf.pr7a_probe_fn() TO mtmf_runtime")
        assert runtime_connection.execute("SELECT mtmf.pr7a_probe_fn()").fetchone()[0] == 7
        runtime_connection.rollback()
    finally:
        db.execute("DROP FUNCTION IF EXISTS mtmf.pr7a_probe_fn()")


# --- PRIV-10: a failing audit insert rolls the removal back -----------------


def test_priv18_owner_default_privileges_are_default_deny(db: psycopg.Connection) -> None:
    # The owner's default privilege for future functions must not include
    # PUBLIC EXECUTE, so a newly created function is default-deny until an
    # explicit migration grants it.
    public_defaults = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_default_acl d "
        "JOIN pg_catalog.pg_roles r ON r.oid = d.defaclrole "
        "CROSS JOIN LATERAL aclexplode(d.defaclacl) AS a "
        "WHERE r.rolname = 'mtmf_owner' AND d.defaclobjtype = 'f' "
        "AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'"
    ).fetchone()[0]
    assert public_defaults == 0


def test_priv10_runtime_audit_failure_rolls_back_removal(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    before = _membership_snapshot(db)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        runtime_connection.execute(
            "SELECT mtmf.remove_identity_tenant_membership(%s, %s, %s)",
            (helpers.IDENTITY_A, helpers.TENANT_A, helpers.new_id()),
        )
    runtime_connection.rollback()
    assert _membership_snapshot(db) == before
    assert helpers.audit_rows(db) == []


# --- PRIV-11: malformed / cross-Tenant input is a no-op ---------------------


def test_priv11_cross_tenant_and_malformed_inputs_are_noop(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    before = _membership_snapshot(db)
    assert (
        helpers.remove_membership(
            runtime_connection, "group_tenant_membership", helpers.GROUP_A, helpers.TENANT_B
        )
        is False
    )
    runtime_connection.commit()
    assert (
        helpers.remove_membership(
            runtime_connection, "identity_group_membership", helpers.new_id(), helpers.GROUP_A
        )
        is False
    )
    runtime_connection.commit()
    assert _membership_snapshot(db) == before
    assert helpers.audit_rows(db) == []


# --- PRIV-12: concurrent runtime removals serialize -------------------------


def test_priv12_concurrent_runtime_removals_serialize(
    db: psycopg.Connection, runtime_config: object
) -> None:
    helpers.seed_full_membership_graph(db)
    barrier = threading.Barrier(2)
    outcomes: list[bool] = []
    guard = threading.Lock()

    def worker() -> None:
        connection = psycopg.connect(
            runtime_config.psycopg_dsn,  # type: ignore[attr-defined]
            autocommit=True,
        )
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


# --- PRIV-13: table SELECT and sequence use are denied ----------------------


def test_priv13_runtime_cannot_select_tables_or_use_sequences(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    for table in (*helpers.MEMBERSHIP_TABLES, "tenant", "membership_removal_audit"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(
                psycopg.sql.SQL("SELECT count(*) FROM mtmf.{}").format(_table(table))
            )
        runtime_connection.rollback()

    db.execute("SET ROLE mtmf_owner")
    try:
        db.execute("CREATE SEQUENCE mtmf.pr7a_probe_seq")
    finally:
        db.execute("RESET ROLE")
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute("SELECT nextval('mtmf.pr7a_probe_seq')")
        runtime_connection.rollback()
    finally:
        db.execute("DROP SEQUENCE IF EXISTS mtmf.pr7a_probe_seq")


# --- PRIV-14: actor field is an unverified caller assertion -----------------


def test_priv14_actor_is_an_unverified_caller_assertion(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    helpers.seed_full_membership_graph(db)
    # The runtime login is not authenticated as IDENTITY_B, yet the approved
    # function records whatever actor UUID the caller supplies. This is a
    # boundary disclosure: the field is provenance input, never proof of
    # authentication or Tenant authorization (which is application-layer).
    assert helpers.remove_membership(
        runtime_connection,
        "identity_group_membership",
        helpers.IDENTITY_A,
        helpers.GROUP_A,
        actor=helpers.IDENTITY_B,
    )
    runtime_connection.commit()
    row = helpers.audit_rows(db)[0]
    assert str(row[_AUDIT_ACTOR_INDEX]) == helpers.IDENTITY_B


# --- PRIV-15: complete owner/ACL/prosecdef introspection --------------------


def test_priv15_privilege_surface_is_exactly_as_documented(db: psycopg.Connection) -> None:
    assert (
        db.execute(
            "SELECT pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname = 'mtmf'"
        ).fetchone()[0]
        == "mtmf_owner"
    )

    wrong_owners = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'mtmf' AND pg_get_userbyid(c.relowner) <> 'mtmf_owner'"
    ).fetchone()[0]
    assert wrong_owners == 0
    wrong_function_owners = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND pg_get_userbyid(p.proowner) <> 'mtmf_owner'"
    ).fetchone()[0]
    assert wrong_function_owners == 0

    assert not db.execute(
        "SELECT has_schema_privilege('mtmf_runtime', 'mtmf', 'CREATE')"
    ).fetchone()[0]
    assert db.execute("SELECT has_schema_privilege('mtmf_runtime', 'mtmf', 'USAGE')").fetchone()[0]

    runtime_tables = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'mtmf' AND c.relkind IN ('r', 'p') "
        "AND has_table_privilege('mtmf_runtime', c.oid, 'SELECT')"
    ).fetchone()[0]
    assert runtime_tables == 0
    runtime_sequences = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS p(privilege) "
        "WHERE n.nspname = 'mtmf' AND c.relkind = 'S' "
        "AND has_sequence_privilege('mtmf_runtime', c.oid, p.privilege)"
    ).fetchone()[0]
    assert runtime_sequences == 0

    runtime_executable = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
    ).fetchone()[0]
    assert runtime_executable == 6

    definer_functions = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND p.prosecdef"
    ).fetchone()[0]
    assert definer_functions == 6
    # Every definer entry point pins search_path to the empty string.
    unpinned = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND p.prosecdef "
        "AND NOT (p.proconfig @> ARRAY['search_path=\"\"'])"
    ).fetchone()[0]
    assert unpinned == 0


# --- PRIV-16: fresh and populated re-run preserve data and privileges -------


def test_priv16_populated_upgrade_rerun_preserves_data_and_acls(
    db: psycopg.Connection, migrator_config: object
) -> None:
    helpers.seed_full_membership_graph(db)
    assert helpers.remove_membership(
        db, "identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_A
    )
    before_memberships = _membership_snapshot(db)
    before_audit = helpers.audit_rows(db)
    manager = PostgresMigrationManager(migrator_config)  # type: ignore[arg-type]
    assert manager.current_revision() == manager.head_revision
    manager.upgrade_to_head()
    manager.upgrade_to_head()
    assert manager.current_revision() == "0003"
    assert _membership_snapshot(db) == before_memberships
    assert helpers.audit_rows(db) == before_audit
    assert (
        db.execute(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
        ).fetchone()[0]
        == 6
    )


def test_priv16b_legacy_ownership_fails_loudly_then_adopts(mtmf_config: object, dsn: str) -> None:
    # A database whose mtmf schema/objects predate PR 7A are owned by the old
    # login. Revision 0003 must fail with the administrator handoff
    # instruction instead of silently reassigning ownership or producing a
    # raw error.
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(mtmf_config, "0002")
    with psycopg.connect(dsn, autocommit=True) as connection:
        # Simulate legacy ownership: the schema and one object belong to the
        # old trusted login rather than mtmf_owner.
        connection.execute("ALTER SCHEMA mtmf OWNER TO mtmf")
        connection.execute("ALTER TABLE mtmf.tenant OWNER TO mtmf")
    with pytest.raises(MigrationError) as excinfo:
        PostgresMigrationManager(mtmf_config).upgrade_to_head()  # type: ignore[arg-type]
    assert "ownership handoff" in str(excinfo.value)

    with psycopg.connect(dsn, autocommit=True) as connection:
        adopt_existing_schema(connection)
    PostgresMigrationManager(mtmf_config).upgrade_to_head()  # type: ignore[arg-type]
    with psycopg.connect(dsn) as connection:
        revision = connection.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()[0]
        non_owner_objects = connection.execute(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'mtmf' "
            "AND pg_get_userbyid(c.relowner) <> 'mtmf_owner'"
        ).fetchone()[0]
    assert revision == "0003"
    assert non_owner_objects == 0


# --- PRIV-17: runtime configuration cannot manage migrations ----------------


def test_priv17_runtime_config_cannot_manage_migrations(
    runtime_config: object, db: psycopg.Connection
) -> None:
    before = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'mtmf'"
    ).fetchone()[0]
    with pytest.raises(MigrationError):
        PostgresMigrationManager(runtime_config)  # type: ignore[arg-type]
    after = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'mtmf'"
    ).fetchone()[0]
    assert after == before


# --- PRIV-19: an unrelated login is denied the approved function ------------


def test_priv19_non_owner_non_runtime_login_is_denied(
    db: psycopg.Connection, mtmf_config: object, dsn: str
) -> None:
    outsider = f"mtmf_pr7a_outsider_{uuid.uuid4().hex[:10]}"
    password = "mtmf-pr7a-outsider-password"
    db.execute(
        psycopg.sql.SQL(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}"
        ).format(psycopg.sql.Identifier(outsider), psycopg.sql.Literal(password))
    )
    try:
        connection = psycopg.connect(
            host=mtmf_config.host,  # type: ignore[attr-defined]
            port=mtmf_config.port,  # type: ignore[attr-defined]
            dbname=mtmf_config.database,  # type: ignore[attr-defined]
            user=outsider,
            password=password,
        )
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT mtmf.remove_identity_group_membership(%s, %s)",
                    (helpers.IDENTITY_A, helpers.GROUP_A),
                )
            connection.rollback()
        finally:
            connection.close()
    finally:
        db.execute(psycopg.sql.SQL("DROP ROLE {}").format(psycopg.sql.Identifier(outsider)))
