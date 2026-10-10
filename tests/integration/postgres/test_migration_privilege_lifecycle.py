"""Migration privilege lifecycle tests (PR 7A-2, I01..I14).

Proves that a successful ``PostgresMigrationManager.upgrade_to_head()``
cannot return without the mandatory post-upgrade effective-privilege
verifier passing, including already-head no-op upgrades, and that the
provisioning/adoption lifecycle remains usable before head.

The lifecycle tests exercise real PostgreSQL 18 identities. Where a case
duplicates an existing PR 7A-1 test that proves the same contract (for
example credential-label confusion I07, covered by A1-12/A1-13), the
existing test is referenced rather than duplicated.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import helpers
import psycopg
import psycopg.sql as sql
import pytest

from mtmf_core.persistence.postgres import (
    MigrationError,
    PostgresConfig,
    PostgresMigrationManager,
)
from mtmf_core.persistence.postgres import roles as pg_roles

REPO_ROOT = Path(__file__).resolve().parents[3]
_CLI = REPO_ROOT / "scripts" / "mtmf-provision-roles.py"


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_CLI), *arguments],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )


def _temporary_role(connection: psycopg.Connection, prefix: str) -> str:
    name = f"{prefix}_{uuid.uuid4().hex[:10]}"
    connection.execute(
        sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS").format(
            sql.Identifier(name)
        )
    )
    return name


# --- I01/I02: fresh and already-head lifecycle -------------------------------


def test_i01_fresh_migration_runs_mandatory_verifier(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    assert manager.current_revision() == "0008"
    pg_roles.verify_runtime_privileges(db)
    assert not db.execute(
        "SELECT has_table_privilege('mtmf_runtime', 'mtmf.tenant', 'SELECT')"
    ).fetchone()[0]


def test_i02_already_head_rerun_reverifies_without_drift(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    before = helpers.privilege_snapshot(db)
    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    manager.upgrade_to_head()
    assert manager.current_revision() == "0008"
    assert helpers.privilege_snapshot(db) == before


# --- I03/I04/I05/I06: contaminated already-head state and recovery -----------


def test_i03_contaminated_table_grant_fails_noop_migration(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    db.execute("GRANT SELECT ON mtmf.tenant TO mtmf_runtime")
    try:
        with pytest.raises(MigrationError) as excinfo:
            PostgresMigrationManager(migrator_config).upgrade_to_head()
        message = str(excinfo.value)
        assert "mtmf.tenant" in message and "SELECT" in message
        assert "post-upgrade" in message
        assert "may already be committed" in message
        # Alembic history is unchanged and untouched; no rollback is claimed.
        assert db.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()[0] == "0008"
    finally:
        db.execute("REVOKE SELECT ON mtmf.tenant FROM mtmf_runtime")


def test_i04_recovery_after_remediation_succeeds(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    db.execute("GRANT SELECT ON mtmf.tenant TO mtmf_runtime")
    try:
        with pytest.raises(MigrationError):
            PostgresMigrationManager(migrator_config).upgrade_to_head()
    finally:
        db.execute("REVOKE SELECT ON mtmf.tenant FROM mtmf_runtime")
    PostgresMigrationManager(migrator_config).upgrade_to_head()
    assert db.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()[0] == "0008"


def test_i05_unauthorized_function_execute_fails_and_recovers(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    db.execute("GRANT EXECUTE ON FUNCTION mtmf.mtf_schema_version() TO mtmf_runtime")
    try:
        with pytest.raises(MigrationError) as excinfo:
            PostgresMigrationManager(migrator_config).upgrade_to_head()
        assert "mtmf.mtf_schema_version()" in str(excinfo.value)
    finally:
        db.execute("REVOKE EXECUTE ON FUNCTION mtmf.mtf_schema_version() FROM mtmf_runtime")
    PostgresMigrationManager(migrator_config).upgrade_to_head()


def test_i06_hostile_runtime_membership_fails_and_recovers(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    role = _temporary_role(db, "mtmf_pr7a2_hostile")
    db.execute(sql.SQL("GRANT {} TO mtmf_runtime").format(sql.Identifier(role)))
    try:
        with pytest.raises(MigrationError) as excinfo:
            PostgresMigrationManager(migrator_config).upgrade_to_head()
        assert role in str(excinfo.value)
    finally:
        db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(role)))
        db.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    PostgresMigrationManager(migrator_config).upgrade_to_head()


# --- I08: legacy adoption then head migration --------------------------------


def test_i08_legacy_adoption_then_upgrade_preserves_data(
    db: psycopg.Connection, migrator_config: PostgresConfig, dsn: str
) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(migrator_config, "0002")
    with psycopg.connect(dsn, autocommit=True) as connection:
        helpers.seed_full_membership_graph(connection)
        assert helpers.remove_membership(
            connection, "identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_A
        )
        before_memberships = {
            table: helpers.membership_count(connection, table)
            for table in helpers.MEMBERSHIP_TABLES
        }
        before_audit = helpers.audit_rows(connection)

    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("ALTER SCHEMA mtmf OWNER TO mtmf")
        connection.execute("ALTER TABLE mtmf.tenant OWNER TO mtmf")
    with pytest.raises(MigrationError):
        PostgresMigrationManager(migrator_config).upgrade_to_head()
    with psycopg.connect(dsn, autocommit=True) as connection:
        pg_roles.adopt_existing_schema(connection)
    PostgresMigrationManager(migrator_config).upgrade_to_head()

    assert {
        table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES
    } == before_memberships
    assert helpers.audit_rows(db) == before_audit
    pg_roles.verify_runtime_privileges(db)


# --- I09: adoption ownership postcondition -----------------------------------


def test_i09_ownership_postcondition_detects_non_owner_object(db: psycopg.Connection) -> None:
    db.execute("CREATE TABLE mtmf.pr7a2_intruder (id int)")
    try:
        offenders = pg_roles.find_non_owner_objects(db)
        assert offenders is not None and "pr7a2_intruder" in offenders
        with pytest.raises(pg_roles.RoleProvisioningError) as excinfo:
            pg_roles._verify_schema_ownership(db)
        assert "pr7a2_intruder" in str(excinfo.value)
    finally:
        db.execute("DROP TABLE IF EXISTS mtmf.pr7a2_intruder")


# --- I10/I11: CLI --verify read-only diagnostic ------------------------------


def test_i10_cli_verify_is_read_only_on_healthy_head(
    db: psycopg.Connection,
) -> None:
    before = helpers.privilege_snapshot(db)
    result = _run_cli("--verify")
    assert result.returncode == 0, result.stderr
    assert "verified runtime privileges" in result.stdout
    after = helpers.privilege_snapshot(db)
    assert after == before


def test_i11_cli_verify_fails_before_schema(
    db: psycopg.Connection, migrator_config: PostgresConfig, dsn: str
) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
    try:
        result = _run_cli("--verify")
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "does not exist" in combined
        # It must not auto-provision or migrate.
        assert pg_roles.find_non_owner_objects(db) is None
        with psycopg.connect(dsn) as connection:
            assert (
                connection.execute(
                    "SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'mtmf'"
                ).fetchone()[0]
                == 0
            )
    finally:
        PostgresMigrationManager(migrator_config).upgrade_to_head()


# --- I13/I14: provisioning lifecycle -----------------------------------------


def test_i13_provisioning_works_without_schema(
    db: psycopg.Connection,
    migrator_config: PostgresConfig,
    runtime_config: PostgresConfig,
    dsn: str,
) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
    try:
        pg_roles.provision_roles(
            db,
            migrator_password=migrator_config.password,
            runtime_password=runtime_config.password,
        )
        pg_roles.verify_role_topology(db)
        # The migrator can still bootstrap the schema afterwards.
        PostgresMigrationManager(migrator_config).upgrade_to_head()
    finally:
        PostgresMigrationManager(migrator_config).upgrade_to_head()


def test_i14_repeated_provision_and_adopt_is_idempotent(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    before = helpers.privilege_snapshot(db)
    for _ in range(2):
        pg_roles.provision_roles(
            db,
            migrator_password=migrator_config.password,
            runtime_password=runtime_config.password,
        )
        pg_roles.adopt_existing_schema(db)
    assert helpers.privilege_snapshot(db) == before
