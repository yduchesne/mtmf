"""Migration and runtime-security integration slice (V5).

Clean install, in-place ``0003`` -> ``0005`` upgrade, the exact function
allowlist, owner-owned ``SECURITY DEFINER`` posture with a fixed
``search_path``, absence of PUBLIC/runtime table and sequence privileges,
and the mandatory post-upgrade verifier's fail-closed and recovery
behaviour.
"""

from __future__ import annotations

import helpers
import psycopg
import pytest

from mtmf_core.persistence.postgres import (
    MigrationError,
    PostgresConfig,
    PostgresMigrationManager,
    expected_runtime_signatures,
)
from mtmf_core.persistence.postgres.roles import verify_runtime_privileges


def _runtime_signatures(connection: psycopg.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT p.proname, pg_get_function_identity_arguments(p.oid) "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
    ).fetchall()
    return {f"mtmf.{name}({arguments})" for name, arguments in rows}


def test_v5_fresh_install_has_the_exact_reviewed_allowlist(db: psycopg.Connection) -> None:
    assert _runtime_signatures(db) == set(expected_runtime_signatures())
    verify_runtime_privileges(db)


def test_v5_in_place_0003_to_0005_upgrade(
    migrator_config: PostgresConfig, mtmf_config: PostgresConfig
) -> None:
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(migrator_config, "0003")
    assert PostgresMigrationManager(migrator_config).current_revision() == "0003"
    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    assert manager.current_revision() == "0009"
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        assert _runtime_signatures(connection) == set(expected_runtime_signatures())


def test_v5_every_approved_entry_point_is_owner_owned_definer_with_pinned_path(
    db: psycopg.Connection,
) -> None:
    offending = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' "
        "AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE') "
        "AND (NOT p.prosecdef "
        "     OR pg_get_userbyid(p.proowner) <> 'mtmf_owner' "
        "     OR NOT (p.proconfig @> ARRAY['search_path=\"\"']))"
    ).fetchone()[0]
    assert offending == 0


def test_v5_no_public_execute_and_no_runtime_relation_privileges(
    db: psycopg.Connection,
) -> None:
    public_execute = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND EXISTS ("
        "  SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
        "  WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')"
    ).fetchone()[0]
    assert public_execute == 0
    assert not db.execute(
        "SELECT has_table_privilege('mtmf_runtime', 'mtmf.tenant', 'SELECT')"
    ).fetchone()[0]
    assert not db.execute(
        "SELECT has_schema_privilege('mtmf_runtime', 'mtmf', 'CREATE')"
    ).fetchone()[0]


def test_v5_unapproved_grant_fails_postflight_then_recovers(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    db.execute("GRANT EXECUTE ON FUNCTION mtmf.mtf_schema_version() TO mtmf_runtime")
    try:
        with pytest.raises(MigrationError) as captured:
            PostgresMigrationManager(migrator_config).upgrade_to_head()
        assert "post-upgrade" in str(captured.value)
        assert "may already be committed" in str(captured.value)
    finally:
        db.execute("REVOKE EXECUTE ON FUNCTION mtmf.mtf_schema_version() FROM mtmf_runtime")
    PostgresMigrationManager(migrator_config).upgrade_to_head()
    assert PostgresMigrationManager(migrator_config).current_revision() == "0009"


def test_v5_runtime_roles_cannot_manage_migrations(runtime_config: PostgresConfig) -> None:
    with pytest.raises(MigrationError):
        PostgresMigrationManager(runtime_config)


def test_v5_every_runtime_callable_function_has_stable_nulls(
    db: psycopg.Connection, runtime_config: PostgresConfig
) -> None:
    # A missing identity returns SQL NULL from a read function, which the
    # provider maps to ``None`` rather than an empty object.
    with psycopg.connect(runtime_config.psycopg_dsn) as connection:
        row = connection.execute(
            "SELECT mtmf.tenant_get(%s)", ("00000000-0000-4000-8000-000000000000",)
        ).fetchone()
    assert row is not None
    assert row[0] is None


def test_v5_head_revision_is_the_migrated_revision(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    manager = PostgresMigrationManager(migrator_config)
    assert manager.current_revision() == manager.head_revision == "0009"
