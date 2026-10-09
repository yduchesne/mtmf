"""Role-topology and credential-boundary adversarial tests (PR 7A-1).

These tests exercise the *effective* membership graph and effective
privilege surface on real PostgreSQL 18 logins. A runtime login must not
reach owner/migrator capabilities directly or transitively, and migration
authority must be exercised only by the authenticated ``mtmf_migrator``.

Hostile roles are uniquely named, never own objects, and are removed in a
``finally`` block; the tests never mutate a persistent non-MTMF role.
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Iterator

import helpers
import psycopg
import psycopg.errors
import psycopg.sql as sql
import pytest

from mtmf_core.persistence.postgres import (
    MigrationError,
    PostgresConfig,
    PostgresMigrationManager,
    PostgresRole,
    PrivilegeVerificationError,
    RoleProvisioningError,
)
from mtmf_core.persistence.postgres import roles as pg_roles


@contextlib.contextmanager
def _temporary_role(connection: psycopg.Connection, prefix: str) -> Iterator[str]:
    """Create a uniquely named NOLOGIN test role and always drop it."""
    name = f"{prefix}_{uuid.uuid4().hex[:10]}"
    connection.execute(
        sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS").format(
            sql.Identifier(name)
        )
    )
    try:
        yield name
    finally:
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


def _object_count(connection: psycopg.Connection) -> int:
    return int(
        connection.execute(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'mtmf'"
        ).fetchone()[0]
    )


# --- A1-01 / A1-16: healthy topology and privilege surface ------------------


def test_a1_01_repeated_provisioning_is_idempotent(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    for _ in range(2):
        pg_roles.provision_roles(
            db,
            migrator_password=migrator_config.password,
            runtime_password=runtime_config.password,
        )
        pg_roles.verify_role_topology(db)
    attributes = {
        row[0]: row[1:]
        for row in db.execute(
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, "
            "       rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN ('mtmf_owner', 'mtmf_migrator', 'mtmf_runtime')"
        ).fetchall()
    }
    assert attributes["mtmf_owner"] == (False, False, False, False, False)
    assert attributes["mtmf_migrator"] == (False, False, False, True, False)
    assert attributes["mtmf_runtime"] == (False, False, False, True, False)


def test_a1_16_runtime_effective_privilege_inventory(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    pg_roles.verify_runtime_privileges(db)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT count(*) FROM mtmf.tenant")
    runtime_connection.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT mtmf.mtf_schema_version()")
    runtime_connection.rollback()


# --- A1-02..A1-05: runtime membership contamination -------------------------


def test_a1_02_runtime_direct_owner_membership_is_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    db.execute("GRANT mtmf_owner TO mtmf_runtime WITH INHERIT FALSE, SET TRUE")
    try:
        assert db.execute("SELECT pg_has_role('mtmf_runtime', 'mtmf_owner', 'SET')").fetchone()[0]
        with pytest.raises(RoleProvisioningError) as excinfo:
            pg_roles.provision_roles(
                db,
                migrator_password=migrator_config.password,
                runtime_password=runtime_config.password,
            )
        assert "mtmf_runtime is a member of mtmf_owner" in str(excinfo.value)
    finally:
        db.execute("REVOKE mtmf_owner FROM mtmf_runtime")


def test_a1_03_runtime_transitive_owner_set_path_is_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    with _temporary_role(db, "mtmf_pr7a1_intermediate") as intermediate:
        db.execute(
            sql.SQL("GRANT mtmf_owner TO {} WITH INHERIT FALSE, SET TRUE").format(
                sql.Identifier(intermediate)
            )
        )
        db.execute(
            sql.SQL("GRANT {} TO mtmf_runtime WITH INHERIT FALSE, SET TRUE").format(
                sql.Identifier(intermediate)
            )
        )
        assert db.execute("SELECT pg_has_role('mtmf_runtime', 'mtmf_owner', 'SET')").fetchone()[0]
        with pytest.raises(RoleProvisioningError) as excinfo:
            pg_roles.provision_roles(
                db,
                migrator_password=migrator_config.password,
                runtime_password=runtime_config.password,
            )
        assert intermediate in str(excinfo.value)
        db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(intermediate)))


def test_a1_04_runtime_transitive_owner_inherit_path_is_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    with _temporary_role(db, "mtmf_pr7a1_inherited") as intermediate:
        db.execute(
            sql.SQL("GRANT mtmf_owner TO {} WITH INHERIT TRUE, SET TRUE").format(
                sql.Identifier(intermediate)
            )
        )
        db.execute(
            sql.SQL("GRANT {} TO mtmf_runtime WITH INHERIT TRUE").format(
                sql.Identifier(intermediate)
            )
        )
        assert db.execute("SELECT pg_has_role('mtmf_runtime', 'mtmf_owner', 'USAGE')").fetchone()[0]
        with pytest.raises(RoleProvisioningError):
            pg_roles.provision_roles(
                db,
                migrator_password=migrator_config.password,
                runtime_password=runtime_config.password,
            )
        db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(intermediate)))


def test_a1_05_runtime_membership_in_unrelated_role_is_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    with _temporary_role(db, "mtmf_pr7a1_unrelated") as unrelated:
        db.execute(sql.SQL("GRANT {} TO mtmf_runtime").format(sql.Identifier(unrelated)))
        with pytest.raises(RoleProvisioningError) as excinfo:
            pg_roles.provision_roles(
                db,
                migrator_password=migrator_config.password,
                runtime_password=runtime_config.password,
            )
        assert "mtmf_runtime is a member of" in str(excinfo.value)
        db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(unrelated)))


# --- A1-06 / A1-07: third-party grants confer MTMF privileges ---------------


def test_a1_06_third_party_table_grant_is_detected(db: psycopg.Connection) -> None:
    with _temporary_role(db, "mtmf_pr7a1_table_grantor") as grantor:
        db.execute(sql.SQL("GRANT SELECT ON mtmf.tenant TO {}").format(sql.Identifier(grantor)))
        db.execute(sql.SQL("GRANT {} TO mtmf_runtime").format(sql.Identifier(grantor)))
        try:
            assert db.execute(
                "SELECT has_table_privilege('mtmf_runtime', 'mtmf.tenant', 'SELECT')"
            ).fetchone()[0]
            with pytest.raises(PrivilegeVerificationError) as excinfo:
                pg_roles.verify_runtime_privileges(db)
            message = str(excinfo.value)
            assert "mtmf.tenant" in message and "SELECT" in message
        finally:
            db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(grantor)))
            db.execute(
                sql.SQL("REVOKE SELECT ON mtmf.tenant FROM {}").format(sql.Identifier(grantor))
            )


def test_a1_07_third_party_function_grant_is_detected(db: psycopg.Connection) -> None:
    with _temporary_role(db, "mtmf_pr7a1_function_grantor") as grantor:
        db.execute(
            sql.SQL("GRANT EXECUTE ON FUNCTION mtmf.mtf_schema_version() TO {}").format(
                sql.Identifier(grantor)
            )
        )
        db.execute(sql.SQL("GRANT {} TO mtmf_runtime").format(sql.Identifier(grantor)))
        try:
            assert db.execute(
                "SELECT has_function_privilege("
                "'mtmf_runtime', 'mtmf.mtf_schema_version()', 'EXECUTE')"
            ).fetchone()[0]
            with pytest.raises(PrivilegeVerificationError) as excinfo:
                pg_roles.verify_runtime_privileges(db)
            assert "mtmf.mtf_schema_version()" in str(excinfo.value)
        finally:
            db.execute(sql.SQL("REVOKE {} FROM mtmf_runtime").format(sql.Identifier(grantor)))
            db.execute(
                sql.SQL("REVOKE EXECUTE ON FUNCTION mtmf.mtf_schema_version() FROM {}").format(
                    sql.Identifier(grantor)
                )
            )


# --- A1-08..A1-11: migrator topology and authenticated identity -------------


def test_a1_08_migrator_extra_membership_is_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    with _temporary_role(db, "mtmf_pr7a1_migrator_extra") as unrelated:
        db.execute(sql.SQL("GRANT {} TO mtmf_migrator").format(sql.Identifier(unrelated)))
        try:
            with pytest.raises(RoleProvisioningError) as excinfo:
                pg_roles.provision_roles(
                    db,
                    migrator_password=migrator_config.password,
                    runtime_password=runtime_config.password,
                )
            assert "mtmf_migrator is a member of" in str(excinfo.value)
        finally:
            db.execute(sql.SQL("REVOKE {} FROM mtmf_migrator").format(sql.Identifier(unrelated)))


def test_a1_09_migrator_inheriting_owner_is_normalized(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    db.execute("GRANT mtmf_owner TO mtmf_migrator WITH INHERIT TRUE, SET TRUE")
    try:
        assert db.execute("SELECT pg_has_role('mtmf_migrator', 'mtmf_owner', 'USAGE')").fetchone()[
            0
        ]
        pg_roles.provision_roles(
            db,
            migrator_password=migrator_config.password,
            runtime_password=runtime_config.password,
        )
        pg_roles.verify_role_topology(db)
        assert not db.execute(
            "SELECT pg_has_role('mtmf_migrator', 'mtmf_owner', 'USAGE')"
        ).fetchone()[0]
        assert db.execute("SELECT pg_has_role('mtmf_migrator', 'mtmf_owner', 'SET')").fetchone()[0]
    finally:
        db.execute("GRANT mtmf_owner TO mtmf_migrator WITH INHERIT FALSE, SET TRUE")


@pytest.mark.parametrize("role", ("mtmf_owner", "mtmf_migrator"))
def test_a1_10_runtime_cannot_set_role(runtime_connection: psycopg.Connection, role: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
    runtime_connection.rollback()


def test_a1_11_migrator_authenticates_before_set_role(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    with psycopg.connect(migrator_config.psycopg_dsn) as connection:
        session_user, current_user = connection.execute(
            "SELECT session_user, current_user"
        ).fetchone()
        assert session_user == current_user == "mtmf_migrator"
        elevated = connection.execute(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
            "FROM pg_catalog.pg_roles WHERE rolname = current_user"
        ).fetchone()
        assert elevated == (False, False, False, False)
    assert db.execute("SELECT pg_has_role('mtmf_migrator', 'mtmf_owner', 'SET')").fetchone()[0]
    assert not db.execute("SELECT pg_has_role('mtmf_migrator', 'mtmf_owner', 'USAGE')").fetchone()[
        0
    ]


# --- A1-12..A1-15: credential/label confusion -------------------------------


def _mislabelled(mtmf_config: PostgresConfig, role: PostgresRole) -> PostgresConfig:
    return PostgresConfig(
        host=mtmf_config.host,
        port=mtmf_config.port,
        database=mtmf_config.database,
        user=mtmf_config.user,
        password=mtmf_config.password,
        role=role,
    )


def test_a1_12_migrator_label_with_admin_credentials_is_rejected(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    before = _object_count(db)
    manager = PostgresMigrationManager(_mislabelled(mtmf_config, PostgresRole.MIGRATOR))
    with pytest.raises(MigrationError) as excinfo:
        manager.upgrade_to_head()
    assert "session_user must be mtmf_migrator" in str(excinfo.value)
    assert _object_count(db) == before


def test_a1_13_migrator_label_with_runtime_credentials_is_rejected(
    db: psycopg.Connection,
    runtime_config: PostgresConfig,
    mtmf_config: PostgresConfig,
) -> None:
    runtime_as_migrator = PostgresConfig(
        host=runtime_config.host,
        port=runtime_config.port,
        database=runtime_config.database,
        user=runtime_config.user,
        password=runtime_config.password,
        role=PostgresRole.MIGRATOR,
    )
    before = _object_count(db)
    with pytest.raises(MigrationError) as excinfo:
        PostgresMigrationManager(runtime_as_migrator).upgrade_to_head()
    assert "session_user must be mtmf_migrator" in str(excinfo.value)
    assert _object_count(db) == before


def test_a1_14_admin_config_cannot_migrate(mtmf_config: PostgresConfig) -> None:
    with pytest.raises(MigrationError):
        PostgresMigrationManager(mtmf_config)


def test_a1_15_alembic_connection_rejects_wrong_authenticated_user(
    db: psycopg.Connection, mtmf_config: PostgresConfig
) -> None:
    before = _object_count(db)
    with pytest.raises(Exception) as excinfo:
        helpers.upgrade_to_revision(mtmf_config, "head")
    rendered = repr(excinfo.value) + repr(excinfo.value.__cause__)
    assert "session_user must be mtmf_migrator" in rendered
    assert _object_count(db) == before


# --- A1-18: fresh versus legacy effective-privilege parity ------------------


def test_a1_18_fresh_and_legacy_privilege_snapshots_match(
    db: psycopg.Connection, migrator_config: PostgresConfig, dsn: str
) -> None:
    fresh = helpers.privilege_snapshot(db)

    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(migrator_config, "0002")
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("ALTER SCHEMA mtmf OWNER TO mtmf")
        connection.execute("ALTER TABLE mtmf.tenant OWNER TO mtmf")
    with pytest.raises(MigrationError):
        PostgresMigrationManager(migrator_config).upgrade_to_head()
    with psycopg.connect(dsn, autocommit=True) as connection:
        pg_roles.adopt_existing_schema(connection)
    PostgresMigrationManager(migrator_config).upgrade_to_head()

    legacy = helpers.privilege_snapshot(db)
    assert legacy == fresh
    pg_roles.verify_runtime_privileges(db)


# --- A1-20 / A1-21: diagnostics do not leak secrets; rejected provisioning ---


def test_a1_20_provisioning_error_is_actionable_and_secret_free(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    db.execute("GRANT mtmf_owner TO mtmf_runtime WITH INHERIT FALSE, SET TRUE")
    try:
        with pytest.raises(RoleProvisioningError) as excinfo:
            pg_roles.provision_roles(
                db,
                migrator_password="super-secret-migrator",
                runtime_password="super-secret-runtime",
            )
        message = str(excinfo.value)
        assert "mtmf_runtime" in message
        assert "super-secret" not in message
    finally:
        db.execute("REVOKE mtmf_owner FROM mtmf_runtime")


def test_a1_21_rejected_provisioning_does_not_mutate_passwords(
    db: psycopg.Connection, migrator_config: PostgresConfig, runtime_config: PostgresConfig
) -> None:
    before = {
        row[0]: row[1]
        for row in db.execute(
            "SELECT rolname, rolpassword FROM pg_catalog.pg_authid "
            "WHERE rolname IN ('mtmf_migrator', 'mtmf_runtime')"
        ).fetchall()
    }
    db.execute("GRANT mtmf_owner TO mtmf_runtime WITH INHERIT FALSE, SET TRUE")
    try:
        with pytest.raises(RoleProvisioningError):
            pg_roles.provision_roles(
                db,
                migrator_password="different-password",
                runtime_password="different-password",
            )
    finally:
        db.execute("REVOKE mtmf_owner FROM mtmf_runtime")
    after = {
        row[0]: row[1]
        for row in db.execute(
            "SELECT rolname, rolpassword FROM pg_catalog.pg_authid "
            "WHERE rolname IN ('mtmf_migrator', 'mtmf_runtime')"
        ).fetchall()
    }
    assert after == before
