"""Stored-function convention tests (FUN).

PR 6 installs one infrastructure proof function from the versioned,
packaged SQL resources to establish the convention PR 7 extends. It must
be schema-qualified, callable after an empty-database migration, carry
no repository CRUD family, use no SECURITY DEFINER, and receive no
broad privilege grants.
"""

from __future__ import annotations

import helpers


def test_fun01_proof_function_installed_from_versioned_sql(db) -> None:
    assert "mtf_schema_version" in helpers.functions_in_schema(db)


def test_fun02_proof_function_is_schema_qualified(db) -> None:
    row = db.execute(
        "SELECT n.nspname FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE p.proname = 'mtf_schema_version' AND n.nspname = %s",
        (helpers.SCHEMA,),
    ).fetchone()
    assert row is not None


def test_fun03_proof_function_callable_after_empty_db_migration(db) -> None:
    # Every test starts from an empty database migrated to head.
    assert db.execute("SELECT mtmf.mtf_schema_version()").fetchone()[0] == "mtmf-schema-v001"


def test_fun04_no_repository_crud_function_family(db) -> None:
    functions = helpers.functions_in_schema(db)
    for fragment in ("repository", "insert_", "update_", "delete_", "select_", "crud"):
        assert not any(fragment in name for name in functions)


def test_fun05_no_security_definer_used(db) -> None:
    row = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND p.prosecdef",
        (helpers.SCHEMA,),
    ).fetchone()
    assert row[0] == 0


def test_fun06_privileges_are_minimal_no_explicit_grants(db) -> None:
    row = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND p.proacl IS NOT NULL",
        (helpers.SCHEMA,),
    ).fetchone()
    assert row[0] == 0
