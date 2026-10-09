"""Stored-function convention tests (FUN).

PR 6 installs one infrastructure proof function from the versioned,
packaged SQL resources to establish the convention PR 7 extends. It must
be schema-qualified and callable after an empty-database migration. PR 7A
adds the reviewed ``SECURITY DEFINER`` membership-removal entry points and
their explicit runtime grants; every other function stays a plain,
non-elevated helper with PUBLIC EXECUTE revoked.
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
    # Repository CRUD functions would be named with these prefixes; the
    # membership guard/removal functions use the ``membership_*``/``remove_*``
    # vocabulary instead and are not a repository CRUD family.
    for fragment in ("repository", "insert_", "update_", "delete_", "select_", "crud"):
        assert not any(name.startswith(fragment) for name in functions)


def test_fun05_only_approved_removal_functions_use_security_definer(db) -> None:
    rows = db.execute(
        "SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner) "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND p.prosecdef "
        "ORDER BY p.proname",
        (helpers.SCHEMA,),
    ).fetchall()
    assert len(rows) == 6
    assert all(name.startswith("remove_") and owner == "mtmf_owner" for name, _def, owner in rows)
    # The infrastructure proof function is deliberately not elevated.
    assert not db.execute(
        "SELECT prosecdef FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND p.proname = 'mtf_schema_version'",
        (helpers.SCHEMA,),
    ).fetchone()[0]


def test_fun06_privileges_are_explicit_default_deny(db) -> None:
    # PR 7A makes function ACLs explicit: PUBLIC EXECUTE is revoked for
    # every function, and only the six approved removal signatures are
    # granted to the restricted runtime role.
    public_executable = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND EXISTS ("
        "  SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
        "  WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')",
        (helpers.SCHEMA,),
    ).fetchone()[0]
    assert public_executable == 0
    runtime_executable = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')",
        (helpers.SCHEMA,),
    ).fetchone()[0]
    assert runtime_executable == 6
