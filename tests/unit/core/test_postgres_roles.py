"""Unit tests for MTMF PostgreSQL role provisioning and verification (no database).

The provisioning SQL and the read-only verifiers are cluster-level
administrator work that must be idempotent and fail closed on unsafe role
topology or effective privileges. These tests exercise statement
construction, the pure diagnostics, and the verifier control flow without
a live PostgreSQL.
"""

from __future__ import annotations

from typing import Any

import pytest

from mtmf_core.persistence.postgres import roles

_OWNER_ATTR = ("mtmf_owner", False, False, False, False, False)
_MIGRATOR_ATTR = ("mtmf_migrator", False, False, False, True, False)
_RUNTIME_ATTR = ("mtmf_runtime", False, False, False, True, False)
_SAFE_MEMBERSHIP = ("mtmf_migrator", "mtmf_owner", False, True, False)
_SAFE_REACHABILITY = (True, False, True, False, False, False, False)


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _ScriptedConnection:
    """Minimal psycopg-like connection with substring-keyed canned results."""

    def __init__(self) -> None:
        self.queries: list[tuple[object, object]] = []
        self._handlers: list[tuple[str, list[tuple[Any, ...]]]] = []

    def on(self, substring: str, rows: list[tuple[Any, ...]]) -> _ScriptedConnection:
        self._handlers.append((substring, rows))
        return self

    def execute(self, query: object, params: object = None) -> _FakeCursor:
        self.queries.append((query, params))
        text = query if isinstance(query, str) else query.as_string(None)
        for substring, rows in self._handlers:
            if substring in text:
                return _FakeCursor(rows)
        return _FakeCursor([])

    def statements(self) -> list[str]:
        rendered: list[str] = []
        for query, _params in self.queries:
            rendered.append(query if isinstance(query, str) else query.as_string(None))
        return rendered


def _healthy_catalog(
    connection: _ScriptedConnection, *, non_owner_rows: list[tuple[Any, ...]] | None = None
) -> _ScriptedConnection:
    """Register the catalog rows produced by a correctly provisioned cluster."""
    offender_rows = [(None,)] if non_owner_rows is None else non_owner_rows
    return (
        connection.on(
            "SELECT rolname, rolsuper",
            [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
        )
        .on("FROM pg_catalog.pg_auth_members", [_SAFE_MEMBERSHIP])
        .on("pg_has_role", [_SAFE_REACHABILITY])
        .on("SELECT string_agg(obj", offender_rows)
    )


def _healthy_privileges(connection: _ScriptedConnection) -> _ScriptedConnection:
    return (
        connection.on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [(1,)])
        .on("has_database_privilege", [(True, False)])
        .on("has_schema_privilege", [(True, False)])
        .on("has_table_privilege", [])
        .on("has_sequence_privilege", [])
        .on(
            "has_function_privilege",
            [(signature,) for signature in sorted(roles.expected_runtime_signatures())],
        )
        .on("aclexplode(coalesce(p.proacl", [(0,)])
        .on("FROM pg_catalog.pg_default_acl", [(0,)])
    )


# --- provision_roles --------------------------------------------------------


def test_provision_roles_creates_missing_roles_and_restricts_runtime() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_roles WHERE rolname = %s", [])  # roles missing
    connection.on("SELECT current_database()", [("mtmf",)])
    roles.provision_roles(
        connection,  # type: ignore[arg-type]
        migrator_password="migrator-pw",
        runtime_password="runtime-pw",
    )
    joined = "\n".join(connection.statements())
    assert 'CREATE ROLE "mtmf_owner" NOLOGIN' in joined
    assert 'CREATE ROLE "mtmf_migrator" LOGIN' in joined
    assert 'CREATE ROLE "mtmf_runtime" LOGIN' in joined
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS" in joined
    assert 'GRANT "mtmf_owner" TO "mtmf_migrator" WITH INHERIT FALSE, SET TRUE' in joined
    assert 'REVOKE "mtmf_owner" FROM "mtmf_runtime"' in joined
    assert 'GRANT CREATE ON DATABASE "mtmf" TO "mtmf_owner"' in joined
    assert 'GRANT CONNECT ON DATABASE "mtmf" TO "mtmf_runtime"' in joined


def test_provision_roles_is_idempotent_when_roles_exist() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_roles WHERE rolname = %s", [(1,)])
    connection.on("SELECT current_database()", [("mtmf",)])
    roles.provision_roles(
        connection,  # type: ignore[arg-type]
        migrator_password="a",
        runtime_password="b",
    )
    statements = connection.statements()
    assert not any("CREATE ROLE" in statement for statement in statements)
    assert any("ALTER ROLE" in statement for statement in statements)
    assert any("GRANT CREATE ON DATABASE" in statement for statement in statements)


def test_provision_roles_fails_closed_before_credential_mutation_on_contamination() -> None:
    connection = _ScriptedConnection()
    connection.on(
        "FROM pg_catalog.pg_auth_members",
        [
            _SAFE_MEMBERSHIP,
            ("mtmf_runtime", "mtmf_owner", False, True, False),
        ],
    )
    with pytest.raises(roles.RoleProvisioningError) as excinfo:
        roles.provision_roles(
            connection,  # type: ignore[arg-type]
            migrator_password="should-not-be-set",
            runtime_password="should-not-be-set",
        )
    message = str(excinfo.value)
    assert "mtmf_runtime is a member of mtmf_owner" in message
    # The preflight runs before any ALTER ROLE ... PASSWORD statement.
    assert not any("PASSWORD" in statement for statement in connection.statements())


def test_provision_roles_rejects_transitive_runtime_path() -> None:
    connection = _ScriptedConnection()
    connection.on(
        "FROM pg_catalog.pg_auth_members",
        [_SAFE_MEMBERSHIP, ("mtmf_runtime", "mtmf_intermediate", False, True, False)],
    )
    with pytest.raises(roles.RoleProvisioningError) as excinfo:
        roles.provision_roles(
            connection,  # type: ignore[arg-type]
            migrator_password="a",
            runtime_password="b",
        )
    assert "mtmf_runtime is a member of mtmf_intermediate" in str(excinfo.value)


# --- topology diagnostics ---------------------------------------------------


def test_topology_problems_accepts_the_approved_graph() -> None:
    assert (
        roles._topology_problems(
            [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
            [_SAFE_MEMBERSHIP],
            _SAFE_REACHABILITY,
        )
        == []
    )


def test_topology_problems_detects_runtime_membership() -> None:
    problems = roles._topology_problems(
        [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
        [_SAFE_MEMBERSHIP, ("mtmf_runtime", "mtmf_unrelated", True, True, False)],
        _SAFE_REACHABILITY,
    )
    assert any("mtmf_runtime is a member of mtmf_unrelated" in problem for problem in problems)


def test_topology_problems_detects_migrator_extra_membership() -> None:
    problems = roles._topology_problems(
        [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
        [_SAFE_MEMBERSHIP, ("mtmf_migrator", "mtmf_unrelated", True, True, False)],
        _SAFE_REACHABILITY,
    )
    assert any("mtmf_migrator is a member of mtmf_unrelated" in problem for problem in problems)


def test_topology_problems_detects_missing_and_wrong_options() -> None:
    missing = roles._topology_problems(
        [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR], [], _SAFE_REACHABILITY
    )
    assert any("membership for mtmf_migrator is missing" in problem for problem in missing)
    wrong = roles._topology_problems(
        [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
        [("mtmf_migrator", "mtmf_owner", True, False, False)],
        _SAFE_REACHABILITY,
    )
    assert any("INHERIT FALSE, SET TRUE, ADMIN FALSE" in problem for problem in wrong)


def test_topology_problems_detects_reachability_violations() -> None:
    problems = roles._topology_problems(
        [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR],
        [_SAFE_MEMBERSHIP],
        (True, False, True, True, False, True, True),
    )
    assert any("must not reach mtmf_owner" in problem for problem in problems)
    assert any("must not be a member of mtmf_migrator" in problem for problem in problems)


def test_topology_problems_detects_missing_role_and_elevated_attributes() -> None:
    problems = roles._topology_problems(
        [("mtmf_owner", True, True, True, True, True)],
        [],
        _SAFE_REACHABILITY,
    )
    assert any("does not exist" in problem for problem in problems)
    assert any("SUPERUSER/CREATEROLE/CREATEDB/BYPASSRLS" in problem for problem in problems)
    assert any("must be NOLOGIN" in problem for problem in problems)


def test_verify_role_topology_raises_on_unsafe_graph() -> None:
    connection = _ScriptedConnection()
    connection.on("SELECT rolname, rolsuper", [_MIGRATOR_ATTR, _OWNER_ATTR, _RUNTIME_ATTR])
    connection.on(
        "FROM pg_catalog.pg_auth_members", [("mtmf_runtime", "mtmf_owner", False, True, False)]
    )
    connection.on("pg_has_role", [_SAFE_REACHABILITY])
    with pytest.raises(roles.RoleProvisioningError):
        roles.verify_role_topology(connection)  # type: ignore[arg-type]


# --- privilege diagnostics --------------------------------------------------


def _safe_privilege_problems() -> list[str]:
    return roles._privilege_problems(
        schema_exists=True,
        database_privileges=(True, False),
        schema_privileges=(True, False),
        table_offenders=[],
        sequence_offenders=[],
        executable_signatures=set(roles.expected_runtime_signatures()),
        public_execute_count=0,
        default_public_execute_count=0,
    )


def test_privilege_problems_accepts_the_approved_surface() -> None:
    assert _safe_privilege_problems() == []


def test_privilege_problems_detects_missing_schema() -> None:
    problems = roles._privilege_problems(
        schema_exists=False,
        database_privileges=None,
        schema_privileges=None,
        table_offenders=[],
        sequence_offenders=[],
        executable_signatures=set(),
        public_execute_count=0,
        default_public_execute_count=0,
    )
    assert any("does not exist" in problem for problem in problems)


def test_privilege_problems_detects_database_and_schema_grants() -> None:
    problems = roles._privilege_problems(
        schema_exists=True,
        database_privileges=(False, True),
        schema_privileges=(False, True),
        table_offenders=[],
        sequence_offenders=[],
        executable_signatures=set(roles.expected_runtime_signatures()),
        public_execute_count=0,
        default_public_execute_count=0,
    )
    assert any("missing CONNECT" in problem for problem in problems)
    assert any("must not have CREATE on the MTMF database" in problem for problem in problems)
    assert any("missing USAGE on schema" in problem for problem in problems)
    assert any("must not have CREATE on schema" in problem for problem in problems)


def test_privilege_problems_detects_object_and_function_violations() -> None:
    problems = roles._privilege_problems(
        schema_exists=True,
        database_privileges=(True, False),
        schema_privileges=(True, False),
        table_offenders=[("mtmf.tenant", "SELECT")],
        sequence_offenders=[("mtmf.some_seq", "USAGE")],
        executable_signatures={
            *roles.expected_runtime_signatures(),
            "mtmf.mtf_schema_version()",
        },
        public_execute_count=1,
        default_public_execute_count=1,
    )
    assert any("SELECT on table/view mtmf.tenant" in problem for problem in problems)
    assert any("USAGE on sequence mtmf.some_seq" in problem for problem in problems)
    assert any("unapproved function mtmf.mtf_schema_version()" in problem for problem in problems)
    assert any("PUBLIC can EXECUTE" in problem for problem in problems)
    assert any("default privileges" in problem for problem in problems)


def test_privilege_problems_detects_missing_approved_function() -> None:
    signatures = set(roles.expected_runtime_signatures())
    signatures.discard(
        "mtmf.remove_group_org_membership(group_id_value uuid, "
        "organization_id_value uuid, actor_identity_id_value uuid)"
    )
    problems = roles._privilege_problems(
        schema_exists=True,
        database_privileges=(True, False),
        schema_privileges=(True, False),
        table_offenders=[],
        sequence_offenders=[],
        executable_signatures=signatures,
        public_execute_count=0,
        default_public_execute_count=0,
    )
    assert any("cannot EXECUTE approved function" in problem for problem in problems)


def test_expected_removal_signatures_are_exactly_six() -> None:
    signatures = roles.expected_removal_signatures()
    assert len(signatures) == 6
    assert all(signature.startswith("mtmf.remove_") for signature in signatures)


def test_expected_runtime_signatures_add_the_44_repository_functions() -> None:
    removal = roles.expected_removal_signatures()
    runtime = roles.expected_runtime_signatures()
    assert len(runtime) == 50
    assert removal <= runtime
    assert len(runtime - removal) == 44
    for name in ("mtmf.tenant_add", "mtmf.role_add", "mtmf.action_get"):
        assert any(signature.startswith(name + "(") for signature in runtime)


def test_verify_runtime_privileges_passes_on_healthy_catalog() -> None:
    connection = _healthy_catalog(_healthy_privileges(_ScriptedConnection()))
    roles.verify_runtime_privileges(connection)  # type: ignore[arg-type]


def test_verify_runtime_privileges_raises_on_unsafe_catalog() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [(1,)])
    connection.on("has_database_privilege", [(True, False)])
    connection.on("has_schema_privilege", [(True, False)])
    connection.on("has_table_privilege", [("mtmf.tenant", "SELECT")])
    connection.on("has_sequence_privilege", [])
    connection.on("has_function_privilege", [])
    connection.on("aclexplode(coalesce(p.proacl", [(0,)])
    connection.on("FROM pg_catalog.pg_default_acl", [(0,)])
    with pytest.raises(roles.PrivilegeVerificationError):
        roles.verify_runtime_privileges(connection)  # type: ignore[arg-type]


# --- migrator identity ------------------------------------------------------


def _migrator_connection_row() -> tuple[Any, ...]:
    return ("mtmf_migrator", "mtmf_migrator", False, False, False, False, True, False)


def test_verify_migrator_connection_accepts_the_migrator() -> None:
    connection = _ScriptedConnection().on(
        "WHERE r.rolname = session_user", [_migrator_connection_row()]
    )
    roles.verify_migrator_connection(connection)  # type: ignore[arg-type]


def test_verify_migrator_connection_rejects_admin_credentials() -> None:
    connection = _ScriptedConnection().on(
        "WHERE r.rolname = session_user",
        [("mtmf", "mtmf", True, True, True, True, True, False)],
    )
    with pytest.raises(roles.MigrationIdentityError) as excinfo:
        roles.verify_migrator_connection(connection)  # type: ignore[arg-type]
    assert "session_user must be mtmf_migrator" in str(excinfo.value)


def test_verify_migrator_connection_rejects_runtime_credentials() -> None:
    connection = _ScriptedConnection().on(
        "WHERE r.rolname = session_user",
        [("mtmf_runtime", "mtmf_runtime", False, False, False, False, False, False)],
    )
    with pytest.raises(roles.MigrationIdentityError) as excinfo:
        roles.verify_migrator_connection(connection)  # type: ignore[arg-type]
    assert "session_user must be mtmf_migrator" in str(excinfo.value)


def test_verify_migrator_connection_rejects_inherited_owner_usage() -> None:
    connection = _ScriptedConnection().on(
        "WHERE r.rolname = session_user",
        [("mtmf_migrator", "mtmf_migrator", False, False, False, False, True, True)],
    )
    with pytest.raises(roles.MigrationIdentityError) as excinfo:
        roles.verify_migrator_connection(connection)  # type: ignore[arg-type]
    assert "must not inherit (USAGE)" in str(excinfo.value)


# --- adopt_existing_schema --------------------------------------------------


def test_adopt_existing_schema_is_a_noop_without_the_schema() -> None:
    connection = _ScriptedConnection().on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [])
    roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    assert len(connection.queries) == 1


def test_adopt_existing_schema_transfers_only_mtmf_objects() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [(1,)])
    connection.on("FROM pg_catalog.pg_class c", [("tenant", "r")])
    connection.on("FROM pg_catalog.pg_proc p", [("remove_x(uuid)",)])
    roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    statements = connection.statements()
    assert 'ALTER SCHEMA "mtmf" OWNER TO "mtmf_owner"' in statements
    assert 'ALTER TABLE "mtmf"."tenant" OWNER TO "mtmf_owner"' in statements
    assert 'ALTER FUNCTION remove_x(uuid) OWNER TO "mtmf_owner"' in statements


def test_adopt_existing_schema_fails_when_owner_transfer_is_incomplete() -> None:
    connection = _healthy_catalog(_ScriptedConnection(), non_owner_rows=[("tenant (mtmf)",)])
    connection.on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [(1,)])
    connection.on("FROM pg_catalog.pg_class c", [("tenant", "r")])
    connection.on("FROM pg_catalog.pg_proc p", [("remove_x(uuid)",)])
    with pytest.raises(roles.RoleProvisioningError) as excinfo:
        roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    assert "tenant (mtmf)" in str(excinfo.value)


def test_find_non_owner_objects_reports_offenders() -> None:
    connection = _ScriptedConnection().on("SELECT string_agg(obj", [("tenant (mtmf)",)])
    assert roles.find_non_owner_objects(connection) == "tenant (mtmf)"  # type: ignore[arg-type]


def test_find_non_owner_objects_returns_none_when_owner_owned() -> None:
    connection = _ScriptedConnection().on("SELECT string_agg(obj", [(None,)])
    assert roles.find_non_owner_objects(connection) is None  # type: ignore[arg-type]


# --- U09/U10: lifecycle phases do not demand head-level privileges ----------


def test_u09_provisioning_does_not_run_head_privilege_queries() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_roles WHERE rolname = %s", [(1,)])
    connection.on("SELECT current_database()", [("mtmf",)])
    roles.provision_roles(
        connection,  # type: ignore[arg-type]
        migrator_password="a",
        runtime_password="b",
    )
    joined = "\n".join(connection.statements())
    assert "has_table_privilege" not in joined
    assert "has_function_privilege" not in joined
    assert "pg_default_acl" not in joined


def test_u10_adoption_checks_ownership_and_topology_only() -> None:
    connection = _healthy_catalog(_ScriptedConnection())
    connection.on("FROM pg_catalog.pg_namespace WHERE nspname = %s", [(1,)])
    connection.on("FROM pg_catalog.pg_class c", [("tenant", "r")])
    connection.on("FROM pg_catalog.pg_proc p", [("remove_x(uuid)",)])
    roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    joined = "\n".join(connection.statements())
    assert "has_table_privilege" not in joined
    assert "has_function_privilege" not in joined
    assert "SELECT rolname, rolsuper" in joined  # topology verifier ran
