"""Unit tests for MTMF PostgreSQL role provisioning helpers (no database).

The provisioning SQL is cluster-level administrator work that must be
idempotent and never silently escalate rights; these tests exercise the
statement construction and control flow without a live PostgreSQL.
"""

from __future__ import annotations

from typing import Any

from mtmf_core.persistence.postgres import roles


class _FakeCursor:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._connection.fetchone_queue.pop(0) if self._connection.fetchone_queue else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._connection.fetchall_queue.pop(0) if self._connection.fetchall_queue else []


class _FakeConnection:
    """Minimal psycopg-like connection recording executed statements."""

    def __init__(self) -> None:
        self.queries: list[tuple[object, object]] = []
        self.fetchone_queue: list[tuple[Any, ...] | None] = []
        self.fetchall_queue: list[list[tuple[Any, ...]]] = []

    def execute(self, query: object, params: object = None) -> _FakeCursor:
        self.queries.append((query, params))
        return _FakeCursor(self)

    def statements(self) -> list[str]:
        rendered: list[str] = []
        for query, _params in self.queries:
            rendered.append(query if isinstance(query, str) else query.as_string(None))
        return rendered


def test_provision_roles_creates_missing_roles_and_restricts_runtime() -> None:
    connection = _FakeConnection()
    # Three role-existence probes (all missing), then current_database().
    connection.fetchone_queue = [None, None, None, ("mtmf",)]
    roles.provision_roles(
        connection,  # type: ignore[arg-type]
        migrator_password="migrator-pw",
        runtime_password="runtime-pw",
    )
    statements = connection.statements()
    joined = "\n".join(statements)
    assert 'CREATE ROLE "mtmf_owner" NOLOGIN' in joined
    assert 'CREATE ROLE "mtmf_migrator" LOGIN' in joined
    assert 'CREATE ROLE "mtmf_runtime" LOGIN' in joined
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS" in joined
    assert 'GRANT "mtmf_owner" TO "mtmf_migrator" WITH INHERIT FALSE, SET TRUE' in joined
    assert 'REVOKE "mtmf_owner" FROM "mtmf_runtime"' in joined
    assert 'GRANT CREATE ON DATABASE "mtmf" TO "mtmf_owner"' in joined
    assert 'GRANT CONNECT ON DATABASE "mtmf" TO "mtmf_runtime"' in joined


def test_provision_roles_is_idempotent_when_roles_exist() -> None:
    connection = _FakeConnection()
    connection.fetchone_queue = [("1",), ("1",), ("1",), ("mtmf",)]
    roles.provision_roles(
        connection,  # type: ignore[arg-type]
        migrator_password="a",
        runtime_password="b",
    )
    statements = connection.statements()
    assert not any("CREATE ROLE" in statement for statement in statements)
    assert any("ALTER ROLE" in statement for statement in statements)
    assert any("GRANT CREATE ON DATABASE" in statement for statement in statements)


def test_adopt_existing_schema_is_a_noop_without_the_schema() -> None:
    connection = _FakeConnection()
    connection.fetchone_queue = [None]
    roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    assert len(connection.queries) == 1


def test_adopt_existing_schema_transfers_only_mtmf_objects() -> None:
    connection = _FakeConnection()
    connection.fetchone_queue = [("1",)]
    connection.fetchall_queue = [[("tenant", "r")], [("remove_x(uuid)",)]]
    roles.adopt_existing_schema(connection)  # type: ignore[arg-type]
    statements = connection.statements()
    assert 'ALTER SCHEMA "mtmf" OWNER TO "mtmf_owner"' in statements
    assert 'ALTER TABLE "mtmf"."tenant" OWNER TO "mtmf_owner"' in statements
    assert 'ALTER FUNCTION remove_x(uuid) OWNER TO "mtmf_owner"' in statements
