"""Unit tests for the MTMF migration-management boundary (no database).

The manager must reject the restricted runtime role outright: a runtime
credential may never manage migrations. Administrator and migrator roles
are accepted; the actual upgrade path is covered by the real-PostgreSQL
integration suite.

The lifecycle control flow (mandatory post-upgrade privilege verification)
is exercised with narrow monkeypatching; mocked control-flow tests are not
evidence of real-role behavior.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from mtmf_core.persistence.postgres import (
    HEAD_REVISION,
    OWNER_ROLE,
    MigrationError,
    MigrationIdentityError,
    PostgresConfig,
    PostgresMigrationManager,
    PostgresRole,
    PrivilegeVerificationError,
)
from mtmf_core.persistence.postgres import migration as migration_module


def _config(role: PostgresRole) -> PostgresConfig:
    return PostgresConfig(
        host="db.example",
        port=25432,
        database="mtmf",
        user=f"user_{role.value}",
        password="pw",
        role=role,
    )


class _NullCursor:
    def fetchone(self) -> tuple[Any, ...] | None:
        return None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return []


class _FakeConnection:
    def __init__(self) -> None:
        self.executed: list[object] = []

    def execute(self, query: object, params: object = None) -> _NullCursor:
        self.executed.append(query)
        return _NullCursor()

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _install_upgrade_fakes(
    monkeypatch: pytest.MonkeyPatch, *, upgrade_error: Exception | None = None
) -> list[str]:
    order: list[str] = []
    fake_connection = _FakeConnection()
    monkeypatch.setattr(migration_module.psycopg, "connect", lambda *a, **k: fake_connection)
    monkeypatch.setattr(migration_module, "verify_migrator_connection", lambda connection: None)
    monkeypatch.setattr(migration_module, "_legacy_ownership", lambda connection: None)

    def fake_upgrade(config: object, revision: str) -> None:
        order.append("alembic")
        if upgrade_error is not None:
            raise upgrade_error

    monkeypatch.setattr(migration_module.command, "upgrade", fake_upgrade)

    def fake_postflight(self: PostgresMigrationManager) -> None:
        order.append("postflight")

    monkeypatch.setattr(
        PostgresMigrationManager, "_verify_post_upgrade_privileges", fake_postflight
    )
    return order


def test_runtime_role_is_rejected_by_the_migration_manager() -> None:
    with pytest.raises(MigrationError):
        PostgresMigrationManager(_config(PostgresRole.RUNTIME))


def test_admin_role_is_rejected_by_the_migration_manager() -> None:
    # The administrator identity is reserved for provisioning and ownership
    # handoff, never normal migrations.
    with pytest.raises(MigrationError):
        PostgresMigrationManager(_config(PostgresRole.ADMIN))


def test_migrator_role_is_accepted() -> None:
    manager = PostgresMigrationManager(_config(PostgresRole.MIGRATOR))
    assert manager.config.role is PostgresRole.MIGRATOR


def test_head_revision_and_owner_role_are_the_pr7b_values() -> None:
    assert HEAD_REVISION == "0004"
    assert PostgresMigrationManager.head_revision == "0004"
    assert OWNER_ROLE == "mtmf_owner"


# --- U01/U02/U06: mandatory postflight ordering ------------------------------


def test_u01_postflight_runs_after_alembic(monkeypatch: pytest.MonkeyPatch) -> None:
    order = _install_upgrade_fakes(monkeypatch)
    PostgresMigrationManager(_config(PostgresRole.MIGRATOR)).upgrade_to_head()
    assert order == ["alembic", "postflight"]


def test_u02_alembic_failure_skips_postflight(monkeypatch: pytest.MonkeyPatch) -> None:
    order = _install_upgrade_fakes(monkeypatch, upgrade_error=RuntimeError("alembic boom"))
    with pytest.raises(MigrationError):
        PostgresMigrationManager(_config(PostgresRole.MIGRATOR)).upgrade_to_head()
    assert order == ["alembic"]


def test_u06_healthy_noop_upgrade_still_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    order = _install_upgrade_fakes(monkeypatch)
    manager = PostgresMigrationManager(_config(PostgresRole.MIGRATOR))
    manager.upgrade_to_head()
    manager.upgrade_to_head()
    assert order == ["alembic", "postflight", "alembic", "postflight"]


# --- U03/U04/U05: postflight failure semantics -------------------------------


def test_u03_postflight_verifier_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(migration_module.psycopg, "connect", lambda *a, **k: _FakeConnection())
    monkeypatch.setattr(migration_module, "verify_migrator_connection", lambda connection: None)

    def failing_verifier(connection: object) -> None:
        raise PrivilegeVerificationError("runtime has SELECT on mtmf.tenant")

    monkeypatch.setattr(migration_module, "verify_runtime_privileges", failing_verifier)
    with pytest.raises(MigrationError) as excinfo:
        PostgresMigrationManager(_config(PostgresRole.MIGRATOR))._verify_post_upgrade_privileges()
    message = str(excinfo.value)
    assert "runtime has SELECT on mtmf.tenant" in message
    assert "post-upgrade" in message
    assert "may already be committed" in message
    assert "automatic downgrade" in message


def test_u04_postflight_connection_failure_is_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_connect(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("could not connect to server")

    monkeypatch.setattr(migration_module.psycopg, "connect", failing_connect)
    with pytest.raises(MigrationError) as excinfo:
        PostgresMigrationManager(_config(PostgresRole.MIGRATOR))._verify_post_upgrade_privileges()
    message = str(excinfo.value)
    assert "could not complete" in message
    assert "password" not in message.lower()
    assert "pw" not in message


def test_u05_postflight_identity_failure_skips_role_and_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    monkeypatch.setattr(migration_module.psycopg, "connect", lambda *a, **k: connection)

    def failing_identity(connection: object) -> None:
        raise MigrationIdentityError("session_user must be mtmf_migrator")

    monkeypatch.setattr(migration_module, "verify_migrator_connection", failing_identity)
    verifier_calls: list[bool] = []
    monkeypatch.setattr(
        migration_module, "verify_runtime_privileges", lambda c: verifier_calls.append(True)
    )
    with pytest.raises(MigrationError):
        PostgresMigrationManager(_config(PostgresRole.MIGRATOR))._verify_post_upgrade_privileges()
    assert verifier_calls == []
    assert connection.executed == []


def test_u07_config_labels_are_rejected_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(migration_module.psycopg, "connect", lambda *a, **k: calls.append((a, k)))
    for role in (PostgresRole.ADMIN, PostgresRole.RUNTIME):
        with pytest.raises(MigrationError):
            PostgresMigrationManager(_config(role))
    assert calls == []
