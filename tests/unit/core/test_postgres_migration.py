"""Unit tests for the MTMF migration-management boundary (no database).

The manager must reject the restricted runtime role outright: a runtime
credential may never manage migrations. Administrator and migrator roles
are accepted; the actual upgrade path is covered by the real-PostgreSQL
integration suite.
"""

from __future__ import annotations

import pytest

from mtmf_core.persistence.postgres import (
    HEAD_REVISION,
    OWNER_ROLE,
    MigrationError,
    PostgresConfig,
    PostgresMigrationManager,
    PostgresRole,
)


def _config(role: PostgresRole) -> PostgresConfig:
    return PostgresConfig(
        host="db.example",
        port=25432,
        database="mtmf",
        user=f"user_{role.value}",
        password="pw",
        role=role,
    )


def test_runtime_role_is_rejected_by_the_migration_manager() -> None:
    with pytest.raises(MigrationError):
        PostgresMigrationManager(_config(PostgresRole.RUNTIME))


def test_admin_and_migrator_roles_are_accepted() -> None:
    for role in (PostgresRole.ADMIN, PostgresRole.MIGRATOR):
        manager = PostgresMigrationManager(_config(role))
        assert manager.config.role is role


def test_head_revision_and_owner_role_are_the_pr7a_values() -> None:
    assert HEAD_REVISION == "0003"
    assert PostgresMigrationManager.head_revision == "0003"
    assert OWNER_ROLE == "mtmf_owner"
