"""MTMF PostgreSQL infrastructure (schema, migrations, configuration).

PR 6 establishes the MTMF-owned physical ``mtmf`` schema, the
Alembic-backed migration graph hidden behind
:class:`~mtmf_core.persistence.postgres.migration.PostgresMigrationManager`,
versioned packaged SQL resources, and explicit MTMF connection
configuration. PR 7A adds owner/migrator/runtime role separation and the
default-deny runtime privilege model. It deliberately contains no
`PostgresMtmfSpi`, no PostgreSQL repositories, and no UnitOfWork
implementation: those belong to PR 7B.
"""

from __future__ import annotations

from mtmf_core.persistence.postgres.config import (
    PostgresConfig,
    PostgresConfigError,
    PostgresRole,
)
from mtmf_core.persistence.postgres.migration import (
    HEAD_REVISION,
    OWNER_ROLE,
    MigrationError,
    PostgresMigrationManager,
)
from mtmf_core.persistence.postgres.resources import (
    MigrationResourceError,
    migrations_script_directory,
    sql_version_files,
)

__all__ = [
    "HEAD_REVISION",
    "OWNER_ROLE",
    "MigrationError",
    "MigrationResourceError",
    "PostgresConfig",
    "PostgresConfigError",
    "PostgresMigrationManager",
    "PostgresRole",
    "migrations_script_directory",
    "sql_version_files",
]
