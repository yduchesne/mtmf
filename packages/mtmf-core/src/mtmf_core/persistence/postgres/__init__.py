"""MTMF PostgreSQL infrastructure (schema, migrations, configuration).

PR 6 establishes the MTMF-owned physical ``mtmf`` schema, the
Alembic-backed migration graph hidden behind
:class:`~mtmf_core.persistence.postgres.migration.PostgresMigrationManager`,
versioned packaged SQL resources, and explicit MTMF connection
configuration. It deliberately contains no `PostgresMtmfSpi`, no
PostgreSQL repositories, and no UnitOfWork implementation: those belong
to PR 7.
"""

from __future__ import annotations

from mtmf_core.persistence.postgres.config import (
    PostgresConfig,
    PostgresConfigError,
)
from mtmf_core.persistence.postgres.migration import (
    HEAD_REVISION,
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
    "MigrationError",
    "MigrationResourceError",
    "PostgresConfig",
    "PostgresConfigError",
    "PostgresMigrationManager",
    "migrations_script_directory",
    "sql_version_files",
]
