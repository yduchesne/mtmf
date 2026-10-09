"""MTMF PostgreSQL infrastructure (schema, migrations, configuration).

PR 6 establishes the MTMF-owned physical ``mtmf`` schema, the
Alembic-backed migration graph hidden behind
:class:`~mtmf_core.persistence.postgres.migration.PostgresMigrationManager`,
versioned packaged SQL resources, and explicit MTMF connection
configuration. PR 7A adds owner/migrator/runtime role separation and the
default-deny runtime privilege model. PR 7B adds the production
:class:`~mtmf_core.persistence.postgres.spi.PostgresMtmfSpi` provider, the
real-transaction PostgreSQL UnitOfWork, all 13 typed repositories, and
their reviewed stored-function entry points through revision 0004.
"""

from __future__ import annotations

from mtmf_core.persistence.postgres.config import (
    PostgresConfig,
    PostgresConfigError,
    PostgresRole,
)
from mtmf_core.persistence.postgres.error_translation import (
    translate_connection_error,
    translate_operation_error,
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
from mtmf_core.persistence.postgres.roles import (
    MigrationIdentityError,
    PrivilegeVerificationError,
    RoleProvisioningError,
    expected_removal_signatures,
    expected_runtime_signatures,
    find_non_owner_objects,
    verify_role_topology,
    verify_runtime_privileges,
)
from mtmf_core.persistence.postgres.spi import PostgresMtmfSpi
from mtmf_core.persistence.postgres.unit_of_work import PostgresUnitOfWork

__all__ = [
    "HEAD_REVISION",
    "OWNER_ROLE",
    "MigrationError",
    "MigrationIdentityError",
    "MigrationResourceError",
    "PostgresConfig",
    "PostgresConfigError",
    "PostgresMigrationManager",
    "PostgresMtmfSpi",
    "PostgresRole",
    "PostgresUnitOfWork",
    "PrivilegeVerificationError",
    "RoleProvisioningError",
    "expected_removal_signatures",
    "expected_runtime_signatures",
    "find_non_owner_objects",
    "migrations_script_directory",
    "sql_version_files",
    "translate_connection_error",
    "translate_operation_error",
    "verify_role_topology",
    "verify_runtime_privileges",
]
