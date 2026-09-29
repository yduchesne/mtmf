"""Alembic environment for MTMF-owned migrations.

This file is executed by Alembic from inside the packaged script
directory. It deliberately exposes no Alembic objects to consumers: the
:class:`~mtmf_core.persistence.postgres.migration.PostgresMigrationManager`
supplies the connection URL through the ``mtmf_url`` configuration
attribute, keeps the MTMF migration state inside the ``mtmf`` schema,
and never supports offline migration mode.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

_MIGRATION_SCHEMA = "mtmf"


def run_migrations_online() -> None:
    url = context.config.attributes.get("mtmf_url")
    if not url:
        raise RuntimeError(
            "the Alembic 'mtmf_url' configuration attribute is required; use "
            "PostgresMigrationManager rather than invoking Alembic directly"
        )
    # The MTMF schema and the Alembic version table inside it are
    # bootstrapped by PostgresMigrationManager (plain psycopg) before
    # Alembic runs, so this environment performs no schema bootstrap.
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=None,
            version_table="alembic_version",
            version_table_schema=_MIGRATION_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


def run_migrations_offline() -> None:
    raise RuntimeError("offline migration mode is not part of the MTMF contract")


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
