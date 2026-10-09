"""Alembic environment for MTMF-owned migrations.

This file is executed by Alembic from inside the packaged script
directory. It deliberately exposes no Alembic objects to consumers: the
:class:`~mtmf_core.persistence.postgres.migration.PostgresMigrationManager`
supplies the connection URL through the ``mtmf_url`` configuration
attribute, keeps the MTMF migration state inside the ``mtmf`` schema,
and never supports offline migration mode.

The SQLAlchemy connection is switched to the MTMF owner role
(``SET ROLE``) before the migration transaction begins, so every object
Alembic creates — including ``mtmf.alembic_version`` — has a
deterministic owner independent of the authenticating login.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from mtmf_core.persistence.postgres.roles import verify_migrator_connection

_MIGRATION_SCHEMA = "mtmf"
_OWNER_ROLE_ATTRIBUTE = "mtmf_owner_role"
_DEFAULT_OWNER_ROLE = "mtmf_owner"


def run_migrations_online() -> None:
    url = context.config.attributes.get("mtmf_url")
    if not url:
        raise RuntimeError(
            "the Alembic 'mtmf_url' configuration attribute is required; use "
            "PostgresMigrationManager rather than invoking Alembic directly"
        )
    owner_role = context.config.attributes.get(_OWNER_ROLE_ATTRIBUTE) or _DEFAULT_OWNER_ROLE
    if not isinstance(owner_role, str) or not owner_role.isidentifier():
        raise RuntimeError(
            "the MTMF owner role name must be a plain SQL identifier; refusing to "
            f"interpolate {owner_role!r} into SET ROLE"
        )
    # The MTMF schema is bootstrapped by PostgresMigrationManager (plain
    # psycopg) as the owner role before Alembic runs, so this environment
    # performs no schema bootstrap.
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        # The migration login must be the migrator and must not be elevated
        # before we assume the owner; check the raw DBAPI connection.
        proxy = connection.connection
        if proxy is None:
            raise RuntimeError("the Alembic migration connection is not available")
        driver = proxy.driver_connection
        if driver is None:
            raise RuntimeError("the Alembic migration driver connection is not available")
        verify_migrator_connection(driver)
        # ``SET ROLE`` is transaction-scoped: commit it so it survives
        # into the migration transaction below. The role move happens
        # before Alembic starts its own transaction, since Alembic would
        # refuse to begin one on an already-open transaction.
        connection.exec_driver_sql(f'SET ROLE "{owner_role}"')
        connection.commit()
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
