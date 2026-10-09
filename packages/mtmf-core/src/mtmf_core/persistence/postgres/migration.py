"""MTMF-owned migration-management boundary.

Alembic is an internal mechanism. Consumers interact only with
:class:`PostgresMigrationManager` — upgrading to head and reading the
current migration revision — and never see Alembic ``Config`` objects,
script locations, revision-graph internals, or command objects.

Migration management is a deployment concern and deliberately stays
outside :class:`~mtmf_core.persistence.spi.MtmfSpi`. The manager owns
only MTMF migrations, works from packaged resources rather than the
repository working directory, and does not imply a production downgrade
or rollback contract (only upgrade-to-head is supported).
"""

from __future__ import annotations

import psycopg
from alembic import command
from alembic.config import Config

from mtmf_core.persistence.postgres.config import PostgresConfig
from mtmf_core.persistence.postgres.resources import migrations_script_directory

HEAD_REVISION = "0002"


class MigrationError(RuntimeError):
    """An MTMF migration operation failed."""


class PostgresMigrationManager:
    """Upgrade and inspect the MTMF-owned PostgreSQL migration graph.

    The manager connects using an explicit
    :class:`~mtmf_core.persistence.postgres.config.PostgresConfig` only.
    It exposes no database-driver handles and no Alembic objects.
    """

    #: The migration interface's current head identifier. Consumers need
    #: only compare :meth:`current_revision` against this value; they must
    #: not know Alembic revision IDs or the migration graph.
    head_revision = HEAD_REVISION

    def __init__(self, config: PostgresConfig) -> None:
        self._config = config

    @property
    def config(self) -> PostgresConfig:
        """The explicit MTMF PostgreSQL configuration this manager uses."""
        return self._config

    def _alembic_configuration(self) -> Config:
        cfg = Config()
        cfg.set_main_option("script_location", str(migrations_script_directory()))
        # The URL travels through attributes so that credentials with
        # special characters never pass through config-file interpolation.
        cfg.attributes["mtmf_url"] = self._config.sqlalchemy_url
        return cfg

    def upgrade_to_head(self) -> None:
        """Migrate an empty or partially migrated MTMF database to head.

        The ``mtmf`` schema itself (including the Alembic version table
        inside it) is created with plain psycopg first so that Alembic
        never needs to bootstrap framework objects through SQLAlchemy.

        :raises MigrationError: if the migration fails.
        """
        try:
            with psycopg.connect(self._config.psycopg_dsn, autocommit=True) as connection:
                connection.execute("CREATE SCHEMA IF NOT EXISTS mtmf")
            command.upgrade(self._alembic_configuration(), "head")
        except Exception as exc:
            raise MigrationError(
                f"MTMF migration upgrade-to-head failed against {self._config.host}"
            ) from exc

    def current_revision(self) -> str | None:
        """Return the applied MTMF migration revision, or ``None`` before any.

        The revision lives in the MTMF-owned ``mtmf.alembic_version``
        table inside the ``mtmf`` schema.
        """
        with psycopg.connect(self._config.psycopg_dsn) as connection:
            row = connection.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()
            return row[0] if row is not None else None
