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

Every migration connection (schema bootstrap and the SQLAlchemy Alembic
connection) executes under the MTMF owner role by ``SET ROLE``, so
objects are owned deterministically regardless of which login
authenticated. The restricted runtime configuration is rejected: a
runtime credential may never manage migrations.
"""

from __future__ import annotations

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

from mtmf_core.persistence.postgres.config import PostgresConfig, PostgresRole
from mtmf_core.persistence.postgres.resources import migrations_script_directory

HEAD_REVISION = "0003"

#: The ``NOLOGIN`` role that owns every MTMF schema object. It is only
#: ever assumed through a controlled ``SET ROLE`` from a deployment login.
OWNER_ROLE = "mtmf_owner"


class MigrationError(RuntimeError):
    """An MTMF migration operation failed."""


def _legacy_ownership(connection: psycopg.Connection) -> str | None:
    """Return a summary of ``mtmf`` objects not owned by the owner role, if any."""
    # ``%%s`` is psycopg's escape for a literal ``%s`` (the SQL ``format()``
    # placeholder); the three ``%s`` tokens are the bound owner-role values.
    row = connection.execute(
        """
        SELECT string_agg(obj, ', ')
          FROM (
                SELECT format('schema mtmf (%%s)', pg_get_userbyid(nspowner)) AS obj
                  FROM pg_catalog.pg_namespace
                 WHERE nspname = 'mtmf' AND pg_get_userbyid(nspowner) <> %s
                UNION ALL
                SELECT format('%%s (%%s)', c.relname, pg_get_userbyid(c.relowner))
                  FROM pg_catalog.pg_class c
                  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'mtmf' AND pg_get_userbyid(c.relowner) <> %s
                UNION ALL
                SELECT format('function %%s (%%s)', p.proname, pg_get_userbyid(p.proowner))
                  FROM pg_catalog.pg_proc p
                  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = 'mtmf' AND pg_get_userbyid(p.proowner) <> %s
               ) AS offenders
        """,
        (OWNER_ROLE, OWNER_ROLE, OWNER_ROLE),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _set_role_statement() -> sql.Composed:
    """A safely quoted ``SET ROLE`` statement for the MTMF owner role."""
    return sql.SQL("SET ROLE {}").format(sql.Identifier(OWNER_ROLE))


class PostgresMigrationManager:
    """Upgrade and inspect the MTMF-owned PostgreSQL migration graph.

    The manager connects using an explicit
    :class:`~mtmf_core.persistence.postgres.config.PostgresConfig` only.
    It exposes no database-driver handles and no Alembic objects. A
    configuration carrying the restricted runtime role is rejected.
    """

    #: The migration interface's current head identifier. Consumers need
    #: only compare :meth:`current_revision` against this value; they must
    #: not know Alembic revision IDs or the migration graph.
    head_revision = HEAD_REVISION

    def __init__(self, config: PostgresConfig) -> None:
        if config.role is PostgresRole.RUNTIME:
            raise MigrationError(
                "the restricted MTMF runtime role cannot manage migrations; "
                "use the administrator or migrator role"
            )
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
        cfg.attributes["mtmf_owner_role"] = OWNER_ROLE
        return cfg

    def upgrade_to_head(self) -> None:
        """Migrate an empty or partially migrated MTMF database to head.

        The ``mtmf`` schema itself (including the Alembic version table
        inside it) is created with plain psycopg first, as the MTMF owner
        role, so that Alembic never needs to bootstrap framework objects
        through SQLAlchemy and every object has a deterministic owner. A
        database whose MTMF objects predate PR 7A (legacy ownership) is
        rejected with the administrator ownership-handoff instruction
        rather than silently reassigning ownership.

        :raises MigrationError: if the migration fails or legacy ownership
            requires the administrator handoff.
        """
        try:
            with psycopg.connect(self._config.psycopg_dsn, autocommit=True) as connection:
                offenders = _legacy_ownership(connection)
                if offenders is not None:
                    raise MigrationError(
                        "MTMF migration requires the administrator ownership handoff "
                        "before upgrade-to-head: these mtmf objects are not owned by "
                        f"{OWNER_ROLE}: {offenders}. Run "
                        "`scripts/mtmf-provision-roles.py --adopt-existing-schema`."
                    )
                connection.execute(_set_role_statement())
                connection.execute("CREATE SCHEMA IF NOT EXISTS mtmf")
            command.upgrade(self._alembic_configuration(), "head")
        except MigrationError:
            raise
        except Exception as exc:
            raise MigrationError(
                f"MTMF migration upgrade-to-head failed against {self._config.host}"
            ) from exc

    def current_revision(self) -> str | None:
        """Return the applied MTMF migration revision, or ``None`` before any.

        The revision lives in the MTMF-owned ``mtmf.alembic_version``
        table inside the ``mtmf`` schema. The read is performed as the
        MTMF owner role, since the deployment login does not inherit
        owner table privileges.
        """
        with psycopg.connect(self._config.psycopg_dsn) as connection:
            connection.execute(_set_role_statement())
            row = connection.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()
            return row[0] if row is not None else None
