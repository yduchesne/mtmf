"""MTMF PostgreSQL integration-test bootstrap.

Every test runs against the explicitly configured MTMF database
(``MTMF_*`` environment variables, see ``.env.example``) with a freshly
migrated, empty ``mtmf`` schema, so tests are deterministic and
order-independent. Only the ``mtmf`` schema inside the configured
database is ever modified.

Missing, malformed, or ambiguous MTMF database configuration is a
test-setup failure (the suite fails closed): the tests never probe for,
discover, or fall back to another PostgreSQL instance — including any
ATI-owned database.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg
import pytest

from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresConfigError,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import helpers  # noqa: E402  (local directory inserted above)


@pytest.fixture(scope="session")
def mtmf_config() -> PostgresConfig:
    """The explicit MTMF PostgreSQL configuration, or a setup failure.

    :raises RuntimeError: when MTMF configuration is missing or
        ambiguous (the suite must not guess an endpoint).
    """
    try:
        return PostgresConfig.from_env()
    except PostgresConfigError as exc:
        raise RuntimeError(
            "MTMF PostgreSQL integration tests require explicit MTMF_* database "
            "configuration (see .env.example); the suite fails closed rather "
            "than probing for or falling back to another PostgreSQL instance"
        ) from exc


@pytest.fixture
def db(mtmf_config: PostgresConfig) -> psycopg.Connection:
    """An autocommit connection to a freshly migrated, empty MTMF schema.

    Every test starts from an empty ``mtmf`` schema so results are
    independent of test order. Dropping and recreating only the ``mtmf``
    schema additionally re-verifies the empty-database migration path on
    every test.
    """
    connection = psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True)
    try:
        helpers.reset_and_migrate(connection, mtmf_config)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def dsn(mtmf_config: PostgresConfig) -> str:
    """A psycopg DSN for the explicitly configured MTMF database."""
    return mtmf_config.psycopg_dsn
