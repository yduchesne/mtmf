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

Three distinct connection identities are used, each from its own explicit
configuration:

- the **administrator** identity (``MTMF_POSTGRES_*``) only provisions
  roles and seeds/verifies deterministic fixtures;
- the **migrator** identity (``MTMF_MIGRATOR_*``) runs real migrations;
- the **runtime** identity (``MTMF_RUNTIME_*``) is the restricted subject
  of the privilege tests. It is never simulated by ``SET ROLE`` from an
  owner session.

The MTMF roles are cluster-wide and are provisioned idempotently, never
dropped by teardown; only the isolated ``mtmf`` schema is reset per test.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg
import pytest

from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresConfigError,
    PostgresRole,
)
from mtmf_core.persistence.postgres.roles import (
    MIGRATOR_ROLE,
    RUNTIME_ROLE,
    provision_roles,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import helpers  # noqa: E402  (local directory inserted above)

_ROLE_PASSWORDS = {
    PostgresRole.MIGRATOR: ("MTMF_MIGRATOR_POSTGRES_PASSWORD", "mtmf-migrator-dev-password"),
    PostgresRole.RUNTIME: ("MTMF_RUNTIME_POSTGRES_PASSWORD", "mtmf-runtime-dev-password"),
}


@pytest.fixture(scope="session")
def mtmf_config() -> PostgresConfig:
    """The explicit MTMF administrator configuration, or a setup failure.

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


def _role_config(role: PostgresRole, expected_user: str) -> PostgresConfig:
    try:
        config = PostgresConfig.from_env(role)
    except PostgresConfigError as exc:
        raise RuntimeError(
            f"MTMF PostgreSQL integration tests require explicit {role.value} "
            f"database configuration (see .env.example); the {role.value} suite "
            "fails closed when role credentials are absent"
        ) from exc
    if config.user != expected_user:
        raise RuntimeError(
            f"the configured {role.value} login must be {expected_user!r} "
            f"(got {config.user!r}); re-provision roles or fix the configuration"
        )
    return config


@pytest.fixture(scope="session")
def migrator_config(mtmf_config: PostgresConfig) -> PostgresConfig:
    """The deployment-only migrator configuration."""
    return _role_config(PostgresRole.MIGRATOR, MIGRATOR_ROLE)


@pytest.fixture(scope="session")
def runtime_config(mtmf_config: PostgresConfig) -> PostgresConfig:
    """The restricted runtime configuration."""
    return _role_config(PostgresRole.RUNTIME, RUNTIME_ROLE)


@pytest.fixture(scope="session", autouse=True)
def provisioned_roles(mtmf_config: PostgresConfig) -> None:
    """Idempotently provision the MTMF owner/migrator/runtime roles.

    Roles are cluster-wide, so they are created once per session by the
    administrator and never dropped by teardown. Passwords come from the
    explicit role configuration environment (with documented development
    placeholders when the role-specific secret is unset).
    """
    passwords: dict[str, str] = {}
    for role, (env_name, default) in _ROLE_PASSWORDS.items():
        passwords[role.value] = os.environ.get(env_name, "").strip() or default
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        provision_roles(
            connection,
            migrator_password=passwords[PostgresRole.MIGRATOR.value],
            runtime_password=passwords[PostgresRole.RUNTIME.value],
        )


@pytest.fixture
def db(mtmf_config: PostgresConfig, migrator_config: PostgresConfig) -> psycopg.Connection:
    """A privileged autocommit connection to a freshly migrated empty schema.

    Every test starts from an empty ``mtmf`` schema so results are
    independent of test order. The schema is dropped and recreated by the
    administrator identity, then migrated by the real migrator identity,
    which re-verifies the empty-database migration path on every test.
    """
    connection = psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True)
    try:
        helpers.reset_and_migrate(connection, migrator_config)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def runtime_connection(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> psycopg.Connection:
    """A fresh connection using the actual restricted runtime login.

    Depends on :func:`db` so the schema is freshly migrated first. The
    test must assert the connected identity itself; this fixture never
    substitutes an owner or superuser session.
    """
    connection = psycopg.connect(runtime_config.psycopg_dsn)
    try:
        session_user, current_user = connection.execute(
            "SELECT session_user, current_user"
        ).fetchone()
        if session_user != RUNTIME_ROLE or current_user != RUNTIME_ROLE:
            raise RuntimeError(
                "runtime test fixture must authenticate as the restricted "
                f"{RUNTIME_ROLE!r} login (got session_user={session_user!r}, "
                f"current_user={current_user!r})"
            )
        if connection.execute(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone()[0]:
            raise RuntimeError("runtime test subject must not be a superuser")
        for elevated in ("mtmf_owner", MIGRATOR_ROLE):
            if connection.execute(
                "SELECT pg_has_role(current_user, %s, 'MEMBER')", (elevated,)
            ).fetchone()[0]:
                raise RuntimeError(f"runtime test subject must not be a member of {elevated!r}")
        yield connection
    finally:
        connection.rollback()
        connection.close()


@pytest.fixture
def dsn(mtmf_config: PostgresConfig) -> str:
    """A psycopg DSN for the explicitly configured MTMF database."""
    return mtmf_config.psycopg_dsn
