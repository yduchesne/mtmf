"""Explicit MTMF PostgreSQL connection configuration.

All MTMF database configuration comes from explicit ``MTMF_*``
environment variables. Missing, malformed, or ambiguous configuration
raises :class:`PostgresConfigError`: MTMF tooling never probes for,
discovers, or falls back to another PostgreSQL instance (including any
ATI-owned database). The port number alone is never proof of MTMF
ownership; it is only a connection parameter.

Two mutually exclusive sources exist:

- ``MTMF_DATABASE_URL`` — a full ``postgresql+psycopg://`` URL; when set,
  the ``MTMF_POSTGRES_*`` component variables must not be set;
- the ``MTMF_POSTGRES_HOST`` / ``MTMF_POSTGRES_PORT`` /
  ``MTMF_POSTGRES_DB`` / ``MTMF_POSTGRES_USER`` /
  ``MTMF_POSTGRES_PASSWORD`` components.

``MTMF_POSTGRES_PORT`` defaults to :data:`DEFAULT_PORT` (a documented,
collision-checked development port); every other component is required
when the URL form is not used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote, urlparse

from psycopg import conninfo

ENV_DATABASE_URL = "MTMF_DATABASE_URL"
ENV_HOST = "MTMF_POSTGRES_HOST"
ENV_PORT = "MTMF_POSTGRES_PORT"
ENV_DATABASE = "MTMF_POSTGRES_DB"
ENV_USER = "MTMF_POSTGRES_USER"
ENV_PASSWORD = "MTMF_POSTGRES_PASSWORD"

DEFAULT_PORT = 55432

_COMPONENT_VARIABLES = (ENV_HOST, ENV_PORT, ENV_DATABASE, ENV_USER, ENV_PASSWORD)


class PostgresConfigError(ValueError):
    """Explicit MTMF PostgreSQL configuration is missing, malformed, or ambiguous."""


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise PostgresConfigError(
            f"required MTMF PostgreSQL configuration variable {name} is not set; "
            "see .env.example for the MTMF_* development values; MTMF never falls "
            "back to another PostgreSQL instance"
        )
    return value


def _parse_url(value: str) -> PostgresConfig:
    parsed = urlparse(value)
    if not parsed.scheme.startswith("postgresql"):
        raise PostgresConfigError(
            "MTMF_DATABASE_URL must use a postgresql URL scheme "
            f"(got {parsed.scheme!r}); expected postgresql+psycopg://... or postgresql://..."
        )
    if parsed.hostname is None:
        raise PostgresConfigError("MTMF_DATABASE_URL is missing a host component")
    if parsed.username is None or parsed.password is None:
        raise PostgresConfigError("MTMF_DATABASE_URL must carry user:password credentials")
    database = (parsed.path or "").lstrip("/")
    if not database:
        raise PostgresConfigError("MTMF_DATABASE_URL is missing the database path component")
    port = parsed.port if parsed.port is not None else DEFAULT_PORT
    _validate_port(port)
    return PostgresConfig(
        host=parsed.hostname,
        port=port,
        database=database,
        user=parsed.username,
        password=parsed.password,
    )


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise PostgresConfigError(f"MTMF PostgreSQL port must be in 1..65535, got {port}")


@dataclass(frozen=True, slots=True)
class PostgresConfig:
    """Validated, explicit MTMF PostgreSQL connection parameters.

    Exactly one source of truth is honored: either a full URL or the
    ``MTMF_POSTGRES_*`` component variables — never both.
    """

    host: str
    port: int
    database: str
    user: str
    password: str

    @classmethod
    def from_env(cls) -> PostgresConfig:
        """Build a :class:`PostgresConfig` from explicit environment values.

        :raises PostgresConfigError: if configuration is missing,
            malformed, or ambiguous.
        """
        url_value = os.environ.get(ENV_DATABASE_URL, "").strip()
        components_set = [name for name in _COMPONENT_VARIABLES if os.environ.get(name, "").strip()]
        if url_value and components_set:
            raise PostgresConfigError(
                "MTMF PostgreSQL configuration is ambiguous: MTMF_DATABASE_URL and "
                "MTMF_POSTGRES_* component variables are both set; choose exactly one source"
            )
        if url_value:
            return _parse_url(url_value)
        raw_port = os.environ.get(ENV_PORT, "").strip() or str(DEFAULT_PORT)
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise PostgresConfigError(
                f"MTMF_POSTGRES_PORT must be an integer, got {raw_port!r}"
            ) from exc
        _validate_port(port)
        return cls(
            host=_require_env(ENV_HOST),
            port=port,
            database=_require_env(ENV_DATABASE),
            user=_require_env(ENV_USER),
            password=_require_env(ENV_PASSWORD),
        )

    @property
    def psycopg_dsn(self) -> str:
        """A psycopg connection DSN for this configuration."""
        return conninfo.make_conninfo(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password,
        )

    @property
    def sqlalchemy_url(self) -> str:
        """A ``postgresql+psycopg://`` SQLAlchemy URL for this configuration."""
        return (
            "postgresql+psycopg://"
            f"{quote(self.user, safe='')}:{quote(self.password, safe='')}"
            f"@{self.host}:{self.port}/{quote(self.database, safe='')}"
        )
