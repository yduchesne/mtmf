"""Explicit MTMF PostgreSQL connection configuration.

All MTMF database configuration comes from explicit ``MTMF_*``
environment variables. Missing, malformed, or ambiguous configuration
raises :class:`PostgresConfigError`: MTMF tooling never probes for,
discovers, or falls back to another PostgreSQL instance (including any
ATI-owned database). The port number alone is never proof of MTMF
ownership; it is only a connection parameter.

Configuration is **role-scoped** so that the deployment (migration) and
application (runtime) identities never share one credential source:

- :attr:`PostgresRole.ADMIN` reads ``MTMF_DATABASE_URL`` or the
  ``MTMF_POSTGRES_*`` components (administrator/provisioning identity);
- :attr:`PostgresRole.MIGRATOR` reads ``MTMF_MIGRATOR_DATABASE_URL`` or
  the ``MTMF_MIGRATOR_POSTGRES_*`` components (deployment-only identity);
- :attr:`PostgresRole.RUNTIME` reads ``MTMF_RUNTIME_DATABASE_URL`` or the
  ``MTMF_RUNTIME_POSTGRES_*`` components (restricted application identity).

Within one role, the full URL and the component variables are mutually
exclusive: setting both is ambiguous and fails closed. ``MTMF_POSTGRES_PORT``
defaults to :data:`DEFAULT_PORT` (a documented, collision-checked
development port); every other component is required when the URL form is
not used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import quote, urlparse

from psycopg import conninfo

ENV_DATABASE_URL = "MTMF_DATABASE_URL"
ENV_HOST = "MTMF_POSTGRES_HOST"
ENV_PORT = "MTMF_POSTGRES_PORT"
ENV_DATABASE = "MTMF_POSTGRES_DB"
ENV_USER = "MTMF_POSTGRES_USER"
ENV_PASSWORD = "MTMF_POSTGRES_PASSWORD"

_ADMIN_PREFIX = "MTMF_"
_MIGRATOR_PREFIX = "MTMF_MIGRATOR_"
_RUNTIME_PREFIX = "MTMF_RUNTIME_"

DEFAULT_PORT = 25432


class PostgresRole(StrEnum):
    """The deployment identity a :class:`PostgresConfig` describes."""

    ADMIN = "admin"
    MIGRATOR = "migrator"
    RUNTIME = "runtime"


class PostgresConfigError(ValueError):
    """Explicit MTMF PostgreSQL configuration is missing, malformed, or ambiguous."""


def _role_prefix(role: PostgresRole) -> str:
    if role is PostgresRole.ADMIN:
        return _ADMIN_PREFIX
    if role is PostgresRole.MIGRATOR:
        return _MIGRATOR_PREFIX
    return _RUNTIME_PREFIX


def _env_variables(role: PostgresRole) -> tuple[str, str, str, str, str, str]:
    """Return ``(url, host, port, db, user, password)`` variable names for a role."""
    prefix = _role_prefix(role)
    return (
        f"{prefix}DATABASE_URL",
        f"{prefix}POSTGRES_HOST",
        f"{prefix}POSTGRES_PORT",
        f"{prefix}POSTGRES_DB",
        f"{prefix}POSTGRES_USER",
        f"{prefix}POSTGRES_PASSWORD",
    )


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise PostgresConfigError(
            f"required MTMF PostgreSQL configuration variable {name} is not set; "
            "see .env.example for the MTMF_* development values; MTMF never falls "
            "back to another PostgreSQL instance"
        )
    return value


def _parse_url(value: str, role: PostgresRole) -> PostgresConfig:
    parsed = urlparse(value)
    if not parsed.scheme.startswith("postgresql"):
        raise PostgresConfigError(
            "MTMF PostgreSQL URL must use a postgresql URL scheme "
            f"(got {parsed.scheme!r}); expected postgresql+psycopg://... or postgresql://..."
        )
    if parsed.hostname is None:
        raise PostgresConfigError("MTMF PostgreSQL URL is missing a host component")
    if parsed.username is None or parsed.password is None:
        raise PostgresConfigError("MTMF PostgreSQL URL must carry user:password credentials")
    database = (parsed.path or "").lstrip("/")
    if not database:
        raise PostgresConfigError("MTMF PostgreSQL URL is missing the database path component")
    port = parsed.port if parsed.port is not None else DEFAULT_PORT
    _validate_port(port)
    return PostgresConfig(
        host=parsed.hostname,
        port=port,
        database=database,
        user=parsed.username,
        password=parsed.password,
        role=role,
    )


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise PostgresConfigError(f"MTMF PostgreSQL port must be in 1..65535, got {port}")


@dataclass(frozen=True, slots=True)
class PostgresConfig:
    """Validated, explicit MTMF PostgreSQL connection parameters.

    Exactly one source of truth is honored per role: either a full URL or
    the role-scoped ``*_POSTGRES_*`` component variables — never both.
    """

    host: str
    port: int
    database: str
    user: str
    password: str
    role: PostgresRole = PostgresRole.ADMIN

    @classmethod
    def from_env(cls, role: PostgresRole = PostgresRole.ADMIN) -> PostgresConfig:
        """Build a role-scoped :class:`PostgresConfig` from explicit environment values.

        :param role: which deployment identity to read (default: administrator).
        :raises PostgresConfigError: if configuration is missing,
            malformed, or ambiguous.
        """
        url_name, host_name, port_name, db_name, user_name, password_name = _env_variables(role)
        url_value = os.environ.get(url_name, "").strip()
        components = (host_name, port_name, db_name, user_name, password_name)
        components_set = [name for name in components if os.environ.get(name, "").strip()]
        if url_value and components_set:
            raise PostgresConfigError(
                f"MTMF PostgreSQL {role.value} configuration is ambiguous: {url_name} and "
                f"{host_name}/* component variables are both set; choose exactly one source"
            )
        if url_value:
            return _parse_url(url_value, role)
        raw_port = os.environ.get(port_name, "").strip() or str(DEFAULT_PORT)
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise PostgresConfigError(f"{port_name} must be an integer, got {raw_port!r}") from exc
        _validate_port(port)
        return cls(
            host=_require_env(host_name),
            port=port,
            database=_require_env(db_name),
            user=_require_env(user_name),
            password=_require_env(password_name),
            role=role,
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
