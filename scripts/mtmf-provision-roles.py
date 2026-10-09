#!/usr/bin/env python3
"""Administrator-invoked MTMF PostgreSQL role provisioning.

Usage (from the repository root)::

    uv run python scripts/mtmf-provision-roles.py
    uv run python scripts/mtmf-provision-roles.py --adopt-existing-schema

This is the only supported way to create the cluster-wide MTMF roles. It is
idempotent and safe to re-run. It connects with the administrator identity
(``MTMF_POSTGRES_*`` / ``MTMF_DATABASE_URL``) and never logs a DSN or a
password.

- ``mtmf_owner``      NOLOGIN; owns the ``mtmf`` schema and objects.
- ``mtmf_migrator``   LOGIN; may ``SET ROLE mtmf_owner`` (INHERIT FALSE).
- ``mtmf_runtime``    LOGIN; restricted application identity.

``--adopt-existing-schema`` additionally performs the one-time
administrator ownership handoff for a database whose ``mtmf`` objects were
created by an older trusted login. It only touches objects inside the
``mtmf`` schema.
"""

from __future__ import annotations

import os
import sys

import psycopg

from mtmf_core.persistence.postgres import PostgresConfig, PostgresConfigError
from mtmf_core.persistence.postgres.roles import (
    RUNTIME_ROLE,
    adopt_existing_schema,
    provision_roles,
)

_MIGRATOR_PASSWORD_ENV = "MTMF_MIGRATOR_POSTGRES_PASSWORD"
_RUNTIME_PASSWORD_ENV = "MTMF_RUNTIME_POSTGRES_PASSWORD"


def main() -> None:
    adopt = "--adopt-existing-schema" in sys.argv[1:]
    unknown = [arg for arg in sys.argv[1:] if arg != "--adopt-existing-schema"]
    if unknown:
        raise SystemExit("usage: mtmf-provision-roles.py [--adopt-existing-schema]")

    try:
        admin = PostgresConfig.from_env()
    except PostgresConfigError as exc:
        raise SystemExit(
            "MTMF administrator PostgreSQL configuration is missing or ambiguous; "
            "export MTMF_POSTGRES_* / MTMF_DATABASE_URL (see .env.example)"
        ) from exc

    migrator_password = os.environ.get(_MIGRATOR_PASSWORD_ENV, "").strip()
    runtime_password = os.environ.get(_RUNTIME_PASSWORD_ENV, "").strip()
    if not migrator_password or not runtime_password:
        raise SystemExit(
            f"{_MIGRATOR_PASSWORD_ENV} and {_RUNTIME_PASSWORD_ENV} must be set; "
            "provide deployment secrets through the environment, never in code"
        )

    with psycopg.connect(admin.psycopg_dsn, autocommit=True) as connection:
        provision_roles(
            connection,
            migrator_password=migrator_password,
            runtime_password=runtime_password,
        )
        if adopt:
            adopt_existing_schema(connection)

    action = "provisioned MTMF roles" + (" and adopted existing mtmf objects" if adopt else "")
    print(f"{action} on {admin.host}:{admin.port}/{admin.database}; {RUNTIME_ROLE} is restricted")


if __name__ == "__main__":
    main()
