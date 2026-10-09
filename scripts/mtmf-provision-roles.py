#!/usr/bin/env python3
"""Administrator-invoked MTMF PostgreSQL role provisioning and verification.

Usage (from the repository root)::

    uv run python scripts/mtmf-provision-roles.py
    uv run python scripts/mtmf-provision-roles.py --adopt-existing-schema
    uv run python scripts/mtmf-provision-roles.py --verify

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

``--verify`` runs the read-only effective-privilege verification after
migration to head (role topology, database/schema/table/sequence/function
privileges, the exact runtime EXECUTE allowlist, PUBLIC function EXECUTE,
and owner default privileges). It requires a migrated schema and fails
closed when head-level object privileges are absent; it never provisions
or migrates. It may be combined with ``--adopt-existing-schema`` only when
the schema already satisfies the head privilege contract. A successful
``PostgresMigrationManager.upgrade_to_head()`` already performs this
verification automatically, so ``--verify`` is an additional operator/CI
diagnostic.
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
    verify_runtime_privileges,
)

_MIGRATOR_PASSWORD_ENV = "MTMF_MIGRATOR_POSTGRES_PASSWORD"
_RUNTIME_PASSWORD_ENV = "MTMF_RUNTIME_POSTGRES_PASSWORD"


def main() -> None:
    arguments = sys.argv[1:]
    unknown = [
        argument
        for argument in arguments
        if argument not in {"--adopt-existing-schema", "--verify"}
    ]
    if unknown:
        raise SystemExit("usage: mtmf-provision-roles.py [--adopt-existing-schema] [--verify]")
    adopt = "--adopt-existing-schema" in arguments
    verify = "--verify" in arguments
    # Provisioning is the default action; --verify alone is verification only.
    do_provision = not verify or adopt

    try:
        admin = PostgresConfig.from_env()
    except PostgresConfigError as exc:
        raise SystemExit(
            "MTMF administrator PostgreSQL configuration is missing or ambiguous; "
            "export MTMF_POSTGRES_* / MTMF_DATABASE_URL (see .env.example)"
        ) from exc

    migrator_password = ""
    runtime_password = ""
    if do_provision:
        migrator_password = os.environ.get(_MIGRATOR_PASSWORD_ENV, "").strip()
        runtime_password = os.environ.get(_RUNTIME_PASSWORD_ENV, "").strip()
        if not migrator_password or not runtime_password:
            raise SystemExit(
                f"{_MIGRATOR_PASSWORD_ENV} and {_RUNTIME_PASSWORD_ENV} must be set; "
                "provide deployment secrets through the environment, never in code"
            )

    with psycopg.connect(admin.psycopg_dsn, autocommit=True) as connection:
        if do_provision:
            provision_roles(
                connection,
                migrator_password=migrator_password,
                runtime_password=runtime_password,
            )
        if adopt:
            adopt_existing_schema(connection)
        if verify:
            verify_runtime_privileges(connection)

    actions: list[str] = []
    if do_provision:
        actions.append("provisioned MTMF roles")
    if adopt:
        actions.append("adopted existing mtmf objects")
    if verify:
        actions.append("verified runtime privileges")
    print(
        f"{' and '.join(actions)} on "
        f"{admin.host}:{admin.port}/{admin.database}; {RUNTIME_ROLE} is restricted"
    )


if __name__ == "__main__":
    main()
