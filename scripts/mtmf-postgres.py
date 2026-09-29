#!/usr/bin/env python3
"""MTMF-owned local PostgreSQL lifecycle (Podman Compose).

Usage (from the repository root)::

    uv run python scripts/mtmf-postgres.py up|stop|down|reset|status

Ownership contract (see compose.yaml and .env.example):

- Every Podman/Compose operation is explicitly scoped with
  ``--project-name mtmf`` and the repository ``compose.yaml``; the caller's
  working directory or an ambient project name is never trusted.
- If the ambient ``COMPOSE_PROJECT_NAME`` variable is set to something
  other than ``mtmf``, this script refuses to run (fail closed).
- No container is discovered by image name, generic container name, host
  port, or "first PostgreSQL" heuristics. No global Podman prunes or
  broad cleanups are ever invoked.
- ``reset`` destroys only the MTMF project's own database container and
  project-scoped volumes; it can never affect ATI resources.
- Starting, stopping, or resetting MTMF leaves ATI containers, pods,
  networks, volumes, databases, and published ports untouched.

``up`` and ``reset`` wait for PostgreSQL readiness by connecting to the
explicitly configured MTMF database (bounded retries) rather than by
sleeping or probing another PostgreSQL endpoint.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import psycopg

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "compose.yaml"
PROJECT_NAME = "mtmf"
_COMPOSE_PROJECT_ENV = "COMPOSE_PROJECT_NAME"

from mtmf_core.persistence.postgres import (  # noqa: E402  (after path setup)
    PostgresConfig,
    PostgresConfigError,
)

_READY_RETRIES = 60
_READY_INTERVAL_SECONDS = 1.0


def _project_guard() -> None:
    """Refuse to run when an ambient project name would misdirect this script."""
    ambient = os.environ.get(_COMPOSE_PROJECT_ENV, "").strip()
    if ambient and ambient != PROJECT_NAME:
        raise SystemExit(
            f"refusing to run: {_COMPOSE_PROJECT_ENV}={ambient!r} is not the canonical "
            f"MTMF project {PROJECT_NAME!r}; MTMF commands act only on MTMF-owned "
            "resources"
        )


def _compose(*arguments: str) -> None:
    command = [
        "podman",
        "compose",
        "--project-name",
        PROJECT_NAME,
        "-f",
        str(COMPOSE_FILE),
        *arguments,
    ]
    print(f"$ {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise SystemExit(
            "podman does not appear to be installed; MTMF local PostgreSQL requires "
            "Podman with the podman-compose frontend"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Podman Compose command failed with exit code {exc.returncode}") from exc


def _require_database_config() -> PostgresConfig:
    try:
        return PostgresConfig.from_env()
    except PostgresConfigError as exc:
        raise SystemExit(
            "MTMF PostgreSQL configuration is missing or ambiguous; export MTMF_* "
            "variables (see .env.example) — MTMF never falls back to another "
            "PostgreSQL instance"
        ) from exc


def _wait_until_ready(config: PostgresConfig) -> None:
    last_error: Exception | None = None
    for _attempt in range(1, _READY_RETRIES + 1):
        try:
            with psycopg.connect(config.psycopg_dsn, connect_timeout=2) as connection:
                connection.execute("SELECT 1")
            print(f"MTMF PostgreSQL is ready ({config.host}:{config.port}/{config.database})")
            return
        except psycopg.OperationalError as exc:
            last_error = exc
            time.sleep(_READY_INTERVAL_SECONDS)
    raise SystemExit(
        "MTMF PostgreSQL did not become ready after "
        f"{_READY_RETRIES * _READY_INTERVAL_SECONDS:.0f}s "
        f"({config.host}:{config.port}/{config.database}); "
        f"last error: {last_error}"
    )


def _cmd_up() -> None:
    # Validate the explicit MTMF configuration BEFORE touching any
    # container-runtime resource: a missing/ambiguous configuration must
    # fail closed with no side effects.
    _require_database_config()
    _compose("up", "-d", "postgres")
    _wait_until_ready(_require_database_config())


def _cmd_stop() -> None:
    _compose("stop", "postgres")


def _cmd_down(with_volumes: bool = False) -> None:
    if with_volumes:
        _compose("down", "-v")
    else:
        _compose("down")


def _cmd_reset() -> None:
    # Destructive, but scoped strictly to the MTMF Compose project:
    # `down -v` removes only MTMF project containers/networks and the
    # project-scoped mtmf-postgres-data volume, then the service is
    # recreated. ATI resources are outside this project and untouched.
    _compose("down", "-v")
    _cmd_up()


def _cmd_status() -> None:
    _compose("ps")


def main() -> None:
    _project_guard()
    if len(sys.argv) < 2 or sys.argv[1] not in {"up", "stop", "down", "reset", "status"}:
        raise SystemExit("usage: mtmf-postgres.py up|stop|down|reset|status")
    command = sys.argv[1]
    if command == "up":
        _cmd_up()
    elif command == "stop":
        _cmd_stop()
    elif command == "down":
        _cmd_down(with_volumes="--with-volumes" in sys.argv[2:])
    elif command == "reset":
        _cmd_reset()
    else:
        _cmd_status()


if __name__ == "__main__":
    main()
