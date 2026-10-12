#!/usr/bin/env python3
"""Portable MTMF development stack orchestration (PR 17 Amendment #1, G3).

`podman-compose 1.0.6` does not honor
`depends_on: condition: service_completed_successfully`, so it cannot order
the privileged one-shot initializer before the unprivileged HTTP service.
This development-only wrapper performs that ordering explicitly and fails
closed at every step:

    postgres + keycloak up  ->  wait for health
    ->  migrations + privilege postflight + one-shot initializer
    ->  unprivileged service up  ->  wait for readiness 200

It manages only the explicit `mtmf` Compose project and never discovers,
prunes, or mutates resources owned by another application. Privileged
credentials are consumed only by the one-shot initializer container; the
HTTP service environment never receives them (see `compose.dev.yaml`).

Usage:
    python scripts/mtmf-dev-stack.py up
    python scripts/mtmf-dev-stack.py status
    python scripts/mtmf-dev-stack.py down
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROJECT = "mtmf"
COMPOSE_FILES = ("-f", "compose.yaml", "-f", "compose.dev.yaml")
SERVICE_READY_URL = "http://127.0.0.1:28001/health/ready"
SERVICE_LIVE_URL = "http://127.0.0.1:28001/health/live"


class OrchestrationError(RuntimeError):
    """The development stack could not be brought up safely."""


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command, echoing it without environment values."""
    print(f"+ {' '.join(args)}", flush=True)
    return subprocess.run(args, cwd=REPO_ROOT, check=check, text=True)


def _compose(*args: str) -> list[str]:
    return ["podman-compose", "-p", PROJECT, *COMPOSE_FILES, *args]


def _wait_http(url: str, *, timeout: float, ca_file: str | None = None) -> None:
    """Poll ``url`` until it answers 2xx/3xx or the deadline expires."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            context = None
            if ca_file:
                import ssl

                context = ssl.create_default_context(cafile=ca_file)
            with urllib.request.urlopen(url, timeout=2, context=context) as response:
                if 200 <= response.status < 400:
                    return
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = exc
        time.sleep(1.0)
    raise OrchestrationError(f"timed out waiting for {url}: {last_error}")


def _require_development() -> None:
    mode = os.environ.get("MTMF_SERVICE_DEPLOYMENT_MODE", "development").strip()
    if mode != "development":
        raise OrchestrationError(
            "the development stack launcher refuses any non-development profile"
        )


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise OrchestrationError(f"required environment {name} is not set")
    return value


def _postgres_inspect() -> None:
    """Require the MTMF PostgreSQL healthcheck to report healthy."""
    # Container name is project-scoped and deterministic for project `mtmf`.
    result = _run(
        ["podman", "inspect", "--format", "{{.State.Health.Status}}", "mtmf_postgres_1"],
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "healthy":
        raise OrchestrationError("the MTMF PostgreSQL container is not healthy")


def up() -> int:
    """Bring up the development stack in the required order."""
    _require_development()
    _required_env("MTMF_MIGRATOR_DATABASE_URL")
    _required_env("MTMF_RUNTIME_DATABASE_URL")
    _required_env("MTMF_AUTH_ISSUER")

    _run(_compose("up", "-d", "postgres", "keycloak"))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            _postgres_inspect()
            break
        except OrchestrationError:
            time.sleep(2.0)
    else:
        raise OrchestrationError("PostgreSQL did not become healthy within 180s")
    _wait_http(
        f"{_required_env('MTMF_AUTH_ADMIN_BASE').rstrip('/')}/realms/master/.well-known/"
        "openid-configuration",
        timeout=180,
        ca_file=os.environ.get("MTMF_PR14_KC_CA_FILE") or None,
    )

    # Privileged one-shot: migrations + postflight + fixture reconciliation.
    _run(_compose("run", "--rm", "--no-deps", "initializer"))

    # Unprivileged HTTP service, only after a successful initializer exit.
    _run(_compose("up", "-d", "service"))
    _wait_http(SERVICE_READY_URL, timeout=120)
    print("MTMF development stack is ready", flush=True)
    return 0


def status() -> int:
    """Print project-scoped container status and liveness/readiness."""
    _run(_compose("ps"), check=False)
    for label, url in (("live", SERVICE_LIVE_URL), ("ready", SERVICE_READY_URL)):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                print(f"{label}: {response.status}")
        except (urllib.error.URLError, OSError) as exc:
            print(f"{label}: unavailable ({exc})")
    return 0


def down() -> int:
    """Stop the MTMF-owned development stack (volumes preserved)."""
    _run(_compose("down"))
    return 0


def down_volumes() -> int:
    """Destroy only MTMF-owned development resources and volumes."""
    _run(_compose("down", "-v"))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse a subcommand and run the development stack operation."""
    parser = argparse.ArgumentParser(description="MTMF development stack orchestrator")
    parser.add_argument("command", choices=("up", "status", "down", "destroy"))
    args = parser.parse_args(argv)
    try:
        if args.command == "up":
            return up()
        if args.command == "status":
            return status()
        if args.command == "down":
            return down()
        return down_volumes()
    except (OrchestrationError, subprocess.CalledProcessError) as exc:
        print(f"development stack error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
