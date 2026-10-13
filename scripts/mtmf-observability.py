#!/usr/bin/env python3
"""Opt-in lifecycle for the MTMF-owned observability stack (PR 19).

This launcher only ever addresses the explicit ``mtmf`` Compose project
and the observability services declared in ``compose.observability.yaml``.
It never discovers, mutates, prunes, or otherwise controls resources owned
by ATI, Darkula, or another application, and it never removes volumes or
runs a broad ``down --volumes``.

Usage::

    python scripts/mtmf-observability.py up
    python scripts/mtmf-observability.py status
    python scripts/mtmf-observability.py down
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

PROJECT = "mtmf"
BASE_FILES = ("-f", "compose.yaml", "-f", "compose.dev.yaml", "-f", "compose.observability.yaml")
OBSERVABILITY_SERVICES = ("collector", "prometheus", "jaeger", "loki", "grafana")


def _compose(*args: str) -> list[str]:
    return ["podman-compose", "-p", PROJECT, *BASE_FILES, *args]


def _run(command: list[str]) -> int:
    print("+", " ".join(command))
    return subprocess.call(command)


def _require_environment() -> None:
    """Fail closed when a required development secret is absent."""
    if not os.environ.get("MTMF_GRAFANA_ADMIN_PASSWORD", "").strip():
        raise SystemExit(
            "MTMF_GRAFANA_ADMIN_PASSWORD must be set for the observability stack "
            "(development-only control; never a production secret)"
        )


def up() -> int:
    """Start the MTMF-owned observability services."""
    _require_environment()
    return _run(_compose("up", "-d", *OBSERVABILITY_SERVICES))


def status() -> int:
    """Show the status of the MTMF Compose project."""
    return _run(_compose("ps"))


def down() -> int:
    """Stop and remove only the MTMF observability services.

    The project network and all named volumes are left intact; no other
    project service and no foreign resource is touched.
    """
    return _run(_compose("rm", "-sf", *OBSERVABILITY_SERVICES))


def main(argv: list[str] | None = None) -> int:
    """Parse a subcommand and run the observability stack operation."""
    parser = argparse.ArgumentParser(description="MTMF observability stack lifecycle")
    parser.add_argument("command", choices=("up", "status", "down"))
    args = parser.parse_args(argv)
    if args.command == "up":
        return up()
    if args.command == "status":
        return status()
    return down()


if __name__ == "__main__":
    sys.exit(main())
