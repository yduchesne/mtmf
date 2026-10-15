#!/usr/bin/env python3
"""PR 20B privileged, acceptance-only fixture lifecycle transitions.

This helper exists solely for the PR 20B isolated acceptance harness. It runs
one-shot, refuses any profile other than ``development``, connects only as the
authenticated ``mtmf_migrator`` identity (never ``mtmf_runtime``), and mutates
fixture state **only** through the existing reviewed stored functions:

- ``mtmf.suspend_tenant(uuid)`` / ``mtmf.activate_tenant(uuid)``
- ``mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)``
- ``mtmf.identity_role_assignment_remove(uuid)`` /
  ``mtmf.identity_role_assignment_add(uuid, uuid, uuid, text, uuid)``

There is **no** raw table write, ``UPDATE``, or ``DELETE``. The helper verifies
the connected database name against the explicitly configured acceptance
database before any mutation, prints only non-secret identifiers, and is never
imported by the reference application.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

_DEV_INITIALIZER = _SCRIPTS / "mtmf-dev-initialize.py"


class TransitionError(RuntimeError):
    """A bounded acceptance fixture-transition failure; never contains a secret."""


def _load_dev_initializer() -> Any:
    """Load the hyphenated development initializer as a module."""
    spec = importlib.util.spec_from_file_location("pr20b_dev_initialize", _DEV_INITIALIZER)
    if spec is None or spec.loader is None:
        raise TransitionError("the development initializer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr20b_dev_initialize"] = module
    spec.loader.exec_module(module)
    return module


dev = _load_dev_initializer()

# Numeric subscription lifecycle values read from the authoritative enum.
_SUBSCRIPTION_ACTIVE = 1
_SUBSCRIPTION_SUSPENDED = 2


def _expected_database() -> str:
    """Return the explicitly configured acceptance database name, or fail closed."""
    value = os.environ.get("MTMF_PR20B_ACCEPTANCE_DB", "").strip()
    if not value:
        raise TransitionError(
            "MTMF_PR20B_ACCEPTANCE_DB must name the isolated acceptance database; "
            "refusing to mutate an unidentified database"
        )
    return value


def _require_development() -> None:
    """Refuse any profile other than the development acceptance profile."""
    from mtmf_service.settings import DeploymentMode, ServiceSettings

    if ServiceSettings.from_env().deployment_mode is not DeploymentMode.DEVELOPMENT:
        raise TransitionError("the PR 20B transitions helper requires the development profile")


def _fixture_ids(tenant_key: str, subject: str) -> dict[str, UUID]:
    """Return the deterministic fixture Tenant / Identity / assignment ids."""
    tenant_id = dev._deterministic(f"tenant:{tenant_key}")
    identity_id = dev._deterministic(f"user-identity:{subject}")
    assignment_id = dev._deterministic(f"reference-document-assignment:{tenant_id}:{identity_id}")
    return {
        "tenant_id": tenant_id,
        "identity_id": identity_id,
        "assignment_id": assignment_id,
    }


def _role_urn(tenant_id: UUID) -> str:
    return f"urn:mtmf:iam:roles:tenant:{tenant_id}:reference-document-reader"


def _subscription_id(tenant_key: str, application_key: str) -> UUID:
    del tenant_key
    return dev._deterministic(f"subscription:{application_key}")


def _open(args: argparse.Namespace) -> Any:
    """Open the privileged migrator provisioner and verify database identity."""
    from mtmf_core.persistence.postgres import PostgresConfig, PostgresRole

    provisioner = dev.PostgresProvisioner(PostgresConfig.from_env(PostgresRole.MIGRATOR))
    provisioner.acquire()
    try:
        actual = provisioner._scalar("SELECT current_database()", ())
        if str(actual) != _expected_database():
            raise TransitionError(
                "the connected database is not the configured acceptance database"
            )
        schema = provisioner._scalar("SELECT mtmf.mtf_schema_version()", ())
        if str(schema) == "":
            raise TransitionError("the acceptance database schema is not initialized")
    except BaseException:
        provisioner.release()
        raise
    return provisioner


def _state(provisioner: Any, args: argparse.Namespace) -> dict[str, Any]:
    ids = _fixture_ids(args.tenant_key, args.subject)
    tenant_lifecycle = provisioner._scalar(
        "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (ids["tenant_id"],)
    )
    subscription_lifecycle = provisioner._scalar(
        "SELECT lifecycle FROM mtmf.tenant_application_subscription WHERE id = %s",
        (_subscription_id(args.tenant_key, args.application_key),),
    )
    assignment_present = (
        provisioner._scalar(
            "SELECT 1 FROM mtmf.identity_role_assignment WHERE id = %s",
            (ids["assignment_id"],),
        )
        is not None
    )
    return {
        "tenant_lifecycle": tenant_lifecycle,
        "subscription_lifecycle": subscription_lifecycle,
        "role_assignment_present": assignment_present,
        "tenant_id": str(ids["tenant_id"]),
        "identity_id": str(ids["identity_id"]),
        "assignment_id": str(ids["assignment_id"]),
    }


def _dispatch(provisioner: Any, args: argparse.Namespace) -> dict[str, Any]:
    ids = _fixture_ids(args.tenant_key, args.subject)
    if args.command == "state":
        return _state(provisioner, args)
    if args.command == "suspend-tenant":
        provisioner._execute("SELECT mtmf.suspend_tenant(%s)", (ids["tenant_id"],))
    elif args.command == "activate-tenant":
        provisioner._execute("SELECT mtmf.activate_tenant(%s)", (ids["tenant_id"],))
    elif args.command == "unsubscribe":
        provisioner._execute(
            "SELECT mtmf.tenant_application_subscription_save(%s, %s, NULL)",
            (_subscription_id(args.tenant_key, args.application_key), _SUBSCRIPTION_SUSPENDED),
        )
    elif args.command == "subscribe":
        provisioner._execute(
            "SELECT mtmf.tenant_application_subscription_save(%s, %s, NULL)",
            (_subscription_id(args.tenant_key, args.application_key), _SUBSCRIPTION_ACTIVE),
        )
    elif args.command == "revoke-role":
        provisioner._execute(
            "SELECT mtmf.identity_role_assignment_remove(%s)", (ids["assignment_id"],)
        )
    elif args.command == "grant-role":
        provisioner._execute(
            "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, NULL)",
            (
                ids["assignment_id"],
                ids["tenant_id"],
                ids["identity_id"],
                _role_urn(ids["tenant_id"]),
            ),
        )
    else:  # pragma: no cover - argparse constrains the choices
        raise TransitionError(f"unknown transition command {args.command!r}")
    return _state(provisioner, args)


def main(argv: list[str] | None = None) -> int:
    """Run exactly one acceptance-only fixture transition."""
    parser = argparse.ArgumentParser(description="PR 20B acceptance fixture transitions")
    parser.add_argument(
        "command",
        choices=(
            "state",
            "suspend-tenant",
            "activate-tenant",
            "unsubscribe",
            "subscribe",
            "revoke-role",
            "grant-role",
        ),
    )
    parser.add_argument("--subject", required=True, help="the allowed user's verified subject")
    parser.add_argument("--tenant-key", default="dev")
    parser.add_argument("--application-key", default="evidence-same-client")
    args = parser.parse_args(argv)
    try:
        _require_development()
        _expected_database()
        provisioner = _open(args)
        try:
            state = _dispatch(provisioner, args)
        finally:
            provisioner.release()
    except TransitionError as exc:
        print(f"transition error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
