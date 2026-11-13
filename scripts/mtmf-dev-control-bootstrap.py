#!/usr/bin/env python3
"""One-shot, opt-in PR 24P development SYSTEM operator fixture installer."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import uuid
from pathlib import Path
from types import ModuleType

import psycopg

from mtmf_core.persistence.postgres import PostgresConfig, PostgresRole
from mtmf_service.development_bootstrap import BootstrapError
from mtmf_service.development_user import DevUserConfig, KeycloakDevUserProvisioner

ROLE = "urn:mtmf:iam:roles:system:application-administrator"
SOURCE = "dev-fixture:mtmf:pr24p:system-operator:v1"
APPROVAL = "MTMF-PR24P-GATE-B-2026-11-13-01"
OPERATOR = "mtmf-dev-operator"
ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
NAMESPACE = uuid.UUID("6f2c1f0e-6f4f-4b64-9b5e-2f6d1f2a4c17")


def _deterministic(name: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, name)


def _keycloak_modules() -> ModuleType:
    path = Path(__file__).with_name("mtmf-dev-initialize.py")
    spec = importlib.util.spec_from_file_location("mtmf_dev_initialize", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the existing development initializer module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _preflight() -> None:
    flag = os.environ.get("MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED")
    if flag not in {"true", "false", None}:
        raise SystemExit("MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED must be true/false/unset")
    if flag != "true":
        raise SystemExit("operator fixture apply requires MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true")
    if os.environ.get("MTMF_SERVICE_DEPLOYMENT_MODE") != "development":
        raise SystemExit("operator fixture is development-only")
    if os.environ.get("COMPOSE_PROJECT_NAME", "mtmf") != "mtmf":
        raise SystemExit("operator fixture requires the mtmf project")
    if os.environ.get("MTMF_AUTH_ISSUER") != ISSUER:
        raise SystemExit("operator fixture requires the canonical development issuer")
    if os.environ.get("MTMF_DEV_USER_USERNAME") == OPERATOR:
        raise SystemExit("the operator username must differ from the ordinary development user")


def _config() -> PostgresConfig:
    return PostgresConfig.from_env(PostgresRole.MIGRATOR)


def _owner_query(
    config: PostgresConfig, sql: str, params: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    with psycopg.connect(config.psycopg_dsn) as connection:
        connection.execute("SET LOCAL ROLE mtmf_owner")
        return connection.execute(sql, params).fetchall()


def _classify(subject: str | None) -> str:
    config = _config()
    principal_id = _deterministic(f"pr24p:dev-operator:principal:{subject}") if subject else None
    identity_id = _deterministic(f"pr24p:dev-operator:identity:{subject}") if subject else None
    assignment_id = (
        _deterministic(f"pr24p:dev-operator:system-assignment:{subject}") if subject else None
    )
    rows = _owner_query(config, "SELECT 1 FROM mtmf.principal WHERE id = %s", (principal_id,))
    has_principal = bool(rows)
    rows = _owner_query(config, "SELECT 1 FROM mtmf.identity WHERE id = %s", (identity_id,))
    has_identity = bool(rows)
    rows = _owner_query(
        config, "SELECT 1 FROM mtmf.system_operator_assignment WHERE id = %s", (assignment_id,)
    )
    has_assignment = bool(rows)
    if not any((has_principal, has_identity, has_assignment)):
        return "ABSENT"
    if has_principal and has_identity and has_assignment:
        return "COMPLETE"
    return "PARTIAL"


def _apply(subject: str) -> str:
    config = _config()
    principal_id = _deterministic(f"pr24p:dev-operator:principal:{subject}")
    identity_id = _deterministic(f"pr24p:dev-operator:identity:{subject}")
    binding_id = _deterministic(f"pr24p:dev-operator:binding:{subject}")
    assignment_id = _deterministic(f"pr24p:dev-operator:system-assignment:{subject}")
    correlation_id = _deterministic(f"pr24p:dev-operator:installation-correlation:{subject}")
    with psycopg.connect(config.psycopg_dsn) as connection:
        connection.execute("SET LOCAL ROLE mtmf_owner")
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('mtmf.pr24p.dev-fixture', 0))"
        )
        created = False
        if not connection.execute(
            "SELECT count(*) FROM mtmf.system_operator_assignment WHERE id = %s", (assignment_id,)
        ).fetchone()[0]:
            created = True
            if connection.execute(
                "SELECT count(*) FROM mtmf.external_subject_identity "
                "WHERE issuer = %s AND subject = %s",
                (ISSUER, subject),
            ).fetchone()[0]:
                raise SystemExit("STOP-PARTIAL: subject binding already exists without fixture")
            connection.execute(
                "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, %s, 2)",
                (principal_id, "MTMF Development SYSTEM Operator"),
            )
            connection.execute(
                "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
                "VALUES (%s, %s, %s, 2, 2)",
                (identity_id, principal_id, "MTMF Development SYSTEM Operator Identity"),
            )
            connection.execute(
                "INSERT INTO mtmf.external_subject_identity "
                "(id, issuer, subject, identity_id, lifecycle, created_at) "
                "VALUES (%s, %s, %s, %s, 1, now())",
                (binding_id, ISSUER, subject, identity_id),
            )
            connection.execute(
                "INSERT INTO mtmf.system_operator_assignment "
                "(id, identity_id, principal_id, role_urn, state, created_at, revoked_at, "
                " approved_by, approval_correlation_id, source_label) "
                "VALUES (%s, %s, %s, %s, 1, now(), NULL, %s, %s, %s)",
                (assignment_id, identity_id, principal_id, ROLE, APPROVAL, correlation_id, SOURCE),
            )
            connection.execute(
                "INSERT INTO mtmf.system_operator_assignment_event "
                "(id, assignment_id, operator_identity_id, operator_principal_id, role_urn, "
                " event_type, occurred_at, approved_by, approval_correlation_id, source_label) "
                "VALUES (%s, %s, %s, %s, %s, 1, now(), %s, %s, %s)",
                (
                    correlation_id,
                    assignment_id,
                    identity_id,
                    principal_id,
                    ROLE,
                    APPROVAL,
                    correlation_id,
                    SOURCE,
                ),
            )
        exact = connection.execute(
            "SELECT count(*) FROM mtmf.system_operator_assignment "
            "WHERE id = %s AND identity_id = %s AND principal_id = %s AND role_urn = %s "
            "AND state = 1 AND approved_by = %s AND source_label = %s",
            (assignment_id, identity_id, principal_id, ROLE, APPROVAL, SOURCE),
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT count(*) FROM mtmf.system_operator_assignment_event WHERE assignment_id = %s",
            (assignment_id,),
        ).fetchone()[0]
        if exact != 1 or event_count != 1:
            raise SystemExit("STOP-PARTIAL: operator fixture is not exact")
        return "CREATED" if created else "EXISTING"


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.inspect == args.apply:
        raise SystemExit("choose exactly one of --inspect or --apply")
    _preflight()
    module = _keycloak_modules()
    credentials = module.KeycloakCredentialProvisioner(
        base_url=os.environ.get("MTMF_AUTH_ADMIN_BASE", "").rstrip("/"),
        realm="mtmf-dev",
        admin_username=os.environ.get("MTMF_AUTH_ADMIN_USERNAME", ""),
        admin_password=os.environ.get("MTMF_AUTH_ADMIN_PASSWORD", ""),
    )
    credentials.preflight_issuer(ISSUER)
    provisioner = KeycloakDevUserProvisioner(
        credentials, credentials.realm, admin_base_url=credentials.base_url
    )
    config = DevUserConfig(
        username=OPERATOR,
        email=None,
        create=args.apply,
        password_file=Path(
            os.environ.get(
                "MTMF_DEV_OPERATOR_PASSWORD_FILE",
                "/run/mtmf-operator-install/dev-operator-password",
            )
        ),
        expected_subject=None,
    )
    try:
        subject = provisioner.ensure_user(config)
    except BootstrapError as exc:
        raise SystemExit(f"STOP-AUTH-FIXTURE: {exc}") from exc
    state = _classify(subject)
    if args.inspect:
        print(f"operator fixture state={state}")
        return 0
    if state == "PARTIAL":
        raise SystemExit("STOP-PARTIAL")
    if state == "COMPLETE":
        print("operator fixture EXISTING (verify-only)")
        return 0
    print(f"operator fixture {_apply(subject)}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
