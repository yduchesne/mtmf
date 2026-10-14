#!/usr/bin/env python3
"""Privileged, one-shot PR 20A reference-consumer fixture initializer.

This is a narrow PR 20A adapter over the existing reviewed development
initializer. It reuses the same sanctioned primitives and the same Keycloak
Admin REST provisioning logic; it adds only:

- verification of a second, deliberately unprivileged Keycloak user;
- registration of the fixture-only document-read Action and TENANT-defined
  Role grant;
- the non-secret subject-to-Tenant fixture mapping consumed by the reference
  app.

It holds owner/migrator and issuer-admin credentials, is never imported by the
reference app, and adds no new schema, migration, generic management API, or
runtime DB grant. It refuses any profile other than ``development``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pr20a_reference_fixture as fixture

from mtmf_core.persistence.postgres import PostgresConfig, PostgresRole
from mtmf_service.development_bootstrap import (
    ApplicationFixture,
    BootstrapError,
    BootstrapFixture,
    TenantFixture,
    UserFixture,
)
from mtmf_service.development_user import DevUserConfig, KeycloakDevUserProvisioner
from mtmf_service.settings import DeploymentMode, ServiceSettings

_DEV_INITIALIZER = Path(__file__).resolve().parent / "mtmf-dev-initialize.py"


def _load_dev_initializer() -> object:
    """Load the hyphenated development initializer as a module."""
    spec = importlib.util.spec_from_file_location("pr20a_dev_initialize", _DEV_INITIALIZER)
    if spec is None or spec.loader is None:
        raise BootstrapError("the development initializer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr20a_dev_initialize"] = module
    spec.loader.exec_module(module)
    return module


dev = _load_dev_initializer()


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or not value.strip():
        raise BootstrapError(f"{name} is required")
    return value.strip()


def _ensure_secondary_user(
    provisioner: object,
    fixture_manifest: BootstrapFixture,
    *,
    subject: str,
    principal_name: str,
    identity_name: str,
) -> str:
    """Create or validate a second ordinary user without any Role grant."""
    tenant_id = dev._deterministic(f"tenant:{fixture_manifest.tenant.key}")
    principal_id = dev._deterministic(f"user-principal:{subject}")
    identity_id = dev._deterministic(f"user-identity:{subject}")
    empty = json.dumps({})
    if provisioner._scalar("SELECT 1 FROM mtmf.principal WHERE id = %s", (principal_id,)) is None:
        provisioner._execute(
            "SELECT mtmf.principal_add(%s, %s, %s, %s::jsonb)",
            (principal_id, principal_name, int(dev.DeletionStatus.NOT_DELETED), empty),
        )
    if provisioner._scalar("SELECT 1 FROM mtmf.identity WHERE id = %s", (identity_id,)) is None:
        provisioner._execute(
            "SELECT mtmf.identity_add(%s, %s, %s, %s, %s, %s::jsonb)",
            (
                identity_id,
                principal_id,
                identity_name,
                int(dev.IdentityOrigin.FEDERATED),
                int(dev.DeletionStatus.NOT_DELETED),
                empty,
            ),
        )
    if (
        provisioner._scalar(
            "SELECT 1 FROM mtmf.principal_tenant_membership WHERE principal_id = %s "
            "AND tenant_id = %s",
            (principal_id, tenant_id),
        )
        is None
    ):
        provisioner._execute(
            "SELECT mtmf.principal_tenant_membership_add(%s, %s)", (principal_id, tenant_id)
        )
    if (
        provisioner._scalar(
            "SELECT 1 FROM mtmf.identity_tenant_membership WHERE identity_id = %s "
            "AND tenant_id = %s",
            (identity_id, tenant_id),
        )
        is None
    ):
        provisioner._execute(
            "SELECT mtmf.identity_tenant_membership_add(%s, %s)", (identity_id, tenant_id)
        )
    binding_id = dev._deterministic(f"user-binding:{subject}")
    existing = provisioner._scalar(
        "SELECT identity_id FROM mtmf.external_subject_identity "
        "WHERE issuer = %s AND subject = %s AND lifecycle = %s",
        (fixture_manifest.issuer, subject, int(dev.BindingLifecycle.ACTIVE)),
    )
    if existing is None:
        provisioner._execute(
            "SELECT mtmf.external_subject_identity_add(%s, %s, %s, %s, %s, %s)",
            (
                binding_id,
                fixture_manifest.issuer,
                subject,
                identity_id,
                int(dev.BindingLifecycle.ACTIVE),
                datetime.now(UTC),
            ),
        )
    elif str(existing) != str(identity_id):
        raise BootstrapError("the secondary user binding conflicts with existing state")
    return str(identity_id)


def main(argv: list[str] | None = None) -> int:
    """Run the privileged PR 20A fixture initialization once."""
    parser = argparse.ArgumentParser(description="MTMF PR 20A fixture initializer")
    parser.add_argument(
        "--write-only",
        action="store_true",
        help="only write the non-secret fixture mapping from existing state",
    )
    args = parser.parse_args(argv)
    settings = ServiceSettings.from_env()
    if settings.deployment_mode is not DeploymentMode.DEVELOPMENT:
        print("refusing: the PR 20A initializer requires the development profile")
        return 2
    issuer = _env("MTMF_AUTH_ISSUER").rstrip("/")
    realm = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
    allowed_username = os.environ.get("MTMF_PR20A_ALLOWED_USERNAME", "mtmf-user-alice")
    denied_username = os.environ.get("MTMF_PR20A_DENIED_USERNAME", "mtmf-user-bob")
    application_key = os.environ.get("MTMF_PR20A_APPLICATION_KEY", fixture.DEFAULT_APPLICATION_KEY)
    fixture_dir = Path(_env("MTMF_PR20A_FIXTURE_DIR"))
    try:
        dev._require_realm_matches_issuer(issuer, realm)
    except BootstrapError as exc:
        print(f"initialization failed: {exc}", file=sys.stderr)
        return 1
    credentials = dev.KeycloakCredentialProvisioner(
        base_url=_env("MTMF_AUTH_ADMIN_BASE").rstrip("/"),
        realm=realm,
        admin_username=_env("MTMF_AUTH_ADMIN_USERNAME"),
        admin_password=_env("MTMF_AUTH_ADMIN_PASSWORD"),
    )
    provisioner = dev.PostgresProvisioner(PostgresConfig.from_env(PostgresRole.MIGRATOR))
    try:
        credentials.preflight_issuer(issuer)
        user_provisioner = KeycloakDevUserProvisioner(
            credentials, realm, admin_base_url=credentials.base_url
        )
        allowed_subject = user_provisioner.ensure_user(_read_only_user(allowed_username))
        denied_subject = user_provisioner.ensure_user(_read_only_user(denied_username))
        fixture_manifest = _build_fixture(
            issuer=issuer,
            realm=realm,
            application_key=application_key,
            allowed_subject=allowed_subject,
        )
        if not args.write_only:
            _provision(
                provisioner,
                credentials,
                fixture_manifest,
                application_key=application_key,
                denied_subject=denied_subject,
            )
            _handoff_reference_secret_ownership(
                secret_dir=Path(os.environ.get("MTMF_DEV_SECRET_DIR", "/run/mtmf-secrets")),
                client_id=f"mtmf-{application_key}",
                uid=int(os.environ.get("MTMF_PR20A_REFERENCE_APP_UID", "10001")),
            )
        tenant_id = dev._deterministic(f"tenant:{fixture_manifest.tenant.key}")
        fixture.write_fixture_mapping(
            fixture_dir / "reference-app-fixture.json",
            application_id_value=fixture.application_id(application_key),
            tenant_id=tenant_id,
            subjects={
                allowed_subject: tenant_id,
                denied_subject: tenant_id,
            },
        )
    except BootstrapError as exc:
        print(f"initialization failed: {exc}", file=sys.stderr)
        return 1
    except fixture.ReferenceFixtureError as exc:
        print(f"initialization failed: {exc}", file=sys.stderr)
        return 1
    print(
        "PR 20A reference fixture initialized: "
        f"application_id={fixture.application_id(application_key)} "
        f"tenant_id={tenant_id} allowed={allowed_subject} denied={denied_subject}"
    )
    return 0


def _read_only_user(username: str) -> DevUserConfig:
    """Build a read-only user config (the realm setup owns creation)."""
    return DevUserConfig(
        username=username,
        email=None,
        create=False,
        password_file=None,
        expected_subject=None,
    )


def _handoff_reference_secret_ownership(*, secret_dir: Path, client_id: str, uid: int) -> None:
    """Hand the delivered client secret to the unprivileged reference-app user.

    The secret stays mode 0600 and is never made group/other readable; only its
    owner is changed to the reference app's in-container UID so the app can read
    it without running as root.
    """
    target = secret_dir / f"{client_id}.secret"
    if not target.is_file():
        raise BootstrapError("the reference client secret was not delivered")
    os.chown(target, uid, uid)
    os.chmod(target, 0o600)


def _build_fixture(
    *,
    issuer: str,
    realm: str,
    application_key: str,
    allowed_subject: str,
) -> BootstrapFixture:
    # The reference PEP binds to ``application_key``. The canonical approved
    # Application ``sample-app`` is additionally registered (with no reference
    # consumer) because the reviewed realm attestation attests *every* approved
    # client, and the shared initializer is the sanctioned mechanism that
    # creates an approved client. No client is created outside the approved
    # expected-client policy.
    application_keys = (application_key, "sample-app")
    return BootstrapFixture(
        tenant=TenantFixture(
            key=os.environ.get("MTMF_DEV_TENANT_KEY", "dev"),
            name=os.environ.get("MTMF_DEV_TENANT_NAME", "Development Tenant"),
            principal_name="Development Tenant Principal",
            identity_name="Development Tenant Steward Identity",
        ),
        user=UserFixture(
            subject=allowed_subject,
            principal_name="Reference Allowed User Principal",
            identity_name="Reference Allowed User Identity",
        ),
        applications=tuple(ApplicationFixture(key, key) for key in dict.fromkeys(application_keys)),
        issuer=issuer,
        service_audience=_env("MTMF_AUTH_SERVICE_AUDIENCE"),
        user_audience=_env("MTMF_AUTH_USER_AUDIENCE"),
        realm=realm,
    )


def _provision(
    provisioner: object,
    credentials: object,
    fixture_manifest: BootstrapFixture,
    *,
    application_key: str,
    denied_subject: str,
) -> None:
    """Run the privileged provisioning sequence under one owner connection."""
    provisioner.apply_migrations_and_verify()
    provisioner.acquire()
    try:
        provisioner.ensure_root(fixture_manifest)
        provisioner.ensure_ordinary_tenant(fixture_manifest)
        provisioner.ensure_user_binding(fixture_manifest)
        _ensure_secondary_user(
            provisioner,
            fixture_manifest,
            subject=denied_subject,
            principal_name="Reference Denied User Principal",
            identity_name="Reference Denied User Identity",
        )
        for application in fixture_manifest.applications:
            provisioner.ensure_application(fixture_manifest, application)
            client_id = credentials.ensure_client(fixture_manifest, application)
            provisioner.ensure_service_binding(fixture_manifest, application, client_id=client_id)
            provisioner.ensure_registration_and_subscription(fixture_manifest, application)
        tenant_id = dev._deterministic(f"tenant:{fixture_manifest.tenant.key}")
        allowed_identity_id = dev._deterministic(f"user-identity:{fixture_manifest.user.subject}")
        fixture.ensure_document_read_action(provisioner)
        fixture.ensure_document_role(provisioner, tenant_id)
        fixture.ensure_document_role_assignment(provisioner, tenant_id, allowed_identity_id)
        credentials.verify_issuer(fixture_manifest)
    finally:
        provisioner.release()


if __name__ == "__main__":
    sys.exit(main())
