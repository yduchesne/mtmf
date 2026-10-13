#!/usr/bin/env python3
"""Privileged, opt-in, idempotent MTMF development initializer (PR 17).

This one-shot process is the *only* place that holds migration/owner and
development-issuer admin credentials. It is never imported by the HTTP
runtime, never runs as a service startup hook, and refuses any profile
other than ``development``.

It invokes only the existing sanctioned primitives:

- the PR 7 ``PostgresMigrationManager.upgrade_to_head`` (with the mandatory
  runtime-privilege postflight);
- the PR 10 ``bootstrap_root`` / ``designate_steward`` / ``activate_tenant``
  installation functions;
- the PR 4/5/6 entity, membership and Role-assignment functions;
- the PR 13 ``application_*`` / ``tenant_application_subscription_*``
  operator functions;
- the PR 14 ``service_credential_application_add`` /
  ``external_subject_identity_add`` operator functions.

No new schema, migration, stored function, or privileged runtime grant is
introduced. A conflict with existing privileged state fails closed and
requires operator remediation; no root recovery or secret rotation happens
here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

from mtmf_core.authentication.contracts import IssuerProfile
from mtmf_core.domain.authentication_binding import BindingLifecycle
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    DeletionStatus,
    IdentityOrigin,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantLifecycle,
)
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMigrationManager,
    PostgresRole,
)
from mtmf_service.authentication.attestation import (
    BaselineConfigurationAttestor,
    ExpectedClientPolicy,
    ExpectedClientPolicyError,
    canonical_client_projection,
)
from mtmf_service.development_bootstrap import (
    ApplicationFixture,
    BootstrapError,
    BootstrapFixture,
    DevelopmentBootstrap,
    TenantFixture,
    UserFixture,
)
from mtmf_service.development_user import DevUserConfig, KeycloakDevUserProvisioner
from mtmf_service.settings import DeploymentMode, ServiceSettings

#: Stable, non-secret fixture namespace for deterministic UUIDv5 identities.
_FIXTURE_NAMESPACE = uuid.UUID("6f2c1f0e-6f4f-4b64-9b5e-2f6d1f2a4c17")

#: Upper bound for any single Keycloak Admin REST response body.
_MAX_RESPONSE_BYTES = 1024 * 1024

TENANT_ADMIN_ROLE_URN = "urn:mtmf:iam:roles:system:tenant-administrator"


def _deterministic(name: str) -> uuid.UUID:
    """Derive a stable fixture UUID from a non-secret manifest name."""
    return uuid.uuid5(_FIXTURE_NAMESPACE, name)


#: Test-only inter-system failpoint selector. It is read exclusively by this
#: privileged initializer, is inert unless explicitly set, and is never part
#: of the HTTP service environment. The live PR 17-B acceptance harness sets
#: it to ``after-user-verify`` to terminate after the Keycloak user is
#: verified and before any MTMF bootstrap write (I13).
TEST_FAILPOINT_ENV = "MTMF_DEV_TEST_FAILPOINT"


def _reach_test_failpoint(name: str) -> None:
    """Terminate deterministically at a test-only orchestration boundary."""
    if os.environ.get(TEST_FAILPOINT_ENV, "").strip() == name:
        print(f"test failpoint reached: {name}", file=sys.stderr)
        raise SystemExit(99)


class PostgresProvisioner:
    """Privileged PostgreSQL provisioner using only sanctioned primitives."""

    def __init__(self, migrator_config: PostgresConfig) -> None:
        self._config = migrator_config
        self._connection: psycopg.Connection[Any] | None = None

    # -- lifecycle ---------------------------------------------------------
    def apply_migrations_and_verify(self) -> None:
        """Migrate to head under the migrator identity with postflight."""
        PostgresMigrationManager(self._config).upgrade_to_head()

    def acquire(self) -> None:
        """Open the privileged connection, assume the owner role, and lock."""
        connection = psycopg.connect(self._config.psycopg_dsn, autocommit=True)
        try:
            connection.execute("SET ROLE mtmf_owner")
            connection.execute("SELECT pg_advisory_lock(hashtextextended('mtmf.pr17.dev', 0))")
        except Exception:
            connection.close()
            raise
        self._connection = connection

    def release(self) -> None:
        """Release the lock and close the privileged connection."""
        connection, self._connection = self._connection, None
        if connection is None:
            return
        try:
            connection.execute("SELECT pg_advisory_unlock(hashtextextended('mtmf.pr17.dev', 0))")
        finally:
            connection.close()

    def _execute(self, sql: str, params: tuple[Any, ...]) -> Any:
        if self._connection is None:
            raise BootstrapError("the privileged provisioner connection is not open")
        return self._connection.execute(sql, params)

    def _scalar(self, sql: str, params: tuple[Any, ...]) -> Any:
        row = self._execute(sql, params).fetchone()
        return None if row is None else row[0]

    # -- root --------------------------------------------------------------
    def ensure_root(self, fixture: BootstrapFixture) -> None:
        """Create or validate the canonical root baseline."""
        root_tenant = _deterministic("root-tenant")
        root_principal = _deterministic("root-principal")
        root_identity = _deterministic("root-identity")
        try:
            self._execute(
                "SELECT mtmf.bootstrap_root(%s, %s, %s, %s, %s, %s)",
                (
                    root_tenant,
                    root_principal,
                    root_identity,
                    "MTMF Root Tenant",
                    "MTMF Root Principal",
                    "MTMF Root Identity",
                ),
            )
        except psycopg.errors.RaiseException as exc:
            raise BootstrapError(
                "the canonical root baseline conflicts with existing privileged state; "
                "no automatic recovery is performed"
            ) from exc

    # -- ordinary Tenant ---------------------------------------------------
    def ensure_ordinary_tenant(self, fixture: BootstrapFixture) -> None:
        """Create or validate the ordinary Tenant and its steward."""
        tenant_id = _deterministic(f"tenant:{fixture.tenant.key}")
        principal_id = _deterministic(f"tenant-principal:{fixture.tenant.key}")
        identity_id = _deterministic(f"tenant-identity:{fixture.tenant.key}")
        user_principal_id = _deterministic(f"user-principal:{fixture.user.subject}")
        user_identity_id = _deterministic(f"user-identity:{fixture.user.subject}")
        empty = json.dumps({})

        for principal, name in (
            (principal_id, fixture.tenant.principal_name),
            (user_principal_id, fixture.user.principal_name),
        ):
            if self._scalar("SELECT 1 FROM mtmf.principal WHERE id = %s", (principal,)) is None:
                self._execute(
                    "SELECT mtmf.principal_add(%s, %s, %s, %s::jsonb)",
                    (principal, name, int(DeletionStatus.NOT_DELETED), empty),
                )
        for identity, principal, name in (
            (identity_id, principal_id, fixture.tenant.identity_name),
            (user_identity_id, user_principal_id, fixture.user.identity_name),
        ):
            if self._scalar("SELECT 1 FROM mtmf.identity WHERE id = %s", (identity,)) is None:
                self._execute(
                    "SELECT mtmf.identity_add(%s, %s, %s, %s, %s, %s::jsonb)",
                    (
                        identity,
                        principal,
                        name,
                        int(IdentityOrigin.FEDERATED),
                        int(DeletionStatus.NOT_DELETED),
                        empty,
                    ),
                )
        # The Tenant's owner Identity must exist before the Tenant row, so
        # tenant creation follows principal/identity creation. An existing
        # Tenant must match the configured name exactly; a drifted name fails
        # closed instead of being silently reused or renamed.
        existing_tenant_name = self._scalar(
            "SELECT name FROM mtmf.tenant WHERE id = %s", (tenant_id,)
        )
        if existing_tenant_name is None:
            self._execute(
                "SELECT mtmf.tenant_add(%s, %s, %s, %s, %s, %s, %s::jsonb)",
                (
                    tenant_id,
                    fixture.tenant.name,
                    int(SecurityScope.TENANT),
                    identity_id,
                    int(TenantLifecycle.PROVISIONING),
                    int(DeletionStatus.NOT_DELETED),
                    empty,
                ),
            )
        elif existing_tenant_name != fixture.tenant.name:
            raise BootstrapError(
                "the existing development Tenant conflicts with the configured tenant name; "
                "no automatic rename is performed"
            )
        for principal in (principal_id, user_principal_id):
            if (
                self._scalar(
                    "SELECT 1 FROM mtmf.principal_tenant_membership "
                    "WHERE principal_id = %s AND tenant_id = %s",
                    (principal, tenant_id),
                )
                is None
            ):
                self._execute(
                    "SELECT mtmf.principal_tenant_membership_add(%s, %s)",
                    (principal, tenant_id),
                )
        for identity in (identity_id, user_identity_id):
            if (
                self._scalar(
                    "SELECT 1 FROM mtmf.identity_tenant_membership "
                    "WHERE identity_id = %s AND tenant_id = %s",
                    (identity, tenant_id),
                )
                is None
            ):
                self._execute(
                    "SELECT mtmf.identity_tenant_membership_add(%s, %s)",
                    (identity, tenant_id),
                )
        # Ensure the steward actor carries an effective Tenant Administrator
        # Role before designation/activation, as the DB eligibility predicate
        # requires.
        assignment_id = _deterministic(f"steward-assignment:{fixture.tenant.key}")
        if (
            self._scalar(
                "SELECT 1 FROM mtmf.identity_role_assignment WHERE id = %s", (assignment_id,)
            )
            is None
        ):
            self._execute(
                "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, NULL)",
                (assignment_id, tenant_id, identity_id, TENANT_ADMIN_ROLE_URN),
            )
        if (
            self._scalar(
                "SELECT 1 FROM mtmf.stewardship_designation WHERE tenant_id = %s", (tenant_id,)
            )
            is None
        ):
            self._execute(
                "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', %s, %s)",
                (
                    tenant_id,
                    principal_id,
                    identity_id,
                    "development fixture steward",
                    "mtmf-dev-initializer",
                ),
            )
        if self._scalar("SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant_id,)) != int(
            TenantLifecycle.ACTIVE
        ):
            self._execute("SELECT mtmf.activate_tenant(%s)", (tenant_id,))

    # -- bindings ----------------------------------------------------------
    def ensure_user_binding(self, fixture: BootstrapFixture) -> None:
        """Create or validate the external-subject to Identity binding."""
        identity_id = _deterministic(f"user-identity:{fixture.user.subject}")
        binding_id = _deterministic(f"user-binding:{fixture.user.subject}")
        existing = self._scalar(
            "SELECT identity_id FROM mtmf.external_subject_identity "
            "WHERE issuer = %s AND subject = %s AND lifecycle = %s",
            (fixture.issuer, fixture.user.subject, int(BindingLifecycle.ACTIVE)),
        )
        if existing is None:
            self._execute(
                "SELECT mtmf.external_subject_identity_add(%s, %s, %s, %s, %s, %s)",
                (
                    binding_id,
                    fixture.issuer,
                    fixture.user.subject,
                    identity_id,
                    int(BindingLifecycle.ACTIVE),
                    datetime.now(UTC),
                ),
            )
        elif existing != identity_id:
            raise BootstrapError(
                "the external-subject binding conflicts with the expected development Identity"
            )

    # -- applications ------------------------------------------------------
    def ensure_application(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        """Create or validate one registered Application."""
        application_id = _deterministic(f"application:{application.application_key}")
        existing = self._scalar(
            "SELECT id FROM mtmf.application WHERE application_key = %s",
            (application.application_key,),
        )
        if existing is None:
            self._execute(
                "SELECT mtmf.application_add(%s, %s, %s, %s, %s, %s::jsonb)",
                (
                    application_id,
                    application.application_key,
                    application.name,
                    _deterministic(f"tenant-identity:{fixture.tenant.key}"),
                    int(ApplicationLifecycle.ACTIVE),
                    json.dumps({}),
                ),
            )
        elif existing != application_id:
            raise BootstrapError(
                f"Application {application.application_key!r} conflicts with the expected fixture"
            )

    def ensure_registration_and_subscription(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        """Create or validate an ACTIVE registration and subscription."""
        application_id = _deterministic(f"application:{application.application_key}")
        tenant_id = _deterministic(f"tenant:{fixture.tenant.key}")
        actor_identity = _deterministic(f"tenant-identity:{fixture.tenant.key}")
        now = datetime.now(UTC)
        registration = self._scalar(
            "SELECT lifecycle FROM mtmf.application_tenant_registration "
            "WHERE application_id = %s AND tenant_id = %s",
            (application_id, tenant_id),
        )
        if registration is None:
            self._execute(
                "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, %s, %s)",
                (
                    _deterministic(f"registration:{application.application_key}"),
                    application_id,
                    tenant_id,
                    actor_identity,
                    int(RegistrationLifecycle.ACTIVE),
                    now,
                ),
            )
        elif registration != int(RegistrationLifecycle.ACTIVE):
            raise BootstrapError(f"registration for {application.application_key!r} is not ACTIVE")
        subscription = self._scalar(
            "SELECT lifecycle FROM mtmf.tenant_application_subscription "
            "WHERE application_id = %s AND tenant_id = %s",
            (application_id, tenant_id),
        )
        if subscription is None:
            self._execute(
                "SELECT mtmf.tenant_application_subscription_add(%s, %s, %s, %s, %s, %s, NULL, %s)",
                (
                    _deterministic(f"subscription:{application.application_key}"),
                    application_id,
                    tenant_id,
                    actor_identity,
                    int(SubscriptionLifecycle.ACTIVE),
                    now,
                    now,
                ),
            )
        elif subscription != int(SubscriptionLifecycle.ACTIVE):
            raise BootstrapError(f"subscription for {application.application_key!r} is not ACTIVE")

    def ensure_service_binding(
        self,
        fixture: BootstrapFixture,
        application: ApplicationFixture,
        *,
        client_id: str,
    ) -> None:
        """Create or validate the credential-to-Application binding."""
        application_id = _deterministic(f"application:{application.application_key}")
        existing = self._scalar(
            "SELECT application_id FROM mtmf.service_credential_application "
            "WHERE issuer = %s AND client_id = %s AND lifecycle = %s",
            (fixture.issuer, client_id, int(BindingLifecycle.ACTIVE)),
        )
        if existing is None:
            self._execute(
                "SELECT mtmf.service_credential_application_add(%s, %s, %s, %s, %s, %s)",
                (
                    _deterministic(f"service-binding:{application.application_key}"),
                    fixture.issuer,
                    client_id,
                    application_id,
                    int(BindingLifecycle.ACTIVE),
                    datetime.now(UTC),
                ),
            )
        elif existing != application_id:
            raise BootstrapError(
                f"service credential {client_id!r} is bound to another Application"
            )


@dataclass
class KeycloakCredentialProvisioner:
    """Minimal Keycloak Admin REST credential provisioner (development only)."""

    base_url: str
    realm: str
    admin_username: str
    admin_password: str
    timeout: float = 10.0

    def _admin_token(self) -> str:
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_username,
                "password": self.admin_password,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/realms/master/protocol/openid-connect/token", data=data
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise BootstrapError("the Keycloak token response exceeded the bounded size")
        return json.loads(payload)["access_token"]

    def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        headers = {"Authorization": f"Bearer {self._admin_token()}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method, headers=headers
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise BootstrapError("the Keycloak response exceeded the bounded size")
        return json.loads(payload) if payload else None

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        """Public Admin REST transport used by the development user provisioner."""
        return self._request(method, path, body)

    def create_user(self, path: str, body: Any) -> str | None:
        """POST a new user and return Keycloak's authoritative created-resource location.

        A non-2xx response raises :class:`urllib.error.HTTPError` so the
        provisioner can classify it. The successful response body is empty; the
        ``Location`` header's final path segment is the created immutable id.
        """
        headers = {
            "Authorization": f"Bearer {self._admin_token()}",
            "Content-Type": "application/json",
        }
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(body).encode(),
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read(_MAX_RESPONSE_BYTES + 1)
            return response.headers.get("Location")

    def _approved_policy(self) -> ExpectedClientPolicy:
        path = os.environ.get(
            "MTMF_AUTH_EXPECTED_CLIENT_POLICY", "dev/keycloak/expected-client-policy.json"
        )
        try:
            return ExpectedClientPolicy.load(path)
        except ExpectedClientPolicyError as exc:
            raise BootstrapError("the approved expected-client policy is unusable") from exc

    def ensure_client(self, fixture: BootstrapFixture, application: ApplicationFixture) -> str:
        """Create or validate one confidential client against the approved policy.

        The client must have an independently approved expected-client entry.
        A missing approved client is created; an existing client is compared to
        the approved projection and any drift fails closed (no automatic repair,
        no secret rotation). The current secret is delivered to an owner-only
        file (mode ``0600``) under ``MTMF_DEV_SECRET_DIR``; it is never printed.
        """
        client_id = f"mtmf-{application.application_key}"
        expected = self._approved_policy().require(client_id)
        reader = _AdminReadAdapter(self)
        lookup = (
            f"/admin/realms/{self.realm}/clients?clientId={urllib.parse.quote(client_id, safe='')}"
        )
        rows = self._request("GET", lookup)
        if not rows:
            self._request(
                "POST",
                f"/admin/realms/{self.realm}/clients",
                {
                    "clientId": client_id,
                    "name": application.name,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": True,
                    "directAccessGrantsEnabled": False,
                },
            )
            rows = self._request("GET", lookup)
        if len(rows) != 1:
            raise BootstrapError(f"client {client_id!r} is missing or ambiguous in the live realm")
        actual = canonical_client_projection(reader, self.realm, rows[0])
        if dict(expected) != actual:
            raise BootstrapError(
                f"client {client_id!r} drifted from the approved expected-client policy; "
                "no automatic repair is performed"
            )
        client_uuid = rows[0]["id"]
        secret_payload = self._request(
            "GET", f"/admin/realms/{self.realm}/clients/{client_uuid}/client-secret"
        )
        secret = secret_payload.get("value") if isinstance(secret_payload, dict) else None
        if isinstance(secret, str) and secret:
            self._deliver_secret(client_id, secret)
        return client_id

    def _deliver_secret(self, client_id: str, secret: str) -> None:
        """Write one client secret to an owner-only, MTMF-controlled file."""
        directory = os.environ.get("MTMF_DEV_SECRET_DIR", "/tmp/mtmf-dev-secrets")
        target_dir = Path(directory)
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = target_dir / f"{client_id}.secret"
        file_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(file_descriptor, "w") as handle:
            handle.write(secret)
        os.chmod(target, 0o600)

    def preflight_issuer(self, expected_issuer: str) -> None:
        """Validate the live issuer discovery before any user provisioning."""
        if not expected_issuer:
            raise BootstrapError("the configured issuer trust anchor is empty")
        try:
            discovery = self._request(
                "GET", f"/realms/{self.realm}/.well-known/openid-configuration"
            )
            if not isinstance(discovery, dict) or discovery.get("issuer") != expected_issuer:
                raise BootstrapError("the live issuer does not match the configured trust anchor")
            self._request("GET", f"/realms/{self.realm}/protocol/openid-connect/certs")
        except BootstrapError:
            raise
        except urllib.error.HTTPError as exc:
            raise BootstrapError(
                f"the development issuer preflight failed with HTTP {exc.code}"
            ) from None
        except urllib.error.URLError, OSError, ValueError:
            raise BootstrapError(
                "the development issuer preflight could not be completed; verify the issuer "
                "trust anchor, credential, and network reachability"
            ) from None

    def verify_issuer(self, fixture: BootstrapFixture) -> None:
        """Freshly attest the realm projection and every approved client."""
        self.preflight_issuer(fixture.issuer)
        manifest_path = os.environ.get(
            "MTMF_AUTH_EXPECTED_MANIFEST", "dev/keycloak/expected-realm-security.json"
        )
        policy_path = os.environ.get(
            "MTMF_AUTH_EXPECTED_CLIENT_POLICY", "dev/keycloak/expected-client-policy.json"
        )
        attestor = BaselineConfigurationAttestor(
            _AdminReadAdapter(self), self.realm, manifest_path, policy_path
        )
        profile = IssuerProfile(
            issuer=fixture.issuer,
            audience=fixture.service_audience,
            jwks_uri=f"{fixture.issuer}/protocol/openid-connect/certs",
        )
        attestor.attest(profile)
        for approved_client_id in self._approved_policy().entries:
            attestor.attest_client(profile, approved_client_id)


class _AdminReadAdapter:
    """Adapt the initializer's Admin REST client to the read-only reader port."""

    def __init__(self, provisioner: KeycloakCredentialProvisioner) -> None:
        self._provisioner = provisioner

    def get(self, path: str) -> Any:
        return self._provisioner._request("GET", path)


def _dev_fixture(subject: str) -> BootstrapFixture:
    """Build the generic, application-neutral development fixture.

    The acting-user ``subject`` must be the authoritative Keycloak user ID
    already verified by :class:`KeycloakDevUserProvisioner`; there is no
    fabricated fallback.
    """
    applications = tuple(
        ApplicationFixture(key.strip(), key.strip())
        for key in (os.environ.get("MTMF_DEV_APPLICATION_KEYS", "sample-app") or "").split(",")
        if key.strip()
    )
    return BootstrapFixture(
        tenant=TenantFixture(
            key=os.environ.get("MTMF_DEV_TENANT_KEY", "dev"),
            name=os.environ.get("MTMF_DEV_TENANT_NAME", "Development Tenant"),
            principal_name="Development Tenant Principal",
            identity_name="Development Tenant Steward Identity",
        ),
        user=UserFixture(
            subject=subject,
            principal_name="Development User Principal",
            identity_name="Development User Identity",
        ),
        applications=applications,
        issuer=os.environ.get("MTMF_AUTH_ISSUER", "").rstrip("/"),
        service_audience=os.environ.get("MTMF_AUTH_SERVICE_AUDIENCE", ""),
        user_audience=os.environ.get("MTMF_AUTH_USER_AUDIENCE", ""),
        realm=os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-pr14-dev"),
    )


def main(argv: list[str] | None = None) -> int:
    """Run the privileged development initialization once."""
    parser = argparse.ArgumentParser(description="MTMF development initializer")
    parser.add_argument(
        "--migrations-only",
        action="store_true",
        help="apply migrations and privilege postflight only, then exit",
    )
    args = parser.parse_args(argv)

    settings = ServiceSettings.from_env()
    if settings.deployment_mode is not DeploymentMode.DEVELOPMENT:
        print("refusing: the development initializer requires the development profile")
        return 2
    provisioner = PostgresProvisioner(PostgresConfig.from_env(PostgresRole.MIGRATOR))
    if args.migrations_only:
        provisioner.apply_migrations_and_verify()
        print("migrations applied and runtime privileges verified")
        return 0
    credentials = KeycloakCredentialProvisioner(
        base_url=os.environ.get("MTMF_AUTH_ADMIN_BASE", "").rstrip("/"),
        realm=os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-pr14-dev"),
        admin_username=os.environ.get("MTMF_AUTH_ADMIN_USERNAME", ""),
        admin_password=os.environ.get("MTMF_AUTH_ADMIN_PASSWORD", ""),
    )
    try:
        config = DevUserConfig.from_env()
        credentials.preflight_issuer(os.environ.get("MTMF_AUTH_ISSUER", "").rstrip("/"))
        subject = KeycloakDevUserProvisioner(
            credentials, credentials.realm, admin_base_url=credentials.base_url
        ).ensure_user(config)
        _reach_test_failpoint("after-user-verify")
        DevelopmentBootstrap(
            mode=settings.deployment_mode,
            fixture=_dev_fixture(subject),
            provisioning=provisioner,
            credentials=credentials,
            lock=provisioner,
        ).run()
    except BootstrapError as exc:
        print(f"initialization failed: {exc}", file=sys.stderr)
        return 1
    print("development initialization complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
