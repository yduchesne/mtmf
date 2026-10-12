"""Opt-in, idempotent development initialization orchestration (PR 17).

This module owns the *sequence and state machine* of the development-only
one-shot initializer. The privileged side effects (migrations, sanctioned
stored functions, Keycloak Admin REST, secret delivery) live behind the
:class:`ProvisioningPort` and :class:`CredentialPort` seams so the
orchestrator can be exercised deterministically and never imports a
database driver or an HTTP client.

Contract:

- the initializer is **opt-in** and refuses any non-development mode;
- it is idempotent: every step validates and reuses exact existing state,
  creates only missing safe fixtures, and fails closed on conflicting or
  incomplete privileged state (no root recovery, no secret rotation);
- it is concurrency-safe through a single exclusive provisioning lock;
- a completed run marks initialization complete, and only then may the
  HTTP service report ready.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from mtmf_service.settings import DeploymentMode

__all__ = [
    "ApplicationFixture",
    "BootstrapError",
    "BootstrapFixture",
    "CredentialPort",
    "DevelopmentBootstrap",
    "ProvisioningPort",
    "TenantFixture",
    "UserFixture",
]


class BootstrapError(RuntimeError):
    """The development initialization cannot proceed safely.

    Raised for a disabled/non-development profile, a malformed fixture, a
    conflicting existing privileged object, or any provisioner failure.
    Restarting after operator remediation is the only supported recovery.
    """


@dataclass(frozen=True, slots=True)
class TenantFixture:
    """A deterministic ordinary development Tenant fixture."""

    key: str
    name: str
    principal_name: str
    identity_name: str

    def __post_init__(self) -> None:
        if not self.key or not self.name or not self.principal_name or not self.identity_name:
            raise BootstrapError("tenant fixture fields must be non-empty")


@dataclass(frozen=True, slots=True)
class UserFixture:
    """A deterministic development acting-user fixture."""

    subject: str
    principal_name: str
    identity_name: str

    def __post_init__(self) -> None:
        if not self.subject or not self.principal_name or not self.identity_name:
            raise BootstrapError("user fixture fields must be non-empty")


@dataclass(frozen=True, slots=True)
class ApplicationFixture:
    """A deterministic consuming-Application fixture."""

    application_key: str
    name: str

    def __post_init__(self) -> None:
        if not self.application_key or not self.name:
            raise BootstrapError("application fixture fields must be non-empty")


@dataclass(frozen=True, slots=True)
class BootstrapFixture:
    """The complete, application-neutral development fixture manifest."""

    tenant: TenantFixture
    user: UserFixture
    applications: tuple[ApplicationFixture, ...]
    issuer: str
    service_audience: str
    user_audience: str
    realm: str

    def __post_init__(self) -> None:
        if not self.applications:
            raise BootstrapError("at least one Application fixture is required")
        if not self.issuer or not self.realm:
            raise BootstrapError("issuer and realm are required")
        keys = [application.application_key for application in self.applications]
        if len(set(keys)) != len(keys):
            raise BootstrapError("Application fixture keys must be unique")


@runtime_checkable
class ProvisioningPort(Protocol):
    """Privileged MTMF-side provisioning operations (sanctioned primitives only)."""

    def apply_migrations_and_verify(self) -> None:
        """Migrate to head and require the mandatory privilege postflight."""
        ...

    def ensure_root(self, fixture: BootstrapFixture) -> None:
        """Create or validate the canonical root baseline exactly."""
        ...

    def ensure_ordinary_tenant(self, fixture: BootstrapFixture) -> None:
        """Create or validate the ordinary Tenant, actor, memberships, steward."""
        ...

    def ensure_user_binding(self, fixture: BootstrapFixture) -> None:
        """Create or validate the external-subject to Identity binding."""
        ...

    def ensure_application(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        """Create or validate one registered Application (Tenant-independent)."""
        ...

    def ensure_registration_and_subscription(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        """Create or validate an ACTIVE registration and subscription."""
        ...

    def ensure_service_binding(
        self,
        fixture: BootstrapFixture,
        application: ApplicationFixture,
        *,
        client_id: str,
    ) -> None:
        """Create or validate the credential-to-Application binding."""
        ...


@runtime_checkable
class CredentialPort(Protocol):
    """External issuer credential provisioning (Keycloak Admin REST)."""

    def ensure_client(
        self,
        fixture: BootstrapFixture,
        application: ApplicationFixture,
    ) -> str:
        """Create or reuse the confidential client; return its ``client_id``.

        Implementations must never reset an existing client secret.
        """
        ...

    def verify_issuer(self, fixture: BootstrapFixture) -> None:
        """Validate live issuer configuration against the approved manifest."""
        ...


@runtime_checkable
class LockPort(Protocol):
    """A single exclusive provisioning lock (e.g. a DB advisory lock)."""

    def acquire(self) -> None:
        """Block until the exclusive lock is held."""
        ...

    def release(self) -> None:
        """Release the lock."""
        ...


class _NoopLock:
    """A no-op lock for callers that already guarantee serialization."""

    def acquire(self) -> None:
        """Do nothing."""

    def release(self) -> None:
        """Do nothing."""


class DevelopmentBootstrap:
    """Run the idempotent development initialization sequence once."""

    __slots__ = ("_credentials", "_fixture", "_lock", "_mode", "_provisioning")

    def __init__(
        self,
        *,
        mode: DeploymentMode,
        fixture: BootstrapFixture,
        provisioning: ProvisioningPort,
        credentials: CredentialPort,
        lock: LockPort | None = None,
    ) -> None:
        self._mode = mode
        self._fixture = fixture
        self._provisioning = provisioning
        self._credentials = credentials
        self._lock = lock or _NoopLock()

    def run(self) -> None:
        """Execute the full initialization sequence.

        :raises BootstrapError: on a disabled profile, a malformed fixture,
            or any provisioner/credential failure. Partial progress is safe
            to retry: the next run reconciles idempotently.
        """
        if self._mode is not DeploymentMode.DEVELOPMENT:
            raise BootstrapError(
                "the development initializer may run only in the development profile"
            )
        self._lock.acquire()
        try:
            self._provisioning.apply_migrations_and_verify()
            self._provisioning.ensure_root(self._fixture)
            self._provisioning.ensure_ordinary_tenant(self._fixture)
            self._provisioning.ensure_user_binding(self._fixture)
            for application in self._fixture.applications:
                self._provisioning.ensure_application(self._fixture, application)
                client_id = self._credentials.ensure_client(self._fixture, application)
                self._provisioning.ensure_service_binding(
                    self._fixture, application, client_id=client_id
                )
                self._provisioning.ensure_registration_and_subscription(self._fixture, application)
            self._credentials.verify_issuer(self._fixture)
        except BootstrapError:
            raise
        except Exception as exc:  # never leak provider detail; fail closed
            raise BootstrapError(
                "development initialization failed; the fixture may be partially "
                "provisioned, which is safe to retry after remediation"
            ) from exc
        finally:
            self._lock.release()
