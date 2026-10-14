"""Shared fixtures for the PR 17 service (HTTP PDP) unit suites.

These suites exercise the real PR 14 actor composition, the real PR 9
effective-Role resolver, the real PR 16 pure-Python batch evaluator, the
real PR 15 codecs, and the real ASGI application. Only externally
unavailable boundaries are doubled: the issuer verifier/attestor seam,
the clock, and (for targeted fault injection) the persistence provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import (
    make_id,
    make_permission,
    make_permission_set,
    make_role,
    make_role_urn,
)

from mtmf_core import (
    Action,
    ActionUrn,
    IdentityRoleAssignment,
    InMemoryMtmfSpi,
    PermissionEffect,
    PermissionSet,
)
from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.effective_roles import EffectiveRoleResolver
from mtmf_core.application.management_memberships import ManagementMembershipService
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    ExternalSubjectKey,
    IssuerProfile,
    ServiceCredentialKey,
    VerifiedAccessToken,
    VerifiedActorContext,
)
from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.authorization.batch import AuthorizationBatch, BatchAuthorizer
from mtmf_core.domain.application import (
    Application,
    ApplicationTenantRegistration,
    TenantApplicationSubscription,
)
from mtmf_core.domain.authentication_binding import (
    BindingLifecycle,
    ExternalSubjectBinding,
    ServiceCredentialBinding,
)
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    IdentityOrigin,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantLifecycle,
)
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_service.app import create_app
from mtmf_service.clock import FrozenClock
from mtmf_service.composition import build_authorization_service
from mtmf_service.concurrency import EvaluationAdmission
from mtmf_service.management import ManagementMembershipHttpService
from mtmf_service.rate_limit import TokenBucketRateLimiter
from mtmf_service.readiness import StaticReadiness
from mtmf_service.sensitivity import (
    AllowlistSensitiveActionClassifier,
    ConservativeSensitiveActionClassifier,
)
from mtmf_service.settings import ServiceSettings

ISS = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
SERVICE_AUD = "mtmf-service-api"
USER_AUD = "mtmf-user-api"
CLIENT = "client-1"
SUBJECT = "user-1"
JWKS = f"{ISS}/certs"

ALLOW_ACTION = "urn:mtmf:iam:actions:system:principal:get-object"
DENY_ACTION = "urn:mtmf:iam:actions:system:principal:update-object"
NO_PERMISSION_ACTION = "urn:mtmf:iam:actions:system:role:get-object"
UNKNOWN_ACTION = "urn:mtmf:iam:actions:system:tenant:get-object"

_NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)


class VerifierSpy:
    """Deterministic PR 14 token-verifier double keyed by token text."""

    def __init__(
        self,
        tokens: dict[str, VerifiedAccessToken],
        errors: dict[str, AuthenticationError] | None = None,
    ) -> None:
        self.tokens = tokens
        self.errors = errors or {}
        self.calls: list[str] = []

    def verify(self, token: str, profile: IssuerProfile) -> VerifiedAccessToken:
        self.calls.append(token)
        if token in self.errors:
            raise self.errors[token]
        try:
            return self.tokens[token]
        except KeyError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "unknown test token"
            ) from exc


class AttestorSpy:
    """Recording attestor that can be forced to drift/unavailable."""

    def __init__(self, *, failure: AuthenticationFailure | None = None) -> None:
        self.failure = failure
        self.calls = 0
        self.client_calls: list[str] = []

    def attest(self, profile: IssuerProfile) -> None:
        self.calls += 1
        if self.failure is not None:
            raise AuthenticationError(self.failure, "forced attestation failure")

    def attest_client(self, profile: IssuerProfile, client_id: str) -> None:
        self.client_calls.append(client_id)
        if self.failure is not None:
            raise AuthenticationError(self.failure, "forced attestation failure")


def make_token(
    *,
    subject: str,
    client_id: str | None,
    azp: str = CLIENT,
    issuer: str = ISS,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> VerifiedAccessToken:
    """Build one verified service/user access token value."""
    base = issued_at or (_NOW - timedelta(seconds=10))
    expiry = expires_at or (_NOW + timedelta(seconds=300))
    return VerifiedAccessToken(
        issuer=issuer,
        subject=subject,
        audiences=frozenset({SERVICE_AUD if client_id else USER_AUD}),
        azp=azp,
        client_id=client_id,
        token_type="Bearer",
        issued_at=base,
        expires_at=expiry,
        not_before=None,
    )


class World:
    """A seeded in-memory ordinary Tenant / Application / Role graph."""

    def __init__(
        self,
        spi: InMemoryMtmfSpi,
        *,
        memberships: bool = True,
        subscription_lifecycle: SubscriptionLifecycle = SubscriptionLifecycle.ACTIVE,
        register_actions: bool = True,
    ) -> None:
        self.spi = spi
        self._memberships = memberships
        self._subscription_lifecycle = subscription_lifecycle
        self._register_actions = register_actions
        now = _NOW - timedelta(hours=1)
        self.principal = Principal(id=make_id(), name="principal")
        self.identity = Identity(
            id=make_id(),
            principal_id=self.principal.id,
            name="identity",
            origin=IdentityOrigin.FEDERATED,
        )
        self.tenant = Tenant(
            id=make_id(),
            name="tenant",
            scope=SecurityScope.TENANT,
            owner_identity_id=self.identity.id,
            lifecycle=TenantLifecycle.ACTIVE,
        )
        self.application = Application(
            id=make_id(),
            application_key="sample-app",
            name="Sample Application",
            owner_identity_id=self.identity.id,
            lifecycle=ApplicationLifecycle.ACTIVE,
        )
        self.registration = ApplicationTenantRegistration(
            id=make_id(),
            application_id=self.application.id,
            tenant_id=self.tenant.id,
            created_by_identity_id=self.identity.id,
            created_at=now,
            lifecycle=RegistrationLifecycle.ACTIVE,
        )
        self.subscription = TenantApplicationSubscription(
            id=make_id(),
            application_id=self.application.id,
            tenant_id=self.tenant.id,
            created_by_identity_id=self.identity.id,
            starts_at=now,
            created_at=now,
            lifecycle=self._subscription_lifecycle,
        )
        # A SYSTEM-defined Role with an ALLOW permission set for
        # ``principal:get-object`` and a DENY permission set for
        # ``principal:update-object``.
        self.role_urn = make_role_urn(role_name="dev-admin")
        allow_set = make_permission_set(role_urn=self.role_urn, effect=PermissionEffect.ALLOW)
        deny_set_id = make_id()
        deny_set = PermissionSet(
            deny_set_id,
            self.role_urn,
            PermissionEffect.DENY,
            (
                make_permission(
                    permission_set_id=deny_set_id,
                    resource="principal",
                    verb="update",
                    qualifier="object",
                ),
            ),
        )
        self.role = make_role(urn=self.role_urn, permission_sets=(allow_set, deny_set))
        self.registered_actions = (
            (ALLOW_ACTION, DENY_ACTION, NO_PERMISSION_ACTION) if register_actions else ()
        )

    @property
    def actor(self) -> VerifiedActorContext:
        """The verified actor context the real composition produces."""
        return VerifiedActorContext(
            application_id=self.application.id,
            identity_id=self.identity.id,
            principal_id=self.principal.id,
            tenant_id=self.tenant.id,
            service_credential=ServiceCredentialKey(issuer=ISS, client_id=CLIENT),
            external_subject=ExternalSubjectKey(issuer=ISS, subject=SUBJECT),
        )

    def seed(self) -> World:
        """Persist the graph and the credential/subject bindings."""
        spi = self.spi
        with spi.create_unit_of_work() as uow:
            spi.create_principal_repository(uow).add(self.principal)
            spi.create_identity_repository(uow).add(self.identity)
            spi.create_tenant_repository(uow).add(self.tenant)
            spi.create_application_repository(uow).add(self.application)
            spi.create_application_tenant_registration_repository(uow).add(self.registration)
            spi.create_tenant_application_subscription_repository(uow).add(self.subscription)
            spi.create_role_repository(uow).add(self.role)
            action_repository = spi.create_action_repository(uow)
            for urn in self.registered_actions:
                action_repository.add(Action(ActionUrn(urn)))
            if self._memberships:
                spi.create_identity_tenant_membership_repository(uow).add(
                    IdentityTenantMembership(self.identity.id, self.tenant.id)
                )
                spi.create_principal_tenant_membership_repository(uow).add(
                    PrincipalTenantMembership(self.principal.id, self.tenant.id)
                )
            spi.create_identity_role_assignment_repository(uow).add(
                IdentityRoleAssignment(make_id(), self.tenant.id, self.identity.id, self.role_urn)
            )
            uow.commit()
        spi.seed_service_credential_binding(
            ServiceCredentialBinding(
                id=make_id(),
                issuer=ISS,
                client_id=CLIENT,
                application_id=self.application.id,
                created_at=_NOW,
                lifecycle=BindingLifecycle.ACTIVE,
            )
        )
        spi.seed_external_subject_binding(
            ExternalSubjectBinding(
                id=make_id(),
                issuer=ISS,
                subject=SUBJECT,
                identity_id=self.identity.id,
                created_at=_NOW,
                lifecycle=BindingLifecycle.ACTIVE,
            )
        )
        return self


class CountingResolver:
    """Wrap a policy resolver and count resolve/evaluate crossings."""

    def __init__(self) -> None:
        from mtmf_core.authorization.policy_resolver import DefaultAuthorizationPolicyResolver

        self._inner = DefaultAuthorizationPolicyResolver()
        self.resolve_calls = 0
        self.contexts: list[Any] = []

    def resolve(self, context: Any) -> Any:
        self.resolve_calls += 1
        self.contexts.append(context)
        return self._inner.resolve(context)


class InstrumentedBatchAuthorizer(BatchAuthorizer):
    """Record every batch the orchestrator evaluates."""

    def __init__(self, policy_resolver: Any | None = None) -> None:
        super().__init__(policy_resolver)
        self.batches: list[AuthorizationBatch] = []

    def authorize(self, batch: AuthorizationBatch) -> Any:
        self.batches.append(batch)
        return super().authorize(batch)


class ExplodingBatchAuthorizer(BatchAuthorizer):
    """Batch authorizer that always fails, for whole-request fault tests."""

    def authorize(self, batch: AuthorizationBatch) -> Any:
        raise RuntimeError("policy resolver exploded")


class TruncatingBatchAuthorizer(BatchAuthorizer):
    """Batch authorizer that drops decisions, to force a conformance fault."""

    def authorize(self, batch: AuthorizationBatch) -> Any:
        result = super().authorize(batch)
        from mtmf_core.authorization.batch import AuthorizationBatchResult

        return AuthorizationBatchResult(result.decisions[:1])


class CancellingBatchAuthorizer(BatchAuthorizer):
    """Batch authorizer that raises a cancellation, to prove propagation."""

    def authorize(self, batch: AuthorizationBatch) -> Any:
        import asyncio

        raise asyncio.CancelledError


@dataclass
class Harness:
    """A fully wired service instance plus its observability seams."""

    world: World
    actor_service: AuthenticatedActorContextService
    authorization_service: Any
    attestor: AttestorSpy
    service_verifier: VerifierSpy
    user_verifier: VerifierSpy
    batch_authorizer: BatchAuthorizer
    resolver: CountingResolver | None
    clock: FrozenClock
    settings: ServiceSettings
    client: TestClient
    app: Any = None
    admission: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


def build_harness(
    *,
    spi: MtmfSpi,
    world: World,
    settings: ServiceSettings | None = None,
    attestor: AttestorSpy | None = None,
    service_verifier: VerifierSpy | None = None,
    user_verifier: VerifierSpy | None = None,
    instrument: bool = False,
    batch_authorizer: BatchAuthorizer | None = None,
    sensitivity: Any | None = None,
    rate_limiter: Any | None = None,
    readiness: Any | None = None,
    admission: Any | None = None,
    telemetry: Any | None = None,
) -> Harness:
    """Assemble one service instance with deterministic boundary doubles."""
    resolved_settings = settings or ServiceSettings()
    attestor = attestor or AttestorSpy()
    service_verifier = service_verifier or VerifierSpy(
        {"service": make_token(subject="sa", client_id=CLIENT)}
    )
    user_verifier = user_verifier or VerifierSpy(
        {"user": make_token(subject=SUBJECT, client_id=None)}
    )
    actor_service = AuthenticatedActorContextService(
        spi=spi,
        attestor=attestor,
        service_verifier=service_verifier,
        service_profile=IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=JWKS),
        user_verifier=user_verifier,
        user_profile=IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=JWKS),
    )
    resolver: CountingResolver | None = None
    if batch_authorizer is not None:
        resolved_batch_authorizer: BatchAuthorizer = batch_authorizer
    elif instrument:
        resolver = CountingResolver()
        resolved_batch_authorizer = InstrumentedBatchAuthorizer(resolver)
    else:
        resolved_batch_authorizer = InstrumentedBatchAuthorizer()
    clock = FrozenClock(_NOW)
    authorization_service = build_authorization_service(
        spi=spi,
        issuer_config=_issuer_config(),
        settings=resolved_settings,
        actor_service=actor_service,
        batch_authorizer=resolved_batch_authorizer,
        clock=clock,
        sensitivity=sensitivity or ConservativeSensitiveActionClassifier(),
        telemetry=telemetry,
    )
    resolved_admission = admission or EvaluationAdmission(
        resolved_settings.max_in_flight_evaluations
    )
    app = create_app(
        settings=resolved_settings,
        authorization_service=authorization_service,
        management_membership_service=ManagementMembershipHttpService(
            membership_service=ManagementMembershipService(
                spi=spi,
                actor_service=actor_service,
                role_resolver=EffectiveRoleResolver(spi),
                authorizer=Authorizer(),
            )
        ),
        readiness=readiness or StaticReadiness(True),
        rate_limiter=rate_limiter or TokenBucketRateLimiter(per_minute=100000, burst=100000),
        admission=resolved_admission,
        telemetry=telemetry,
    )
    client = TestClient(app, raise_server_exceptions=False)
    return Harness(
        world=world,
        actor_service=actor_service,
        authorization_service=authorization_service,
        attestor=attestor,
        service_verifier=service_verifier,
        user_verifier=user_verifier,
        batch_authorizer=resolved_batch_authorizer,
        resolver=resolver,
        clock=clock,
        settings=resolved_settings,
        client=client,
        app=app,
        admission=resolved_admission,
    )


def seeded_harness(
    world_kwargs: dict[str, Any] | None = None,
    **harness_kwargs: Any,
) -> Harness:
    """Build a seeded in-memory world and a fully wired harness."""
    world = World(InMemoryMtmfSpi(), **(world_kwargs or {})).seed()
    return build_harness(spi=world.spi, world=world, **harness_kwargs)


def _issuer_config() -> Any:
    from mtmf_service.authentication.config import IssuerConfig

    return IssuerConfig(
        issuer=ISS,
        service_audience=SERVICE_AUD,
        user_audience=USER_AUD,
        jwks_uri=JWKS,
        expected_manifest_path="dev/keycloak/expected-realm-security.json",
        admin_base_url="https://127.0.0.1:28443",
        admin_realm="mtmf-pr14-dev",
        attestation_client_id="mtmf-attestation-reader",
        attestation_client_secret="mtmf-attestation-reader-dev-secret",
    )


def action_body(
    *actions: tuple[str, str],
    tenant_id: str | None,
    organization_id: str | None = None,
) -> dict[str, Any]:
    """Build a raw request mapping from ``(request_id, action)`` pairs."""
    return {
        "tenant_id": tenant_id,
        "organization_id": organization_id,
        "actions": [
            {
                "request_id": request_id,
                "action": action,
                "resource": {"kind": "capability"},
            }
            for request_id, action in actions
        ],
    }


def auth_headers(*, service: str = "service", user: str = "user") -> dict[str, str]:
    """Build the service and user authorization headers."""
    return {
        "Authorization": f"Bearer {service}",
        "X-MTMF-User-Authorization": f"Bearer {user}",
    }


@pytest.fixture
def sensitivity_allowlist() -> AllowlistSensitiveActionClassifier:
    """A reviewed sensitivity allowlist marking only the ALLOW action sensitive."""
    return AllowlistSensitiveActionClassifier(frozenset({ALLOW_ACTION}))


IDENTITY_TYPE = Identity
