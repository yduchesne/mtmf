"""Unit acceptance tests for verified D1 actor-context composition.

Uses the in-memory SPI, a deterministic verifier double, and a recording
attestor so orchestration, domain gates, and root exclusion are exercised
without a live issuer or database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
    VerifiedAccessToken,
)
from mtmf_core.domain.application import (
    Application,
    ApplicationTenantRegistration,
    TenantApplicationSubscription,
)
from mtmf_core.domain.authentication_binding import (
    BindingLifecycle,
    ExternalSubjectBinding,
    RootRegistryRecord,
    ServiceCredentialBinding,
)
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    DeletionStatus,
    IdentityOrigin,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantLifecycle,
)
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.testing import InMemoryMtmfSpi

ISS = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
SERVICE_AUD = "mtmf-service-api"
USER_AUD = "mtmf-user-api"
CLIENT = "client-1"
SUBJECT = "user-1"


class VerifierSpy:
    """Deterministic token verifier double keyed by token text."""

    def __init__(self, tokens: dict[str, VerifiedAccessToken]) -> None:
        self.tokens = tokens
        self.calls: list[str] = []

    def verify(self, token: str, profile: IssuerProfile) -> VerifiedAccessToken:
        self.calls.append(token)
        try:
            return self.tokens[token]
        except KeyError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "unknown test token"
            ) from exc


class AttestorSpy:
    """Recording attestor that can be forced to fail closed."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def attest(self, profile: IssuerProfile) -> None:
        self.calls += 1
        if self.fail:
            raise AuthenticationError(AuthenticationFailure.ATTESTATION_DRIFT, "forced drift")


def token(*, subject: str, client_id: str | None, azp: str = CLIENT) -> VerifiedAccessToken:
    now = datetime.now(UTC)
    return VerifiedAccessToken(
        issuer=ISS,
        subject=subject,
        audiences=frozenset({SERVICE_AUD if client_id else USER_AUD}),
        azp=azp,
        client_id=client_id,
        token_type="Bearer",
        issued_at=now - timedelta(seconds=10),
        expires_at=now + timedelta(seconds=300),
        not_before=None,
    )


class World:
    """A seeded in-memory world for one actor-composition test."""

    def __init__(
        self,
        spi: InMemoryMtmfSpi,
        *,
        memberships: bool = True,
        subscription_lifecycle: SubscriptionLifecycle = SubscriptionLifecycle.ACTIVE,
    ) -> None:
        self.spi = spi
        now = datetime.now(UTC)
        self.principal = Principal(id=DomainId.generate(), name="principal")
        self.identity = Identity(
            id=DomainId.generate(),
            principal_id=self.principal.id,
            name="identity",
            origin=IdentityOrigin.FEDERATED,
        )
        self.tenant = Tenant(
            id=DomainId.generate(),
            name="tenant",
            scope=SecurityScope.TENANT,
            owner_identity_id=self.identity.id,
            lifecycle=TenantLifecycle.ACTIVE,
        )
        self.application = Application(
            id=DomainId.generate(),
            application_key="app",
            name="Application",
            owner_identity_id=self.identity.id,
            lifecycle=ApplicationLifecycle.ACTIVE,
        )
        self.registration = ApplicationTenantRegistration(
            id=DomainId.generate(),
            application_id=self.application.id,
            tenant_id=self.tenant.id,
            created_by_identity_id=self.identity.id,
            created_at=now - timedelta(hours=1),
            lifecycle=RegistrationLifecycle.ACTIVE,
        )
        self.subscription = TenantApplicationSubscription(
            id=DomainId.generate(),
            application_id=self.application.id,
            tenant_id=self.tenant.id,
            created_by_identity_id=self.identity.id,
            starts_at=now - timedelta(hours=1),
            created_at=now - timedelta(hours=1),
            lifecycle=SubscriptionLifecycle.ACTIVE,
        )
        self.subscription.lifecycle = subscription_lifecycle
        self._subscription_lifecycle = subscription_lifecycle
        self._memberships = memberships

    def seed(self) -> World:
        spi = self.spi
        with spi.create_unit_of_work() as uow:
            spi.create_principal_repository(uow).add(self.principal)
            spi.create_identity_repository(uow).add(self.identity)
            spi.create_tenant_repository(uow).add(self.tenant)
            spi.create_application_repository(uow).add(self.application)
            spi.create_application_tenant_registration_repository(uow).add(self.registration)
            spi.create_tenant_application_subscription_repository(uow).add(self.subscription)
            if self._memberships:
                spi.create_identity_tenant_membership_repository(uow).add(
                    IdentityTenantMembership(self.identity.id, self.tenant.id)
                )
                spi.create_principal_tenant_membership_repository(uow).add(
                    PrincipalTenantMembership(self.principal.id, self.tenant.id)
                )
            uow.commit()
        now = datetime.now(UTC)
        spi.seed_service_credential_binding(
            ServiceCredentialBinding(
                id=DomainId.generate(),
                issuer=ISS,
                client_id=CLIENT,
                application_id=self.application.id,
                created_at=now,
                lifecycle=BindingLifecycle.ACTIVE,
            )
        )
        spi.seed_external_subject_binding(
            ExternalSubjectBinding(
                id=DomainId.generate(),
                issuer=ISS,
                subject=SUBJECT,
                identity_id=self.identity.id,
                created_at=now,
                lifecycle=BindingLifecycle.ACTIVE,
            )
        )
        return self


def make_service(
    spi: InMemoryMtmfSpi,
    *,
    service_token: VerifiedAccessToken | None = None,
    user_token: VerifiedAccessToken | None = None,
    attestor: AttestorSpy | None = None,
    service_spy: VerifierSpy | None = None,
    user_spy: VerifierSpy | None = None,
) -> tuple[AuthenticatedActorContextService, VerifierSpy, VerifierSpy]:
    service_profile = IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs")
    user_profile = IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs")
    svc_spy = service_spy or VerifierSpy(
        {"service": service_token or token(subject="sa", client_id=CLIENT)}
    )
    usr_spy = user_spy or VerifierSpy(
        {"user": user_token or token(subject=SUBJECT, client_id=None)}
    )
    composed = AuthenticatedActorContextService(
        spi=spi,
        attestor=attestor or AttestorSpy(),
        service_verifier=svc_spy,
        service_profile=service_profile,
        user_verifier=usr_spy,
        user_profile=user_profile,
    )
    return composed, svc_spy, usr_spy


def resolve(service: AuthenticatedActorContextService, tenant_id: DomainId):
    return service.resolve(service_token="service", user_token="user", tenant_id=tenant_id)


def test_happy_path_composes_actor_context():
    world = World(InMemoryMtmfSpi()).seed()
    context = resolve(make_service(world.spi)[0], world.tenant.id)
    assert context.application_id == world.application.id
    assert context.identity_id == world.identity.id
    assert context.principal_id == world.principal.id
    assert context.tenant_id == world.tenant.id


def test_cross_client_pair_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    service = make_service(
        world.spi, user_token=token(subject=SUBJECT, client_id=None, azp="other-client")
    )[0]
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.CROSS_CLIENT


def test_wrong_user_class_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    service = make_service(world.spi, user_token=token(subject=SUBJECT, client_id=CLIENT))[0]
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS


def test_attestation_failure_rejects_before_verification():
    world = World(InMemoryMtmfSpi()).seed()
    service, service_spy, user_spy = make_service(world.spi, attestor=AttestorSpy(fail=True))
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
    assert service_spy.calls == [] and user_spy.calls == []


def test_revoked_application_binding_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    world.spi.seed_service_credential_binding(
        ServiceCredentialBinding(
            id=DomainId.generate(),
            issuer=ISS,
            client_id="revoked-client",
            application_id=world.application.id,
            created_at=datetime.now(UTC),
            lifecycle=BindingLifecycle.REVOKED,
        )
    )
    service = make_service(
        world.spi,
        service_token=token(subject="sa", client_id="revoked-client", azp="revoked-client"),
        user_token=token(subject=SUBJECT, client_id=None, azp="revoked-client"),
    )[0]
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.UNKNOWN_APPLICATION


def test_revoked_subject_binding_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    world.spi.seed_external_subject_binding(
        ExternalSubjectBinding(
            id=DomainId.generate(),
            issuer=ISS,
            subject="revoked-subject",
            identity_id=world.identity.id,
            created_at=datetime.now(UTC),
            lifecycle=BindingLifecycle.REVOKED,
        )
    )
    service = make_service(world.spi, user_token=token(subject="revoked-subject", client_id=None))[
        0
    ]
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.UNKNOWN_SUBJECT


def test_root_identity_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    world.spi.seed_root_registry(
        RootRegistryRecord(
            root_tenant_id=world.tenant.id,
            root_principal_id=world.principal.id,
            root_identity_id=world.identity.id,
        )
    )
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.ROOT_FORBIDDEN


def test_inactive_identity_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    with world.spi.create_unit_of_work() as uow:
        repo = world.spi.create_identity_repository(uow)
        identity = repo.get(world.identity.id)
        assert identity is not None
        identity.deletion_status = DeletionStatus.DELETED
        repo.save(identity)
        uow.commit()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INACTIVE_ACTOR


def test_missing_tenant_membership_is_rejected():
    world = World(InMemoryMtmfSpi(), memberships=False).seed()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_TENANT


def test_ineligible_subscription_is_rejected():
    world = World(InMemoryMtmfSpi(), subscription_lifecycle=SubscriptionLifecycle.PENDING).seed()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_SUBSCRIPTION


def test_missing_service_token_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    service, _, _ = make_service(world.spi)
    with pytest.raises(AuthenticationError) as exc:
        service.resolve(service_token="", user_token="user", tenant_id=world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INVALID_REQUEST


def test_missing_user_token_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    service, _, _ = make_service(world.spi)
    with pytest.raises(AuthenticationError) as exc:
        service.resolve(service_token="service", user_token="", tenant_id=world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INVALID_REQUEST


def test_inactive_tenant_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    with world.spi.create_unit_of_work() as uow:
        repo = world.spi.create_tenant_repository(uow)
        tenant = repo.get(world.tenant.id)
        assert tenant is not None
        tenant.lifecycle = TenantLifecycle.SUSPENDED
        repo.save(tenant)
        uow.commit()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_TENANT


def test_missing_active_registration_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    with world.spi.create_unit_of_work() as uow:
        repo = world.spi.create_application_tenant_registration_repository(uow)
        registration = repo.get(world.registration.id)
        assert registration is not None
        registration.lifecycle = RegistrationLifecycle.REVOKED
        repo.save(registration)
        uow.commit()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_REGISTRATION


def test_other_tenant_without_membership_is_rejected():
    world = World(InMemoryMtmfSpi()).seed()
    other_tenant = Tenant(
        id=DomainId.generate(),
        name="other",
        scope=SecurityScope.TENANT,
        owner_identity_id=world.identity.id,
        lifecycle=TenantLifecycle.ACTIVE,
    )
    with world.spi.create_unit_of_work() as uow:
        world.spi.create_tenant_repository(uow).add(other_tenant)
        uow.commit()
    with pytest.raises(AuthenticationError) as exc:
        resolve(make_service(world.spi)[0], other_tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_TENANT


class FailingSpi:
    """SPI whose UnitOfWork acquisition fails, simulating database outage."""

    def create_unit_of_work(self):
        from mtmf_core.persistence.errors import PersistenceError

        raise PersistenceError("database unavailable")

    def __getattr__(self, name: str):
        raise AssertionError(f"unexpected SPI access: {name}")


def test_database_unavailable_is_typed_infrastructure_failure():
    world = World(InMemoryMtmfSpi()).seed()
    service = AuthenticatedActorContextService(
        spi=FailingSpi(),  # type: ignore[arg-type]
        attestor=AttestorSpy(),
        service_verifier=VerifierSpy({"service": token(subject="sa", client_id=CLIENT)}),
        service_profile=IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs"),
        user_verifier=VerifierSpy({"user": token(subject=SUBJECT, client_id=None)}),
        user_profile=IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs"),
    )
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.INFRASTRUCTURE


def test_revoked_binding_is_not_reused_on_next_resolution():
    world = World(InMemoryMtmfSpi()).seed()
    service = make_service(world.spi)[0]
    first = resolve(service, world.tenant.id)
    assert first.application_id == world.application.id
    with world.spi.create_unit_of_work() as uow:
        repo = world.spi.create_service_credential_application_repository(uow)
        binding = repo.find_active_by_key(ISS, CLIENT)
        assert binding is not None
        repo.revoke(binding.id)
        uow.commit()
    with pytest.raises(AuthenticationError) as exc:
        resolve(service, world.tenant.id)
    assert exc.value.failure is AuthenticationFailure.UNKNOWN_APPLICATION
