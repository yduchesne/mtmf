"""Deterministic unit acceptance for the PR 23 pre-Tenant subject seam.

These tests use the in-memory SPI, the PR 14 verifier/attestor doubles and
never touch a database or live issuer. They prove orchestration, trust
ordering, global-subject resolution, root exclusion, detachment and the
absence of any Tenant/write/commit requirement. They do NOT claim that a
hand-built ``VerifiedPreTenantSubject`` is cryptographic proof.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.pre_tenant_subject import PreTenantSubjectVerificationService
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
    VerifiedAccessToken,
    VerifiedPreTenantSubject,
)
from mtmf_core.domain.application import Application
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
    TenantLifecycle,
)
from mtmf_core.domain.principal import Principal
from mtmf_core.persistence.errors import PersistenceError
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
        self.client_calls: list[str] = []
        self.order: list[str] = []

    def attest(self, profile: IssuerProfile) -> None:
        self.calls += 1
        self.order.append("attest")
        if self.fail:
            raise AuthenticationError(AuthenticationFailure.ATTESTATION_DRIFT, "forced drift")

    def attest_client(self, profile: IssuerProfile, client_id: str) -> None:
        self.client_calls.append(client_id)
        self.order.append(f"attest_client:{client_id}")
        if self.fail:
            raise AuthenticationError(AuthenticationFailure.ATTESTATION_DRIFT, "forced drift")


class RecordingSpi:
    """SPI proxy that records UnitOfWork commits and delegates everything else."""

    def __init__(self, inner: InMemoryMtmfSpi) -> None:
        self.inner = inner
        self.commits = 0

    def create_unit_of_work(self):
        uow = self.inner.create_unit_of_work()
        original = uow.commit

        def commit() -> None:
            self.commits += 1
            original()

        uow.commit = commit  # type: ignore[method-assign]
        return uow

    def __getattr__(self, name: str):
        return getattr(self.inner, name)


class FailingSpi:
    """SPI whose UnitOfWork acquisition fails, simulating database outage."""

    def create_unit_of_work(self):
        raise PersistenceError("database unavailable")


def token(
    *,
    subject: str = SUBJECT,
    client_id: str | None = None,
    azp: str = CLIENT,
    issuer: str = ISS,
    audience: str | None = None,
) -> VerifiedAccessToken:
    now = datetime.now(UTC)
    return VerifiedAccessToken(
        issuer=issuer,
        subject=subject,
        audiences=frozenset({audience or (SERVICE_AUD if client_id else USER_AUD)}),
        azp=azp,
        client_id=client_id,
        token_type="Bearer",
        issued_at=now - timedelta(seconds=10),
        expires_at=now + timedelta(seconds=300),
        not_before=None,
    )


class World:
    """A seeded global subject world with no Tenant, membership or registration."""

    def __init__(
        self,
        *,
        global_subject: bool = True,
        identity_origin: IdentityOrigin = IdentityOrigin.FEDERATED,
        identity_deleted: bool = False,
        principal_deleted: bool = False,
        root: bool = True,
        application_lifecycle: ApplicationLifecycle = ApplicationLifecycle.ACTIVE,
    ) -> None:
        self.inner = InMemoryMtmfSpi()
        self.spi = RecordingSpi(self.inner)
        now = datetime.now(UTC)
        self.principal = Principal(id=DomainId.generate(), name="principal")
        self.identity = Identity(
            id=DomainId.generate(),
            principal_id=self.principal.id,
            name="identity",
            origin=identity_origin,
            deletion_status=(
                DeletionStatus.DELETED if identity_deleted else DeletionStatus.NOT_DELETED
            ),
        )
        if principal_deleted:
            self.principal.deletion_status = DeletionStatus.DELETED
        self.application = Application(
            id=DomainId.generate(),
            application_key="app",
            name="Application",
            owner_identity_id=self.identity.id,
            lifecycle=application_lifecycle,
        )
        self._global_subject = global_subject
        self._root = root
        self._now = now

    def seed(self) -> World:
        spi = self.inner
        with spi.create_unit_of_work() as uow:
            spi.create_principal_repository(uow).add(self.principal)
            spi.create_identity_repository(uow).add(self.identity)
            spi.create_application_repository(uow).add(self.application)
            uow.commit()
        spi.seed_service_credential_binding(
            ServiceCredentialBinding(
                id=DomainId.generate(),
                issuer=ISS,
                client_id=CLIENT,
                application_id=self.application.id,
                created_at=self._now,
                lifecycle=BindingLifecycle.ACTIVE,
            )
        )
        if self._global_subject:
            spi.seed_external_subject_binding(
                ExternalSubjectBinding(
                    id=DomainId.generate(),
                    issuer=ISS,
                    subject=SUBJECT,
                    identity_id=self.identity.id,
                    created_at=self._now,
                    lifecycle=BindingLifecycle.ACTIVE,
                )
            )
        if self._root:
            spi.seed_root_registry(
                RootRegistryRecord(
                    root_tenant_id=DomainId.generate(),
                    root_principal_id=DomainId.generate(),
                    root_identity_id=DomainId.generate(),
                )
            )
        return self

    def make_service(
        self,
        *,
        service_token: VerifiedAccessToken | None = None,
        user_token: VerifiedAccessToken | None = None,
        attestor: AttestorSpy | None = None,
    ) -> tuple[PreTenantSubjectVerificationService, VerifierSpy, VerifierSpy, AttestorSpy]:
        service_profile = IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs")
        user_profile = IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs")
        svc_spy = VerifierSpy({"service": service_token or token(subject="sa", client_id=CLIENT)})
        usr_spy = VerifierSpy({"user": user_token or token(subject=SUBJECT, client_id=None)})
        spy = attestor or AttestorSpy()
        service = PreTenantSubjectVerificationService(
            spi=self.spi,
            attestor=spy,
            service_verifier=svc_spy,
            service_profile=service_profile,
            user_verifier=usr_spy,
            user_profile=user_profile,
        )
        return service, svc_spy, usr_spy, spy


def verify(service: PreTenantSubjectVerificationService, **kwargs):
    return service.verify(service_token="service", user_token="user", **kwargs)


# --- A-U01..03: valid pair, exact signed azp, derived Application UUID --------


def test_a_u01_valid_pair_returns_detached_result_with_derived_application() -> None:
    world = World().seed()
    service, svc_spy, usr_spy, attestor = world.make_service()
    result = verify(service)
    assert result.application_id == world.application.id
    assert result.service_credential.issuer == ISS
    assert result.service_credential.client_id == CLIENT
    assert result.external_subject.issuer == ISS
    assert result.external_subject.subject == SUBJECT
    assert svc_spy.calls == ["service"]
    assert usr_spy.calls == ["user"]
    assert attestor.client_calls == [CLIENT, CLIENT]


def test_a_u02_application_uuid_is_derived_from_persisted_binding_not_input() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service()
    result = verify(service)
    assert result.application_id == world.application.id
    # The API accepts no caller-supplied Application/Identity/Tenant UUID at all.
    with pytest.raises(TypeError):
        service.verify(  # type: ignore[call-arg]
            service_token="service", user_token="user", application_id=DomainId.generate()
        )


def test_a_u03_attestation_precedes_token_verification() -> None:
    world = World().seed()
    service, _, _, attestor = world.make_service()
    verify(service)
    assert attestor.order[0] == "attest"
    assert attestor.order[-2:] == [f"attest_client:{CLIENT}", f"attest_client:{CLIENT}"]


# --- A-U04..06: negative trust cases -----------------------------------------


def test_a_u04_reversed_token_classes_are_rejected() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service(
        service_token=token(subject=SUBJECT, client_id=None),
        user_token=token(subject="sa", client_id=CLIENT),
    )
    with pytest.raises(AuthenticationError) as exc:
        verify(service)
    assert exc.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS


def test_a_u05_empty_or_cross_client_pair_is_rejected() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service()
    with pytest.raises(AuthenticationError) as exc:
        service.verify(service_token="", user_token="user")
    assert exc.value.failure is AuthenticationFailure.INVALID_REQUEST
    with pytest.raises(AuthenticationError) as exc:
        service.verify(service_token="service", user_token="")
    assert exc.value.failure is AuthenticationFailure.INVALID_REQUEST

    cross, _, _, _ = world.make_service(user_token=token(subject=SUBJECT, azp="other-client"))
    with pytest.raises(AuthenticationError) as exc:
        verify(cross)
    assert exc.value.failure is AuthenticationFailure.CROSS_CLIENT


def test_a_u06_wrong_issuer_and_attestation_failure_reject() -> None:
    world = World().seed()
    untrusted, _, _, _ = world.make_service(
        user_token=token(subject=SUBJECT, issuer="https://untrusted.example/realms/x")
    )
    with pytest.raises(AuthenticationError) as exc:
        verify(untrusted)
    assert exc.value.failure is AuthenticationFailure.UNTRUSTED_ISSUER

    failing, svc_spy, usr_spy, _ = world.make_service(attestor=AttestorSpy(fail=True))
    with pytest.raises(AuthenticationError) as exc:
        verify(failing)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
    assert svc_spy.calls == [] and usr_spy.calls == []


# --- A-U07..08: existing vs absent global subject ----------------------------


def test_a_u07_active_binding_returns_exact_global_uuids() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service()
    result = verify(service)
    assert result.existing_identity_id == world.identity.id
    assert result.existing_principal_id == world.principal.id


def test_a_u08_absent_active_binding_returns_both_none_without_creating() -> None:
    world = World(global_subject=False).seed()
    service, _, _, _ = world.make_service()
    result = verify(service)
    assert result.existing_identity_id is None
    assert result.existing_principal_id is None
    # No Identity/Principal/binding was created.
    with world.inner.create_unit_of_work() as uow:
        assert world.inner.create_identity_repository(uow).get(world.identity.id) is not None
        assert (
            world.inner.create_external_subject_binding_repository(uow).find_active_by_key(
                ISS, SUBJECT
            )
            is None
        )


# --- A-U09..10: structural integrity and root preconditions ------------------


def test_a_u09_deleted_or_non_federated_identity_is_rejected() -> None:
    for world in (
        World(identity_deleted=True).seed(),
        World(identity_origin=IdentityOrigin.LOCAL).seed(),
    ):
        service, _, _, _ = world.make_service()
        with pytest.raises(AuthenticationError) as exc:
            verify(service)
        assert exc.value.failure is AuthenticationFailure.INACTIVE_ACTOR

    deleted_principal = World(principal_deleted=True).seed()
    service, _, _, _ = deleted_principal.make_service()
    with pytest.raises(AuthenticationError) as exc:
        verify(service)
    assert exc.value.failure is AuthenticationFailure.INACTIVE_ACTOR


def test_a_u10_missing_root_registry_is_rejected() -> None:
    world = World(root=False).seed()
    service, _, _, _ = world.make_service()
    with pytest.raises(AuthenticationError) as exc:
        verify(service)
    assert exc.value.failure is AuthenticationFailure.ROOT_FORBIDDEN


# --- A-U11..12: no Tenant/commit/write requirement ---------------------------


def test_a_u11_no_tenant_membership_registration_or_subscription_needed() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service()
    result = verify(service)
    assert result.existing_identity_id == world.identity.id
    # The world contains no Tenant/membership/registration/subscription at all.
    with world.inner.create_unit_of_work() as uow:
        assert (
            world.inner.create_identity_tenant_membership_repository(uow).find_by_identity(
                world.identity.id
            )
            == ()
        )
        assert (
            world.inner.create_principal_tenant_membership_repository(uow).find_by_principal(
                world.principal.id
            )
            == ()
        )


def test_a_u12_verification_never_commits_or_writes() -> None:
    world = World(global_subject=False).seed()
    service, _, _, _ = world.make_service()
    verify(service)
    assert world.spi.commits == 0
    with world.inner.create_unit_of_work() as uow:
        assert world.inner.create_principal_repository(uow).get(world.principal.id) is not None
        assert (
            world.inner.create_external_subject_binding_repository(uow).find_active_by_key(
                ISS, "brand-new-subject"
            )
            is None
        )


# --- A-U13..14: instant and infrastructure failures --------------------------


def test_a_u13_naive_verification_instant_is_rejected() -> None:
    world = World().seed()
    service, svc_spy, usr_spy, _ = world.make_service()
    with pytest.raises(AuthenticationError) as exc:
        verify(service, at=datetime(2026, 1, 1, 0, 0, 0))
    assert exc.value.failure is AuthenticationFailure.INVALID_REQUEST
    assert svc_spy.calls == [] and usr_spy.calls == []


def test_a_u14_backend_fault_is_infrastructure_not_user_not_found() -> None:
    service = PreTenantSubjectVerificationService(
        spi=FailingSpi(),  # type: ignore[arg-type]
        attestor=AttestorSpy(),
        service_verifier=VerifierSpy({"service": token(subject="sa", client_id=CLIENT)}),
        service_profile=IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs"),
        user_verifier=VerifierSpy({"user": token(subject=SUBJECT, client_id=None)}),
        user_profile=IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs"),
    )
    with pytest.raises(AuthenticationError) as exc:
        verify(service)
    assert exc.value.failure is AuthenticationFailure.INFRASTRUCTURE
    assert exc.value.failure is not AuthenticationFailure.UNKNOWN_SUBJECT


# --- A-U15..16: detachment/immutability and root exclusion -------------------


def test_a_u15_result_is_immutable_and_carries_no_raw_token() -> None:
    world = World().seed()
    service, _, _, _ = world.make_service()
    result = verify(service)
    assert isinstance(result, VerifiedPreTenantSubject)
    assert not hasattr(result, "service_token")
    assert not hasattr(result, "user_token")
    with pytest.raises(FrozenInstanceError):
        result.existing_identity_id = DomainId.generate()  # type: ignore[misc]


def test_a_u16_canonical_root_subject_is_excluded() -> None:
    world = World().seed()
    world.inner.seed_root_registry(
        RootRegistryRecord(
            root_tenant_id=DomainId.generate(),
            root_principal_id=world.principal.id,
            root_identity_id=world.identity.id,
        )
    )
    service, _, _, _ = world.make_service()
    with pytest.raises(AuthenticationError) as exc:
        verify(service)
    assert exc.value.failure is AuthenticationFailure.ROOT_FORBIDDEN


# --- A-U17..18: ordinary actor resolution is unchanged ------------------------


def _ordinary_service(world: World) -> AuthenticatedActorContextService:
    return AuthenticatedActorContextService(
        spi=world.inner,
        attestor=AttestorSpy(),
        service_verifier=VerifierSpy({"service": token(subject="sa", client_id=CLIENT)}),
        service_profile=IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs"),
        user_verifier=VerifierSpy({"user": token(subject=SUBJECT, client_id=None)}),
        user_profile=IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs"),
    )


def test_a_u17_ordinary_resolution_requires_a_valid_tenant_and_memberships() -> None:
    from mtmf_core.domain.memberships import (
        IdentityTenantMembership,
        PrincipalTenantMembership,
    )
    from mtmf_core.domain.scope import SecurityScope
    from mtmf_core.domain.tenant import Tenant

    world = World().seed()
    tenant = Tenant(
        id=DomainId.generate(),
        name="tenant",
        scope=SecurityScope.TENANT,
        owner_identity_id=world.identity.id,
        lifecycle=TenantLifecycle.ACTIVE,
    )
    with world.inner.create_unit_of_work() as uow:
        world.inner.create_tenant_repository(uow).add(tenant)
        uow.commit()

    service = _ordinary_service(world)
    with pytest.raises(AuthenticationError) as exc:
        service.resolve(service_token="service", user_token="user", tenant_id=tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_TENANT

    with world.inner.create_unit_of_work() as uow:
        world.inner.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(world.principal.id, tenant.id)
        )
        world.inner.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(world.identity.id, tenant.id)
        )
        uow.commit()

    with pytest.raises(AuthenticationError) as exc:
        service.resolve(service_token="service", user_token="user", tenant_id=tenant.id)
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_REGISTRATION


def test_a_u18_ordinary_resolution_retains_attestation_semantics() -> None:
    world = World().seed()
    service = AuthenticatedActorContextService(
        spi=world.inner,
        attestor=AttestorSpy(fail=True),
        service_verifier=VerifierSpy({"service": token(subject="sa", client_id=CLIENT)}),
        service_profile=IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=f"{ISS}/certs"),
        user_verifier=VerifierSpy({"user": token(subject=SUBJECT, client_id=None)}),
        user_profile=IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=f"{ISS}/certs"),
    )
    with pytest.raises(AuthenticationError) as exc:
        service.resolve(service_token="service", user_token="user", tenant_id=DomainId.generate())
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
