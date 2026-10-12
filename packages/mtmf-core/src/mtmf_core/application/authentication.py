"""Verified D1 actor-context composition (PR 14, development-only).

This application-layer service composes the trusted attestation, two
independently verified access tokens, persisted bindings, and the existing
PR 13 eligibility service into one immutable
:class:`~mtmf_core.authentication.contracts.VerifiedActorContext`.

It never evaluates an Action, never issues an ``ALLOW``, and never lets a
caller-supplied Identity, Principal, Application or Tenant UUID authenticate.
Attestation is performed for every call (zero positive caching is the
attestor's contract); any attestation failure rejects both token classes.
Root identities/Tenants always fail closed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from mtmf_core.application.application_eligibility import (
    ApplicationTenantEligibilityService,
)
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    ExternalSubjectKey,
    IssuerProfile,
    ServiceCredentialKey,
    VerifiedAccessToken,
    VerifiedActorContext,
)
from mtmf_core.authentication.ports import ConfigurationAttestor, TokenVerifier
from mtmf_core.domain.authentication_binding import BindingLifecycle
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    DeletionStatus,
    IdentityOrigin,
    RegistrationLifecycle,
    TenantLifecycle,
)
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = ["AuthenticatedActorContextService"]


class AuthenticatedActorContextService:
    """Compose one verified D1 actor context from two verified tokens."""

    __slots__ = (
        "_attestor",
        "_eligibility",
        "_service_profile",
        "_service_verifier",
        "_spi",
        "_user_profile",
        "_user_verifier",
    )

    def __init__(
        self,
        *,
        spi: MtmfSpi,
        attestor: ConfigurationAttestor,
        service_verifier: TokenVerifier,
        service_profile: IssuerProfile,
        user_verifier: TokenVerifier,
        user_profile: IssuerProfile,
        eligibility: ApplicationTenantEligibilityService | None = None,
    ) -> None:
        self._spi = spi
        self._attestor = attestor
        self._service_verifier = service_verifier
        self._service_profile = service_profile
        self._user_verifier = user_verifier
        self._user_profile = user_profile
        self._eligibility = eligibility or ApplicationTenantEligibilityService(spi)

    def resolve(
        self,
        *,
        service_token: str,
        user_token: str,
        tenant_id: DomainId,
        at: datetime | None = None,
    ) -> VerifiedActorContext:
        """Verify both tokens and compose one ordinary-Tenant actor context.

        :raises AuthenticationError: on any attestation, trust, class,
            binding, lifecycle, membership or eligibility failure.
        """
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_REQUEST,
                "an authentication instant must be timezone-aware",
            )

        # Fresh, zero-cache attestation precedes acceptance of either token.
        self._attestor.attest(self._service_profile)

        service = self._verify(service_token, self._service_verifier, self._service_profile)
        user = self._verify(user_token, self._user_verifier, self._user_profile)
        self._require_service_class(service)
        self._require_user_class(user)
        if service.azp != user.azp:
            raise AuthenticationError(
                AuthenticationFailure.CROSS_CLIENT,
                "the service and user tokens were issued to different clients",
            )
        if (
            service.issuer != self._service_profile.issuer
            or user.issuer != self._user_profile.issuer
        ):
            raise AuthenticationError(
                AuthenticationFailure.UNTRUSTED_ISSUER, "issuer did not match the trusted profile"
            )

        service_key = ServiceCredentialKey(issuer=service.issuer, client_id=service.azp)
        subject_key = ExternalSubjectKey(issuer=user.issuer, subject=user.subject)

        try:
            with self._spi.create_unit_of_work() as uow:
                return self._compose(uow, service_key, subject_key, tenant_id, instant)
        except AuthenticationError:
            raise
        except PersistenceError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "persistence was unavailable"
            ) from exc

    # -- verification ------------------------------------------------------
    @staticmethod
    def _verify(token: str, verifier: TokenVerifier, profile: IssuerProfile) -> VerifiedAccessToken:
        if not token:
            raise AuthenticationError(AuthenticationFailure.INVALID_REQUEST, "a token is required")
        return verifier.verify(token, profile)

    @staticmethod
    def _require_service_class(token: VerifiedAccessToken) -> None:
        if not token.is_service_class:
            raise AuthenticationError(
                AuthenticationFailure.WRONG_TOKEN_CLASS,
                "the service token did not carry client-credentials class evidence",
            )

    @staticmethod
    def _require_user_class(token: VerifiedAccessToken) -> None:
        if not token.is_user_class:
            raise AuthenticationError(
                AuthenticationFailure.WRONG_TOKEN_CLASS,
                "the user token did not carry interactive-user class evidence",
            )

    # -- composition -------------------------------------------------------
    def _compose(
        self,
        uow: UnitOfWork,
        service_key: ServiceCredentialKey,
        subject_key: ExternalSubjectKey,
        tenant_id: DomainId,
        instant: datetime,
    ) -> VerifiedActorContext:
        application_id = self._resolve_application(uow, service_key)
        identity_id = self._resolve_identity(uow, subject_key)

        application = self._spi.create_application_repository(uow).get(application_id)
        if application is None or application.lifecycle is not ApplicationLifecycle.ACTIVE:
            raise AuthenticationError(
                AuthenticationFailure.UNKNOWN_APPLICATION, "the Application is not active"
            )
        identity = self._spi.create_identity_repository(uow).get(identity_id)
        if (
            identity is None
            or identity.deletion_status is not DeletionStatus.NOT_DELETED
            or identity.origin is not IdentityOrigin.FEDERATED
        ):
            raise AuthenticationError(
                AuthenticationFailure.INACTIVE_ACTOR,
                "the Identity is not an active federated Identity",
            )
        principal = self._spi.create_principal_repository(uow).get(identity.principal_id)
        if principal is None or principal.deletion_status is not DeletionStatus.NOT_DELETED:
            raise AuthenticationError(
                AuthenticationFailure.INACTIVE_ACTOR, "the Principal is not active"
            )
        tenant = self._spi.create_tenant_repository(uow).get(tenant_id)
        if (
            tenant is None
            or tenant.deletion_status is not DeletionStatus.NOT_DELETED
            or tenant.lifecycle is not TenantLifecycle.ACTIVE
            or tenant.scope is not SecurityScope.TENANT
        ):
            raise AuthenticationError(
                AuthenticationFailure.INELIGIBLE_CONTEXT,
                "the Tenant is not an active ordinary Tenant",
            )

        self._reject_root(uow, identity_id, principal.id, tenant_id)

        if (
            self._spi.create_identity_tenant_membership_repository(uow).get(identity_id, tenant_id)
            is None
        ):
            raise AuthenticationError(
                AuthenticationFailure.INELIGIBLE_CONTEXT,
                "the Identity is not a member of the selected Tenant",
            )
        if (
            self._spi.create_principal_tenant_membership_repository(uow).get(
                principal.id, tenant_id
            )
            is None
        ):
            raise AuthenticationError(
                AuthenticationFailure.INELIGIBLE_CONTEXT,
                "the Principal is not a member of the selected Tenant",
            )

        registration = self._spi.create_application_tenant_registration_repository(
            uow
        ).find_by_application_and_tenant(application_id, tenant_id)
        if not any(row.lifecycle is RegistrationLifecycle.ACTIVE for row in registration):
            raise AuthenticationError(
                AuthenticationFailure.INELIGIBLE_CONTEXT,
                "the Application is not actively registered for the Tenant",
            )

        eligibility = self._eligibility.evaluate(
            uow, application_id=application_id, tenant_id=tenant_id, at=instant
        )
        if not eligibility.eligible:
            raise AuthenticationError(
                AuthenticationFailure.INELIGIBLE_CONTEXT,
                "the Application subscription is not eligible",
            )

        return VerifiedActorContext(
            application_id=application_id,
            identity_id=identity_id,
            principal_id=principal.id,
            tenant_id=tenant_id,
            service_credential=service_key,
            external_subject=subject_key,
        )

    def _resolve_application(self, uow: UnitOfWork, key: ServiceCredentialKey) -> DomainId:
        binding = self._spi.create_service_credential_application_repository(
            uow
        ).find_active_by_key(key.issuer, key.client_id)
        if binding is None or binding.lifecycle is not BindingLifecycle.ACTIVE:
            raise AuthenticationError(
                AuthenticationFailure.UNKNOWN_APPLICATION,
                "no active Application binding exists for the service credential",
            )
        return binding.application_id

    def _resolve_identity(self, uow: UnitOfWork, key: ExternalSubjectKey) -> DomainId:
        binding = self._spi.create_external_subject_binding_repository(uow).find_active_by_key(
            key.issuer, key.subject
        )
        if binding is None or binding.lifecycle is not BindingLifecycle.ACTIVE:
            raise AuthenticationError(
                AuthenticationFailure.UNKNOWN_SUBJECT,
                "no active Identity binding exists for the external subject",
            )
        return binding.identity_id

    def _reject_root(
        self,
        uow: UnitOfWork,
        identity_id: DomainId,
        principal_id: DomainId,
        tenant_id: DomainId,
    ) -> None:
        root = self._spi.create_root_registry_repository(uow).get()
        if root is None:
            return
        if (
            identity_id == root.root_identity_id
            or principal_id == root.root_principal_id
            or tenant_id == root.root_tenant_id
        ):
            raise AuthenticationError(
                AuthenticationFailure.ROOT_FORBIDDEN,
                "root context is never available through ordinary D1 authentication",
            )
