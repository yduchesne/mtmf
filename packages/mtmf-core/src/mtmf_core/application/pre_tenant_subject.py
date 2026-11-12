"""Read-only pre-Tenant verified-subject resolution (PR 23).

This application-layer service answers one narrow question: given two
independently verified access tokens (an approved service credential and an
interactive user proof), which Application and exact external
``(issuer, subject)`` are trusted, and does that subject already resolve to a
global Identity/Principal?

It deliberately requires **no** Tenant, membership, Role, registration,
subscription or onboarding entitlement, because a genuinely new subject has
none of those. It never creates an Identity/Principal/binding, never issues an
``ALLOW``, never opens a privileged transaction and never calls ``commit()``.
The returned :class:`~mtmf_core.authentication.contracts.VerifiedPreTenantSubject`
is detached internal evidence only; a future privileged executor (PR 24P/22B)
must revalidate all authoritative database state under its own transaction.

All external attestation/verification work completes before any UnitOfWork is
opened, and every backend failure maps to the existing typed infrastructure
failure rather than a false "unknown subject" success.
"""

from __future__ import annotations

from datetime import UTC, datetime

from mtmf_core.application.authentication import _verify_token_pair
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    ExternalSubjectKey,
    IssuerProfile,
    ServiceCredentialKey,
    VerifiedPreTenantSubject,
)
from mtmf_core.authentication.ports import ConfigurationAttestor, TokenVerifier
from mtmf_core.domain.authentication_binding import BindingLifecycle
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.lifecycle import ApplicationLifecycle, DeletionStatus, IdentityOrigin
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = ["PreTenantSubjectVerificationService"]


class PreTenantSubjectVerificationService:
    """Resolve a verified pre-Tenant subject without Tenant authority."""

    __slots__ = (
        "_attestor",
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
    ) -> None:
        self._spi = spi
        self._attestor = attestor
        self._service_verifier = service_verifier
        self._service_profile = service_profile
        self._user_verifier = user_verifier
        self._user_profile = user_profile

    def verify(
        self,
        *,
        service_token: str,
        user_token: str,
        at: datetime | None = None,
    ) -> VerifiedPreTenantSubject:
        """Verify both tokens and resolve the detached pre-Tenant subject.

        No Tenant/membership/entitlement read is performed and no write is
        staged. The UnitOfWork is left without committing.

        :raises AuthenticationError: on malformed input, any attestation,
            trust, class, issuer, binding, lifecycle or root-exclusion
            failure, or on any backend failure.
        """
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_REQUEST,
                "a verification instant must be timezone-aware",
            )
        if not service_token or not user_token:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_REQUEST,
                "both a service token and a user token are required",
                slot="service" if not service_token else "user",
            )

        service, user = _verify_token_pair(
            attestor=self._attestor,
            service_token=service_token,
            service_verifier=self._service_verifier,
            service_profile=self._service_profile,
            user_token=user_token,
            user_verifier=self._user_verifier,
            user_profile=self._user_profile,
        )

        service_key = ServiceCredentialKey(issuer=service.issuer, client_id=service.azp)
        subject_key = ExternalSubjectKey(issuer=user.issuer, subject=user.subject)

        try:
            with self._spi.create_unit_of_work() as uow:
                return self._compose(uow, service_key, subject_key, instant, user.expires_at)
        except AuthenticationError:
            raise
        except PersistenceError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "persistence was unavailable"
            ) from exc

    # -- composition -------------------------------------------------------
    def _compose(
        self,
        uow: UnitOfWork,
        service_key: ServiceCredentialKey,
        subject_key: ExternalSubjectKey,
        instant: datetime,
        user_token_expires_at: datetime,
    ) -> VerifiedPreTenantSubject:
        application_id = self._resolve_application(uow, service_key)
        application = self._spi.create_application_repository(uow).get(application_id)
        if application is None or application.lifecycle is not ApplicationLifecycle.ACTIVE:
            raise AuthenticationError(
                AuthenticationFailure.UNKNOWN_APPLICATION, "the Application is not active"
            )

        root = self._spi.create_root_registry_repository(uow).get()
        if root is None:
            # A new Tenant requires the initialized canonical root registry; the
            # pre-Tenant seam never auto-initializes it.
            raise AuthenticationError(
                AuthenticationFailure.ROOT_FORBIDDEN,
                "pre-Tenant subject verification requires an initialized root registry",
            )

        binding = self._spi.create_external_subject_binding_repository(uow).find_active_by_key(
            subject_key.issuer, subject_key.subject
        )
        if binding is None or binding.lifecycle is not BindingLifecycle.ACTIVE:
            # No active global binding: a genuinely new subject candidate. This
            # is not an ALLOW and never creates the Identity/Principal.
            return VerifiedPreTenantSubject(
                application_id=application_id,
                service_credential=service_key,
                external_subject=subject_key,
                verified_at=instant,
                user_token_expires_at=user_token_expires_at,
                existing_identity_id=None,
                existing_principal_id=None,
            )

        identity = self._spi.create_identity_repository(uow).get(binding.identity_id)
        if (
            identity is None
            or identity.deletion_status is not DeletionStatus.NOT_DELETED
            or identity.origin is not IdentityOrigin.FEDERATED
        ):
            raise AuthenticationError(
                AuthenticationFailure.INACTIVE_ACTOR,
                "the bound Identity is not an active federated Identity",
            )
        principal = self._spi.create_principal_repository(uow).get(identity.principal_id)
        if principal is None or principal.deletion_status is not DeletionStatus.NOT_DELETED:
            raise AuthenticationError(
                AuthenticationFailure.INACTIVE_ACTOR, "the bound Principal is not active"
            )
        if identity.id == root.root_identity_id or principal.id == root.root_principal_id:
            raise AuthenticationError(
                AuthenticationFailure.ROOT_FORBIDDEN,
                "canonical root subjects are never available through the pre-Tenant seam",
            )

        return VerifiedPreTenantSubject(
            application_id=application_id,
            service_credential=service_key,
            external_subject=subject_key,
            verified_at=instant,
            user_token_expires_at=user_token_expires_at,
            existing_identity_id=identity.id,
            existing_principal_id=principal.id,
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
