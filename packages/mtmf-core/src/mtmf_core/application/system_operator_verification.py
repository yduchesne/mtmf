"""Genuine interactive SYSTEM-operator proof verification (PR 24P).

The service verifies one independently signed user-class access token against
the approved issuer/client profile and resolves the exact persisted
``(issuer, subject)`` binding. It never evaluates an Action, never reads a Role
assignment, never opens a Tenant context, and never returns an authorization
decision. The privileged snapshot/wrapper later revalidate every persisted fact.
"""

from __future__ import annotations

from datetime import UTC, datetime

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    ExternalSubjectKey,
    IssuerProfile,
)
from mtmf_core.authentication.operator_contracts import VerifiedSystemOperator
from mtmf_core.authentication.ports import ConfigurationAttestor, TokenVerifier
from mtmf_core.domain.authentication_binding import BindingLifecycle
from mtmf_core.domain.lifecycle import DeletionStatus, IdentityOrigin
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.spi import MtmfSpi

__all__ = ["SystemOperatorVerificationService"]

_MAX_TOKEN_BYTES = 8192


class SystemOperatorVerificationService:
    """Verify one genuine interactive operator token and its exact binding."""

    __slots__ = ("_attestor", "_profile", "_spi", "_verifier")

    def __init__(
        self,
        *,
        spi: MtmfSpi,
        attestor: ConfigurationAttestor,
        verifier: TokenVerifier,
        profile: IssuerProfile,
    ) -> None:
        self._spi = spi
        self._attestor = attestor
        self._verifier = verifier
        self._profile = profile

    def verify(
        self, operator_user_token: str, *, at: datetime | None = None
    ) -> VerifiedSystemOperator:
        """Return an immutable operator proof or raise fail-closed."""
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_REQUEST,
                "a verification instant must be timezone-aware",
            )
        if not operator_user_token or len(operator_user_token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_REQUEST,
                "a bounded operator user access token is required",
                slot="user",
            )

        # Fresh zero-cache attestation precedes acceptance of the token.
        self._attestor.attest(self._profile)
        try:
            token = self._verifier.verify(operator_user_token, self._profile)
        except AuthenticationError:
            raise
        if not token.is_user_class:
            raise AuthenticationError(
                AuthenticationFailure.WRONG_TOKEN_CLASS,
                "the operator token did not carry interactive-user class evidence",
                slot="user",
            )
        if token.issuer != self._profile.issuer:
            raise AuthenticationError(
                AuthenticationFailure.UNTRUSTED_ISSUER,
                "the operator token issuer did not match the trusted profile",
                slot="user",
            )
        self._attestor.attest_client(self._profile, token.azp)
        if token.expires_at <= instant:
            raise AuthenticationError(
                AuthenticationFailure.EXPIRED_TOKEN, "the operator token has expired", slot="user"
            )
        if not token.subject:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN,
                "the operator token has no subject",
                slot="user",
            )

        subject_key = ExternalSubjectKey(issuer=token.issuer, subject=token.subject)
        try:
            with self._spi.create_unit_of_work() as uow:
                binding = self._spi.create_external_subject_binding_repository(
                    uow
                ).find_active_by_key(subject_key.issuer, subject_key.subject)
                if binding is None or binding.lifecycle is not BindingLifecycle.ACTIVE:
                    raise AuthenticationError(
                        AuthenticationFailure.UNKNOWN_SUBJECT,
                        "no active persisted operator binding exists",
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
                        AuthenticationFailure.INACTIVE_ACTOR,
                        "the bound Principal is not active",
                    )
                root = self._spi.create_root_registry_repository(uow).get()
                if root is None:
                    raise AuthenticationError(
                        AuthenticationFailure.ROOT_FORBIDDEN,
                        "the canonical root registry is not initialized",
                    )
                if identity.id == root.root_identity_id or principal.id == root.root_principal_id:
                    raise AuthenticationError(
                        AuthenticationFailure.ROOT_FORBIDDEN,
                        "the canonical root subject is never an operator",
                    )
                return VerifiedSystemOperator(
                    issuer=subject_key.issuer,
                    subject=subject_key.subject,
                    identity_id=identity.id,
                    principal_id=principal.id,
                    user_token_expires_at=token.expires_at,
                    verified_at=instant,
                )
        except AuthenticationError:
            raise
        except PersistenceError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "persistence was unavailable"
            ) from exc
