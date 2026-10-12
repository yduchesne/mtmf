"""Provider-neutral PR 14 authentication contracts.

These are immutable, detached value objects. They carry no raw JWT, secret,
connection, or transport object, and constructing them confers no authority;
only the trusted verifier and actor-composition service create them.

Package ownership (approved §10/§14H): ``mtmf-core`` owns these
provider-neutral contracts, class predicates, and domain actor composition;
``mtmf-service`` owns HTTP/JWKS transport, configuration, attestation and
assembly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from mtmf_core.domain.identity import DomainId

__all__ = [
    "AuthenticationError",
    "AuthenticationFailure",
    "ExternalSubjectKey",
    "IssuerProfile",
    "ServiceCredentialKey",
    "VerifiedAccessToken",
    "VerifiedActorContext",
]


class AuthenticationFailure(StrEnum):
    """Stable, non-sensitive authentication failure categories.

    External HTTP error mapping belongs to PR 15; these categories must not
    reveal account existence to untrusted callers when surfaced later.
    """

    INVALID_REQUEST = "invalid_request"
    ATTESTATION_UNAVAILABLE = "attestation_unavailable"
    ATTESTATION_DRIFT = "attestation_drift"
    INVALID_TOKEN = "invalid_token"
    EXPIRED_TOKEN = "expired_token"
    IMMATURE_TOKEN = "immature_token"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_TOKEN_CLASS = "wrong_token_class"
    CROSS_CLIENT = "cross_client"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    UNKNOWN_APPLICATION = "unknown_application"
    UNKNOWN_SUBJECT = "unknown_subject"
    INACTIVE_ACTOR = "inactive_actor"
    #: Requested ordinary-Tenant context is unusable: the Tenant is missing,
    #: non-ordinary/inactive, or the verified actor lacks the required
    #: memberships. PR 17 maps this to the public ``UNTRUSTED_ACTOR`` code.
    INELIGIBLE_TENANT = "ineligible_tenant"
    #: No ACTIVE Application-Tenant registration covers the exact pair. PR 17
    #: maps this to the public ``INELIGIBLE_APPLICATION`` code.
    INELIGIBLE_REGISTRATION = "ineligible_registration"
    #: No currently in-window ACTIVE subscription covers the exact pair. PR 17
    #: maps this to the public ``INELIGIBLE_APPLICATION`` code.
    INELIGIBLE_SUBSCRIPTION = "ineligible_subscription"
    #: Retained for compatibility with the pre-PR-17 coarse category. New code
    #: must raise one of the three precise categories above instead.
    INELIGIBLE_CONTEXT = "ineligible_context"
    ROOT_FORBIDDEN = "root_forbidden"
    INFRASTRUCTURE = "infrastructure_unavailable"


class AuthenticationError(Exception):
    """A typed, sanitized authentication/trust failure.

    This is never a policy ``DENY`` and never an ``ALLOW``; it carries a
    stable category and a short non-sensitive message only.

    :attr:`slot` optionally identifies which independently verified token
    slot produced the failure (``"service"`` or ``"user"``). It is
    additive, non-sensitive routing evidence for the HTTP adapter's error
    mapping; it is never part of a public wire body and never changes the
    authenticated/denied outcome.
    """

    __slots__ = ("failure", "slot")

    def __init__(
        self,
        failure: AuthenticationFailure,
        message: str = "",
        *,
        slot: str | None = None,
    ) -> None:
        self.failure = failure
        self.slot = slot
        super().__init__(message or failure.value)


@dataclass(frozen=True, slots=True)
class IssuerProfile:
    """A configured, trusted issuer validation profile (development-only)."""

    issuer: str
    audience: str
    jwks_uri: str
    algorithms: frozenset[str] = frozenset({"RS256"})

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience or not self.jwks_uri:
            raise ValueError("issuer, audience and jwks_uri are required")
        if not self.algorithms or not self.algorithms <= {"RS256", "ES256", "PS256"}:
            raise ValueError("only reviewed asymmetric algorithms are permitted")


@dataclass(frozen=True, slots=True)
class VerifiedAccessToken:
    """A signature- and profile-verified access token (typed, detached).

    ``client_id`` is present only for the client-credentials service class
    (the built-in session-note claim); it is ``None`` for interactive user
    access tokens. ``azp`` and ``subject`` are always present.
    """

    issuer: str
    subject: str
    audiences: frozenset[str]
    azp: str
    client_id: str | None
    token_type: str
    issued_at: datetime
    expires_at: datetime
    not_before: datetime | None

    @property
    def is_service_class(self) -> bool:
        """Whether the token carries the client-credentials class evidence."""
        return (
            self.token_type == "Bearer"
            and bool(self.azp)
            and self.client_id is not None
            and self.client_id == self.azp
        )

    @property
    def is_user_class(self) -> bool:
        """Whether the token carries the interactive-user class evidence."""
        return (
            self.token_type == "Bearer"
            and bool(self.azp)
            and bool(self.subject)
            and self.client_id is None
        )


@dataclass(frozen=True, slots=True)
class ServiceCredentialKey:
    """Immutable semantic key ``(issuer, client_id)`` for one Application."""

    issuer: str
    client_id: str


@dataclass(frozen=True, slots=True)
class ExternalSubjectKey:
    """Immutable semantic key ``(issuer, subject)`` for one Identity."""

    issuer: str
    subject: str


@dataclass(frozen=True, slots=True)
class VerifiedActorContext:
    """One verified Application + acting Identity + ordinary Tenant context.

    This is authentication/trust output only. It is not an authorization
    decision and never an ``ALLOW``.
    """

    application_id: DomainId
    identity_id: DomainId
    principal_id: DomainId
    tenant_id: DomainId
    service_credential: ServiceCredentialKey
    external_subject: ExternalSubjectKey
