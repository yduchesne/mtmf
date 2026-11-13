"""Non-authorizing pre-Tenant admission composition (PR 24P).

The service independently verifies both tokens through the existing PR 23
seam, performs one read-only privileged historical-subject/entitlement read,
and returns a detached candidacy observation. It never writes, reserves quota,
creates a Tenant, or authorizes a future composite.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    VerifiedPreTenantSubject,
)
from mtmf_core.authentication.operator_contracts import VerifiedPreTenantAdmission
from mtmf_core.domain.identity import DomainId

__all__ = [
    "AdmissionError",
    "AdmissionFailure",
    "AdmissionOutcome",
    "AdmissionReadPort",
    "CheckedFirstTenantRequest",
    "FirstTenantCompositeResult",
    "PreTenantAdmissionResult",
    "PreTenantAdmissionService",
    "PrivilegedOnboardingTransactionPort",
    "UnimplementedOnboardingExecutor",
]


class AdmissionFailure(StrEnum):
    """Sanitized admission failure categories for the private wire."""

    INVALID = "INVALID"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    CONFLICT = "CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"


class AdmissionError(Exception):
    """A sanitized admission failure; never an authorization ALLOW."""

    __slots__ = ("failure",)

    def __init__(self, failure: AdmissionFailure, message: str = "") -> None:
        self.failure = failure
        super().__init__(message or failure.value)


class AdmissionOutcome(StrEnum):
    """The only three non-error admission outcomes."""

    CANDIDATE = "CANDIDATE"
    EXISTING_SUBJECT = "EXISTING_SUBJECT"
    NO_ENTITLEMENT = "NO_ENTITLEMENT"


@dataclass(frozen=True, slots=True)
class PreTenantAdmissionResult:
    """Bounded, non-authorizing result returned by the private handler."""

    outcome: AdmissionOutcome
    application_id: DomainId
    entitlement_id: DomainId | None
    eligible_for_first_tenant: bool


class AdmissionReadPort(Protocol):
    """Read-only privileged historical-subject/entitlement read."""

    def read(self, application_id: DomainId, issuer: str, subject: str) -> Mapping[str, object]:
        """Return the exact §5A.7 internal JSON object or raise."""
        ...


class _PreTenantVerifier(Protocol):
    """The existing PR 23 verifier seam used by admission."""

    def verify(
        self, *, service_token: str, user_token: str, at: datetime
    ) -> VerifiedPreTenantSubject:
        """Return the verified detached pre-Tenant subject."""
        ...


class CheckedFirstTenantRequest(Protocol):
    """Opaque PR 22B-owned request; PR 24P defines no fields."""

    __slots__ = ()


class FirstTenantCompositeResult(Protocol):
    """Opaque PR 22B-owned result; PR 24P defines no fields."""

    __slots__ = ()


class PrivilegedOnboardingTransactionPort(Protocol):
    """Future PR 22B one-transaction composite; unimplemented in PR 24P."""

    def execute_approved_composite(
        self,
        verified_proof: VerifiedPreTenantAdmission,
        checked_request: CheckedFirstTenantRequest,
    ) -> FirstTenantCompositeResult:
        """Execute the future composite; must remain fail-closed in PR 24P."""
        ...


class UnimplementedOnboardingExecutor:
    """Fail-closed placeholder: never opens a connection or executes SQL."""

    __slots__ = ()

    def execute_approved_composite(
        self,
        verified_proof: VerifiedPreTenantAdmission,
        checked_request: CheckedFirstTenantRequest,
    ) -> FirstTenantCompositeResult:
        raise NotImplementedError("PR 22B composite is not implemented in PR 24P")


class PreTenantAdmissionService:
    """Compose one non-authorizing admission result."""

    __slots__ = ("_reader", "_verifier")

    def __init__(
        self,
        *,
        verifier: _PreTenantVerifier,
        reader: AdmissionReadPort,
    ) -> None:
        # The verifier is the existing PR 23 PreTenantSubjectVerificationService.
        self._verifier = verifier
        self._reader = reader

    def prepare(
        self,
        *,
        service_token: str,
        user_token: str,
        at: datetime | None = None,
    ) -> PreTenantAdmissionResult:
        """Verify both tokens, perform one history read, and map R01-R10."""
        instant = at or datetime.now(UTC)
        try:
            verified = self._verifier.verify(
                service_token=service_token, user_token=user_token, at=instant
            )
        except AuthenticationError as exc:
            raise AdmissionError(_map_auth_failure(exc)) from exc

        try:
            payload = self._reader.read(
                verified.application_id,
                verified.external_subject.issuer,
                verified.external_subject.subject,
            )
        except Exception as exc:
            raise AdmissionError(AdmissionFailure.UNAVAILABLE) from exc

        history, entitlement_id, quota_available = _validate_payload(payload)
        existing = verified.existing_identity_id is not None

        if history == "CONFLICT" or history == "REVOKED_ONLY":
            raise AdmissionError(AdmissionFailure.CONFLICT)
        if history == "NEVER_SEEN" and existing:
            raise AdmissionError(AdmissionFailure.CONFLICT)
        if history == "ACTIVE":
            return PreTenantAdmissionResult(
                outcome=AdmissionOutcome.EXISTING_SUBJECT,
                application_id=verified.application_id,
                entitlement_id=None,
                eligible_for_first_tenant=False,
            )
        # NEVER_SEEN and genuinely new.
        if quota_available and entitlement_id is not None:
            return PreTenantAdmissionResult(
                outcome=AdmissionOutcome.CANDIDATE,
                application_id=verified.application_id,
                entitlement_id=entitlement_id,
                eligible_for_first_tenant=True,
            )
        return PreTenantAdmissionResult(
            outcome=AdmissionOutcome.NO_ENTITLEMENT,
            application_id=verified.application_id,
            entitlement_id=None,
            eligible_for_first_tenant=False,
        )


def _map_auth_failure(exc: AuthenticationError) -> AdmissionFailure:
    failure = exc.failure.value
    if failure == "invalid_request":
        return AdmissionFailure.INVALID
    if failure in {
        "invalid_token",
        "expired_token",
        "immature_token",
        "wrong_audience",
        "wrong_token_class",
        "cross_client",
        "untrusted_issuer",
        "unknown_application",
        "unknown_subject",
        "inactive_actor",
    }:
        return AdmissionFailure.UNAUTHENTICATED
    if failure in {"attestation_unavailable", "infrastructure_unavailable"}:
        return AdmissionFailure.UNAVAILABLE
    if failure in {"attestation_drift", "root_forbidden"}:
        return AdmissionFailure.FORBIDDEN
    return AdmissionFailure.UNAVAILABLE


def _validate_payload(payload: Mapping[str, object]) -> tuple[str, DomainId | None, bool]:
    expected = {"v", "subject_history", "entitlement_id", "quota_available"}
    if set(payload) != expected or payload.get("v") != 1:
        raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    history = payload.get("subject_history")
    if history not in {"NEVER_SEEN", "ACTIVE", "REVOKED_ONLY", "CONFLICT"}:
        raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    quota = payload.get("quota_available")
    if not isinstance(quota, bool):
        raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    raw_id = payload.get("entitlement_id")
    if raw_id is None:
        entitlement_id = None
    elif isinstance(raw_id, str):
        try:
            entitlement_id = DomainId.from_str(raw_id)
        except ValueError as exc:
            raise AdmissionError(AdmissionFailure.UNAVAILABLE) from exc
    else:
        raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    if history != "NEVER_SEEN":
        if entitlement_id is not None or quota:
            raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    else:
        if quota and entitlement_id is None:
            raise AdmissionError(AdmissionFailure.UNAVAILABLE)
        if not quota and entitlement_id is not None:
            raise AdmissionError(AdmissionFailure.UNAVAILABLE)
    return str(history), entitlement_id, quota
