"""Typed classification of failures into the closed audit reason taxonomy.

Reason codes are derived exclusively from typed exceptions and stable
error codes. Exception text is never inspected, so a raw provider message
or SQL fragment can never become a reason code. An ambiguous or unknown
failure becomes ``INTERNAL_ERROR`` instead of a guess.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_api.errors import ApiContractValidationError, ApiErrorCode
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.persistence.errors import PersistenceError
from mtmf_service.authentication.config import AuthenticationConfigError
from mtmf_service.errors import PublicError
from mtmf_service.observability.events import AuditEventName, AuditReason
from mtmf_service.settings import ServiceConfigurationError

__all__ = ["AuditClassification", "classify_failure"]

_AUTH_FAILURE = AuditEventName.AUTHENTICATION_REJECTED
_CONTEXT_FAILURE = AuditEventName.CONTEXT_REJECTED
_SUBSCRIPTION_FAILURE = AuditEventName.SUBSCRIPTION_REJECTED
_REQUEST_FAILURE = AuditEventName.REQUEST_REJECTED
_ERROR = AuditEventName.AUTHORIZATION_ERROR

#: Typed authentication failures that represent a trusted dependency
#: outage rather than a caller fault.
_DEPENDENCY_AUTH_FAILURES = frozenset(
    {
        AuthenticationFailure.ATTESTATION_UNAVAILABLE,
        AuthenticationFailure.ATTESTATION_DRIFT,
    }
)

#: Typed authentication failures that are an Application/subscription
#: eligibility rejection. Never converted into a policy DENY.
_SUBSCRIPTION_AUTH_FAILURES = frozenset(
    {
        AuthenticationFailure.UNKNOWN_APPLICATION,
        AuthenticationFailure.INELIGIBLE_REGISTRATION,
        AuthenticationFailure.INELIGIBLE_SUBSCRIPTION,
    }
)

#: Typed authentication failures that are an actor-context binding
#: rejection (verified caller, unusable context).
_CONTEXT_AUTH_FAILURES = frozenset(
    {
        AuthenticationFailure.UNKNOWN_SUBJECT,
        AuthenticationFailure.INACTIVE_ACTOR,
        AuthenticationFailure.INELIGIBLE_TENANT,
        AuthenticationFailure.ROOT_FORBIDDEN,
        AuthenticationFailure.INELIGIBLE_CONTEXT,
    }
)

_PUBLIC_CODE_CLASSIFICATION: dict[ApiErrorCode, tuple[AuditEventName, AuditReason]] = {
    ApiErrorCode.INVALID_REQUEST: (_REQUEST_FAILURE, AuditReason.INVALID_REQUEST),
    ApiErrorCode.REQUEST_TOO_LARGE: (_REQUEST_FAILURE, AuditReason.INVALID_REQUEST),
    ApiErrorCode.UNSUPPORTED_MEDIA_TYPE: (_REQUEST_FAILURE, AuditReason.INVALID_REQUEST),
    ApiErrorCode.RATE_LIMITED: (_REQUEST_FAILURE, AuditReason.RATE_LIMITED),
    ApiErrorCode.UNAUTHENTICATED: (
        _AUTH_FAILURE,
        AuditReason.SERVICE_AUTHENTICATION_FAILED,
    ),
    ApiErrorCode.UNTRUSTED_ACTOR: (_AUTH_FAILURE, AuditReason.USER_AUTHENTICATION_FAILED),
    ApiErrorCode.INELIGIBLE_APPLICATION: (
        _SUBSCRIPTION_FAILURE,
        AuditReason.SUBSCRIPTION_INELIGIBLE,
    ),
    ApiErrorCode.FORBIDDEN: (_REQUEST_FAILURE, AuditReason.OPERATION_FORBIDDEN),
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: (_ERROR, AuditReason.DATABASE_UNAVAILABLE),
    ApiErrorCode.INTERNAL_ERROR: (_ERROR, AuditReason.INTERNAL_ERROR),
}


@dataclass(frozen=True, slots=True)
class AuditClassification:
    """A terminal audit event name paired with a bounded reason code."""

    event_name: AuditEventName
    reason_code: AuditReason


def classify_failure(error: BaseException) -> AuditClassification:
    """Classify ``error`` into a terminal event name and reason code."""
    if isinstance(error, PublicError):
        override = _override_reason(error)
        if override is not None:
            return AuditClassification(_REQUEST_FAILURE, override)
        classification = _PUBLIC_CODE_CLASSIFICATION.get(error.code)
        if classification is not None:
            return AuditClassification(*classification)
        return AuditClassification(_ERROR, AuditReason.INTERNAL_ERROR)
    if isinstance(error, AuthenticationError):
        return _classify_authentication(error)
    if isinstance(error, PersistenceError):
        return AuditClassification(_ERROR, AuditReason.DATABASE_UNAVAILABLE)
    if isinstance(error, ApiContractValidationError):
        from mtmf_api.conformance import ResponseConformanceError

        if isinstance(error, ResponseConformanceError):
            return AuditClassification(_ERROR, AuditReason.EVALUATION_ERROR)
        return AuditClassification(_REQUEST_FAILURE, AuditReason.INVALID_REQUEST)
    if isinstance(error, (AuthenticationConfigError, ServiceConfigurationError)):
        return AuditClassification(_ERROR, AuditReason.INTERNAL_ERROR)
    # Imported lazily to keep this module importable without the service
    # orchestrator (and to avoid a circular import at module load).
    from mtmf_service.evaluation import InternalEvaluationError

    if isinstance(error, InternalEvaluationError):
        return AuditClassification(_ERROR, AuditReason.EVALUATION_ERROR)
    return AuditClassification(_ERROR, AuditReason.INTERNAL_ERROR)


def _override_reason(error: PublicError) -> AuditReason | None:
    raw = error.audit_reason
    if raw is None:
        return None
    try:
        return AuditReason(raw)
    except ValueError:
        return None


def _classify_authentication(error: AuthenticationError) -> AuditClassification:
    failure = error.failure
    if failure is AuthenticationFailure.INFRASTRUCTURE:
        return AuditClassification(_ERROR, AuditReason.DATABASE_UNAVAILABLE)
    if failure in _DEPENDENCY_AUTH_FAILURES:
        return AuditClassification(_ERROR, AuditReason.ISSUER_UNAVAILABLE)
    if failure is AuthenticationFailure.INVALID_REQUEST:
        return AuditClassification(_REQUEST_FAILURE, AuditReason.INVALID_REQUEST)
    if failure in _SUBSCRIPTION_AUTH_FAILURES:
        return AuditClassification(_SUBSCRIPTION_FAILURE, AuditReason.SUBSCRIPTION_INELIGIBLE)
    if failure in _CONTEXT_AUTH_FAILURES:
        return AuditClassification(_CONTEXT_FAILURE, AuditReason.ACTOR_CONTEXT_INVALID)
    if error.slot == "service":
        return AuditClassification(_AUTH_FAILURE, AuditReason.SERVICE_AUTHENTICATION_FAILED)
    if error.slot == "user":
        return AuditClassification(_AUTH_FAILURE, AuditReason.USER_AUTHENTICATION_FAILED)
    return AuditClassification(_AUTH_FAILURE, AuditReason.INTERNAL_ERROR)
