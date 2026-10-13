"""Typed failure classification into the closed audit reason taxonomy (O-U07)."""

from __future__ import annotations

import pytest

from mtmf_api.errors import ApiErrorCode
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.persistence.errors import PersistenceError
from mtmf_service.errors import PublicError
from mtmf_service.observability import (
    AuditEventName,
    AuditReason,
    classify_failure,
)


@pytest.mark.parametrize(
    ("code", "event_name", "reason"),
    [
        (
            ApiErrorCode.INVALID_REQUEST,
            AuditEventName.REQUEST_REJECTED,
            AuditReason.INVALID_REQUEST,
        ),
        (
            ApiErrorCode.RATE_LIMITED,
            AuditEventName.REQUEST_REJECTED,
            AuditReason.RATE_LIMITED,
        ),
        (
            ApiErrorCode.UNAUTHENTICATED,
            AuditEventName.AUTHENTICATION_REJECTED,
            AuditReason.SERVICE_AUTHENTICATION_FAILED,
        ),
        (
            ApiErrorCode.UNTRUSTED_ACTOR,
            AuditEventName.AUTHENTICATION_REJECTED,
            AuditReason.USER_AUTHENTICATION_FAILED,
        ),
        (
            ApiErrorCode.INELIGIBLE_APPLICATION,
            AuditEventName.SUBSCRIPTION_REJECTED,
            AuditReason.SUBSCRIPTION_INELIGIBLE,
        ),
        (
            ApiErrorCode.INTERNAL_ERROR,
            AuditEventName.AUTHORIZATION_ERROR,
            AuditReason.INTERNAL_ERROR,
        ),
        (
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            AuditEventName.AUTHORIZATION_ERROR,
            AuditReason.DATABASE_UNAVAILABLE,
        ),
    ],
)
def test_public_codes_map_to_closed_reasons(
    code: ApiErrorCode, event_name: AuditEventName, reason: AuditReason
) -> None:
    classification = classify_failure(PublicError(code))
    assert classification.event_name is event_name
    assert classification.reason_code is reason


def test_admission_override_is_not_a_database_fault() -> None:
    classification = classify_failure(
        PublicError(ApiErrorCode.DEPENDENCY_UNAVAILABLE, audit_reason="ADMISSION_REJECTED")
    )
    assert classification.event_name is AuditEventName.REQUEST_REJECTED
    assert classification.reason_code is AuditReason.ADMISSION_REJECTED


@pytest.mark.parametrize(
    ("failure", "event_name", "reason"),
    [
        (
            AuthenticationFailure.INFRASTRUCTURE,
            AuditEventName.AUTHORIZATION_ERROR,
            AuditReason.DATABASE_UNAVAILABLE,
        ),
        (
            AuthenticationFailure.ATTESTATION_UNAVAILABLE,
            AuditEventName.AUTHORIZATION_ERROR,
            AuditReason.ISSUER_UNAVAILABLE,
        ),
        (
            AuthenticationFailure.INELIGIBLE_SUBSCRIPTION,
            AuditEventName.SUBSCRIPTION_REJECTED,
            AuditReason.SUBSCRIPTION_INELIGIBLE,
        ),
        (
            AuthenticationFailure.UNKNOWN_SUBJECT,
            AuditEventName.CONTEXT_REJECTED,
            AuditReason.ACTOR_CONTEXT_INVALID,
        ),
        (
            AuthenticationFailure.INVALID_REQUEST,
            AuditEventName.REQUEST_REJECTED,
            AuditReason.INVALID_REQUEST,
        ),
    ],
)
def test_authentication_failures_map_to_closed_reasons(
    failure: AuthenticationFailure, event_name: AuditEventName, reason: AuditReason
) -> None:
    classification = classify_failure(AuthenticationError(failure, "typed"))
    assert classification.event_name is event_name
    assert classification.reason_code is reason


def test_authentication_slot_distinguishes_service_and_user() -> None:
    service = classify_failure(
        AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "x", slot="service")
    )
    user = classify_failure(
        AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "x", slot="user")
    )
    assert service.reason_code is AuditReason.SERVICE_AUTHENTICATION_FAILED
    assert user.reason_code is AuditReason.USER_AUTHENTICATION_FAILED


def test_persistence_and_unknown_errors_are_internal_errors() -> None:
    persistence = classify_failure(PersistenceError("db"))
    assert persistence.event_name is AuditEventName.AUTHORIZATION_ERROR
    assert persistence.reason_code is AuditReason.DATABASE_UNAVAILABLE
    unknown = classify_failure(RuntimeError("token=super-secret"))
    assert unknown.event_name is AuditEventName.AUTHORIZATION_ERROR
    assert unknown.reason_code is AuditReason.INTERNAL_ERROR
