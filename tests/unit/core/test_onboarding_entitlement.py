"""Unit tests for the PR 22 onboarding-entitlement domain contract.

Pure structural validation only: no persistence, transport, authentication,
or authorization is involved. The database remains authoritative under
concurrent writers; these tests mirror the persisted constraints.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mtmf_core.domain.errors import OnboardingEntitlementInvariantError
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.onboarding_entitlement import (
    OnboardingEntitlement,
    OnboardingEntitlementEvent,
    OnboardingEntitlementEventType,
    OnboardingEntitlementState,
    validate_entitlement_grant_reason,
    validate_entitlement_quota,
)

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _active(**overrides: object) -> OnboardingEntitlement:
    values: dict[str, object] = {
        "id": DomainId.generate(),
        "application_id": DomainId.generate(),
        "state": OnboardingEntitlementState.ACTIVE,
        "granted_at": _NOW,
        "granted_by_operator_principal_id": DomainId.generate(),
        "grant_reason": "approved onboarding",
        "quota_total": 5,
    }
    values.update(overrides)
    return OnboardingEntitlement(**values)  # type: ignore[arg-type]


def test_active_entitlement_is_valid_and_active() -> None:
    entitlement = _active()
    assert entitlement.is_active is True
    assert entitlement.quota_consumed == 0
    assert entitlement.version == 0
    assert entitlement.revoked_at is None


def test_quota_must_be_explicit_positive_and_bounded() -> None:
    validate_entitlement_quota(3, 0)
    validate_entitlement_quota(3, 3)
    for total, consumed in ((0, 0), (-1, 0), (3, -1), (3, 4)):
        with pytest.raises(OnboardingEntitlementInvariantError):
            validate_entitlement_quota(total, consumed)


def test_quota_rejects_non_integer_and_bool() -> None:
    with pytest.raises(OnboardingEntitlementInvariantError):
        validate_entitlement_quota(3.0, 0)
    with pytest.raises(OnboardingEntitlementInvariantError):
        validate_entitlement_quota(True, 0)


def test_grant_reason_is_bounded_nonempty() -> None:
    assert validate_entitlement_grant_reason("  ok  ") == "ok"
    for bad in ("", "   ", "x" * 513):
        with pytest.raises(OnboardingEntitlementInvariantError):
            validate_entitlement_grant_reason(bad)
    with pytest.raises(OnboardingEntitlementInvariantError):
        validate_entitlement_grant_reason(None)


def test_active_entitlement_rejects_revocation_provenance() -> None:
    with pytest.raises(OnboardingEntitlementInvariantError):
        _active(revoked_at=_NOW)
    with pytest.raises(OnboardingEntitlementInvariantError):
        _active(revoked_by_operator_principal_id=DomainId.generate())
    with pytest.raises(OnboardingEntitlementInvariantError):
        _active(revocation_reason="revoked")


def test_revoked_entitlement_requires_complete_provenance() -> None:
    base = {
        "id": DomainId.generate(),
        "application_id": DomainId.generate(),
        "state": OnboardingEntitlementState.REVOKED,
        "granted_at": _NOW,
        "granted_by_operator_principal_id": DomainId.generate(),
        "grant_reason": "approved onboarding",
        "quota_total": 5,
    }
    revoked = OnboardingEntitlement(
        **base,  # type: ignore[arg-type]
        revoked_at=_NOW,
        revoked_by_operator_principal_id=DomainId.generate(),
        revocation_reason="policy changed",
    )
    assert revoked.is_active is False

    # Missing any revocation provenance field is rejected.
    with pytest.raises(OnboardingEntitlementInvariantError):
        OnboardingEntitlement(**base, revocation_reason="x")  # type: ignore[arg-type]
    with pytest.raises(OnboardingEntitlementInvariantError):
        OnboardingEntitlement(  # type: ignore[arg-type]
            **base, revoked_at=_NOW, revocation_reason="x"
        )


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(OnboardingEntitlementInvariantError):
        _active(granted_at=datetime(2026, 1, 1, 12, 0))
    revoked = _active(
        state=OnboardingEntitlementState.REVOKED,
        revoked_at=_NOW,
        revoked_by_operator_principal_id=DomainId.generate(),
        revocation_reason="x",
    )
    assert revoked.revocation_reason == "x"


def test_version_must_be_nonnegative() -> None:
    with pytest.raises(OnboardingEntitlementInvariantError):
        _active(version=-1)


def test_granted_event_shape() -> None:
    event = OnboardingEntitlementEvent(
        id=DomainId.generate(),
        entitlement_id=DomainId.generate(),
        event_type=OnboardingEntitlementEventType.GRANTED,
        occurred_at=_NOW,
        operator_principal_id=DomainId.generate(),
        correlation_id=DomainId.generate(),
        new_state=OnboardingEntitlementState.ACTIVE,
        reason="granted",
    )
    assert event.old_state is None
    with pytest.raises(OnboardingEntitlementInvariantError):
        OnboardingEntitlementEvent(
            id=DomainId.generate(),
            entitlement_id=DomainId.generate(),
            event_type=OnboardingEntitlementEventType.GRANTED,
            occurred_at=_NOW,
            operator_principal_id=DomainId.generate(),
            correlation_id=DomainId.generate(),
            new_state=OnboardingEntitlementState.REVOKED,
            reason="granted",
        )


def test_revoked_event_shape() -> None:
    event = OnboardingEntitlementEvent(
        id=DomainId.generate(),
        entitlement_id=DomainId.generate(),
        event_type=OnboardingEntitlementEventType.REVOKED,
        occurred_at=_NOW,
        operator_principal_id=DomainId.generate(),
        correlation_id=DomainId.generate(),
        old_state=OnboardingEntitlementState.ACTIVE,
        new_state=OnboardingEntitlementState.REVOKED,
        reason="revoked",
    )
    assert event.new_state is OnboardingEntitlementState.REVOKED
    with pytest.raises(OnboardingEntitlementInvariantError):
        OnboardingEntitlementEvent(
            id=DomainId.generate(),
            entitlement_id=DomainId.generate(),
            event_type=OnboardingEntitlementEventType.REVOKED,
            occurred_at=_NOW,
            operator_principal_id=DomainId.generate(),
            correlation_id=DomainId.generate(),
            old_state=None,
            new_state=OnboardingEntitlementState.REVOKED,
            reason="revoked",
        )
