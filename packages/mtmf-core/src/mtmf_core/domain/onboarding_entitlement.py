"""Application onboarding entitlement domain contract (PR 22).

The PR 21-approved pre-Tenant onboarding entitlement is a separately
provisioned, MTMF-controlled authority bound to the canonical registered
``Application`` UUID. It is **not** a Role, Permission, subscription, or
credential, and it confers no authority by itself.

This module provides the detached immutable snapshots and pure structural
validators for the persisted entitlement foundation. It does not
authenticate an operator, authorize an Action, assign a Role, reserve quota,
create a Tenant, or perform I/O. The database remains authoritative under
concurrent writers; these validators mirror the persisted constraints.

The first-Tenant composite transaction that would consume an ACTIVE
entitlement is deliberately **not** implemented in PR 22 (see
``docs/pr-artifacts/pr-22/PR22_STOP_REPORT.md``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

from mtmf_core.domain.errors import OnboardingEntitlementInvariantError
from mtmf_core.domain.identity import DomainId

__all__ = [
    "OnboardingEntitlement",
    "OnboardingEntitlementEvent",
    "OnboardingEntitlementEventType",
    "OnboardingEntitlementState",
    "validate_entitlement_grant_reason",
    "validate_entitlement_quota",
]

_MAX_REASON_LENGTH = 512


class OnboardingEntitlementState(IntEnum):
    """Lifecycle of one per-Application onboarding entitlement.

    Only :attr:`ACTIVE` permits first-Tenant provisioning. :attr:`REVOKED`
    is terminal: a replacement grant is a new record with a new UUID.
    """

    ACTIVE = 1
    REVOKED = 2


class OnboardingEntitlementEventType(IntEnum):
    """Append-only entitlement history event type."""

    GRANTED = 1
    REVOKED = 2


def _require_aware(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OnboardingEntitlementInvariantError(f"{name} must be a timezone-aware instant")
    return value


def validate_entitlement_grant_reason(value: object, name: str = "grant_reason") -> str:
    """Return a bounded non-empty reason string, or raise.

    :raises OnboardingEntitlementInvariantError: for a malformed reason.
    """
    if not isinstance(value, str):
        raise OnboardingEntitlementInvariantError(f"{name} must be a string")
    stripped = value.strip()
    if not stripped or len(stripped) > _MAX_REASON_LENGTH:
        raise OnboardingEntitlementInvariantError(
            f"{name} must be a bounded non-empty string (1..{_MAX_REASON_LENGTH})"
        )
    return stripped


def validate_entitlement_quota(quota_total: object, quota_consumed: object) -> None:
    """Validate the explicit positive quota and its nonnegative consumption.

    There is no implicit unlimited mode: ``quota_total`` must be an explicitly
    supplied positive limit, and ``0 <= quota_consumed <= quota_total``.

    :raises OnboardingEntitlementInvariantError: for an invalid quota.
    """
    if isinstance(quota_total, bool) or not isinstance(quota_total, int):
        raise OnboardingEntitlementInvariantError("quota_total must be an integer")
    if quota_total <= 0:
        raise OnboardingEntitlementInvariantError("quota_total must be a positive explicit limit")
    if isinstance(quota_consumed, bool) or not isinstance(quota_consumed, int):
        raise OnboardingEntitlementInvariantError("quota_consumed must be an integer")
    if quota_consumed < 0:
        raise OnboardingEntitlementInvariantError("quota_consumed must not be negative")
    if quota_consumed > quota_total:
        raise OnboardingEntitlementInvariantError("quota_consumed must not exceed quota_total")


@dataclass(frozen=True, slots=True)
class OnboardingEntitlement:
    """Immutable detached snapshot of one Application onboarding entitlement.

    :attr:`id` is the immutable entitlement UUID. A REVOKED entitlement is
    terminal and carries complete revocation provenance; an ACTIVE
    entitlement carries none. ``quota_consumed`` is monotonic.
    """

    id: DomainId
    application_id: DomainId
    state: OnboardingEntitlementState
    granted_at: datetime
    granted_by_operator_principal_id: DomainId
    grant_reason: str
    quota_total: int
    quota_consumed: int = 0
    version: int = 0
    revoked_at: datetime | None = None
    revoked_by_operator_principal_id: DomainId | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, OnboardingEntitlementState):
            raise OnboardingEntitlementInvariantError("state must be an OnboardingEntitlementState")
        _require_aware(self.granted_at, "granted_at")
        validate_entitlement_grant_reason(self.grant_reason)
        validate_entitlement_quota(self.quota_total, self.quota_consumed)
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 0:
            raise OnboardingEntitlementInvariantError("version must be a nonnegative integer")
        if self.state is OnboardingEntitlementState.ACTIVE:
            if (
                self.revoked_at is not None
                or self.revoked_by_operator_principal_id is not None
                or self.revocation_reason is not None
            ):
                raise OnboardingEntitlementInvariantError(
                    "an ACTIVE entitlement must not carry revocation provenance"
                )
        else:
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_by_operator_principal_id is None:
                raise OnboardingEntitlementInvariantError(
                    "a REVOKED entitlement must record the revoking operator Principal"
                )
            validate_entitlement_grant_reason(self.revocation_reason, "revocation_reason")

    @property
    def is_active(self) -> bool:
        """Whether this entitlement currently permits first-Tenant onboarding."""
        return self.state is OnboardingEntitlementState.ACTIVE


@dataclass(frozen=True, slots=True)
class OnboardingEntitlementEvent:
    """One append-only entitlement history event with immutable provenance."""

    id: DomainId
    entitlement_id: DomainId
    event_type: OnboardingEntitlementEventType
    occurred_at: datetime
    operator_principal_id: DomainId
    correlation_id: DomainId
    new_state: OnboardingEntitlementState
    reason: str
    old_state: OnboardingEntitlementState | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, OnboardingEntitlementEventType):
            raise OnboardingEntitlementInvariantError(
                "event_type must be an OnboardingEntitlementEventType"
            )
        if not isinstance(self.new_state, OnboardingEntitlementState):
            raise OnboardingEntitlementInvariantError(
                "new_state must be an OnboardingEntitlementState"
            )
        _require_aware(self.occurred_at, "occurred_at")
        validate_entitlement_grant_reason(self.reason, "reason")
        if self.event_type is OnboardingEntitlementEventType.GRANTED:
            if (
                self.old_state is not None
                or self.new_state is not OnboardingEntitlementState.ACTIVE
            ):
                raise OnboardingEntitlementInvariantError(
                    "a GRANTED event has no previous state and yields ACTIVE"
                )
        else:
            if (
                self.old_state is not OnboardingEntitlementState.ACTIVE
                or self.new_state is not OnboardingEntitlementState.REVOKED
            ):
                raise OnboardingEntitlementInvariantError(
                    "a REVOKED event transitions ACTIVE to REVOKED"
                )
