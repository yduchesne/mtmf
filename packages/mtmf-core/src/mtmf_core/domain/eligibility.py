"""Pure Application/Tenant eligibility evaluation (PR 13, decisions S6/S7).

This module is deliberately pure and deterministic: it evaluates the four
independent prerequisites of a positive eligibility outcome against
already-loaded domain values and one injected evaluation instant. It does
not retrieve persistence state, authenticate a caller, evaluate a
Permission or Action, or return an authorization ``ALLOW``.

The prerequisites are all required and none substitutes for another
(decision S6):

1. an ``ACTIVE`` :class:`~mtmf_core.domain.application.Application`;
2. an ``ACTIVE`` tenant (not soft-deleted, ``TenantLifecycle.ACTIVE``);
3. an ``ACTIVE``
   :class:`~mtmf_core.domain.application.ApplicationTenantRegistration`
   for exactly that Application/Tenant pair;
4. an ``ACTIVE`` in-window
   :class:`~mtmf_core.domain.application.TenantApplicationSubscription`
   for exactly that Application/Tenant pair.

A missing, inactive, terminal, out-of-window, or wrong-pair fact is
ineligible. Expiry is time-derived (decision S7): a subscription is
ineligible immediately at ``ends_at`` without any asynchronous status
transition. The returned reason taxonomy is stable and contains no
tenant- or application-sensitive data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from mtmf_core.domain.application import (
    Application,
    ApplicationTenantRegistration,
    TenantApplicationSubscription,
)
from mtmf_core.domain.errors import ApplicationRegistryInvariantError
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantLifecycle,
)
from mtmf_core.domain.tenant import Tenant

__all__ = [
    "ApplicationTenantEligibility",
    "EligibilityReason",
    "evaluate_application_tenant_eligibility",
]


class EligibilityReason(StrEnum):
    """Stable internal eligibility reason taxonomy.

    Every reason other than :attr:`ELIGIBLE` is a fail-closed
    ineligibility outcome. None of these values is a policy decision and
    none of them implies an ``ALLOW``.
    """

    ELIGIBLE = "eligible"
    APPLICATION_MISSING = "application_missing"
    APPLICATION_NOT_ACTIVE = "application_not_active"
    TENANT_MISSING = "tenant_missing"
    TENANT_NOT_ACTIVE = "tenant_not_active"
    REGISTRATION_MISSING = "registration_missing"
    REGISTRATION_NOT_ACTIVE = "registration_not_active"
    REGISTRATION_PAIR_MISMATCH = "registration_pair_mismatch"
    SUBSCRIPTION_MISSING = "subscription_missing"
    SUBSCRIPTION_NOT_ACTIVE = "subscription_not_active"
    SUBSCRIPTION_PAIR_MISMATCH = "subscription_pair_mismatch"
    SUBSCRIPTION_NOT_YET_STARTED = "subscription_not_yet_started"
    SUBSCRIPTION_EXPIRED = "subscription_expired"


@dataclass(frozen=True, slots=True)
class ApplicationTenantEligibility:
    """The typed, fail-closed result of one eligibility evaluation.

    ``eligible`` is ``True`` if and only if ``reason`` is
    :attr:`EligibilityReason.ELIGIBLE`. The result is a prerequisite
    evaluation, never an authorization decision.
    """

    eligible: bool
    reason: EligibilityReason
    evaluated_at: datetime


def _ineligible(reason: EligibilityReason, at: datetime) -> ApplicationTenantEligibility:
    return ApplicationTenantEligibility(eligible=False, reason=reason, evaluated_at=at)


def _require_aware(at: datetime) -> None:
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ApplicationRegistryInvariantError(
            "eligibility evaluation requires a timezone-aware evaluation instant"
        )


def evaluate_application_tenant_eligibility(
    *,
    application: Application | None,
    tenant: Tenant | None,
    registration: ApplicationTenantRegistration | None,
    subscription: TenantApplicationSubscription | None,
    at: datetime,
) -> ApplicationTenantEligibility:
    """Evaluate all four Application/Tenant eligibility prerequisites.

    The evaluation is fail-closed: any missing, inactive, terminal,
    wrong-pair, or out-of-window fact yields an ineligible result. No
    fact substitutes for another and a wrong pair is never evaluated as
    eligible.

    :param application: the loaded Application, or ``None`` when absent.
    :param tenant: the loaded Tenant, or ``None`` when absent.
    :param registration: the current registration for the pair, or
        ``None`` when absent.
    :param subscription: the current subscription for the pair, or
        ``None`` when absent.
    :param at: the single authoritative, timezone-aware evaluation
        instant, captured once per evaluation.
    :raises ApplicationRegistryInvariantError: when ``at`` is naive.
    """
    _require_aware(at)

    if application is None:
        return _ineligible(EligibilityReason.APPLICATION_MISSING, at)
    if application.lifecycle is not ApplicationLifecycle.ACTIVE:
        return _ineligible(EligibilityReason.APPLICATION_NOT_ACTIVE, at)

    if tenant is None:
        return _ineligible(EligibilityReason.TENANT_MISSING, at)
    if tenant.deleted or tenant.lifecycle is not TenantLifecycle.ACTIVE:
        return _ineligible(EligibilityReason.TENANT_NOT_ACTIVE, at)

    if registration is None:
        return _ineligible(EligibilityReason.REGISTRATION_MISSING, at)
    if not registration.describes_pair(application.id, tenant.id):
        return _ineligible(EligibilityReason.REGISTRATION_PAIR_MISMATCH, at)
    if registration.lifecycle is not RegistrationLifecycle.ACTIVE:
        return _ineligible(EligibilityReason.REGISTRATION_NOT_ACTIVE, at)

    if subscription is None:
        return _ineligible(EligibilityReason.SUBSCRIPTION_MISSING, at)
    if not subscription.describes_pair(application.id, tenant.id):
        return _ineligible(EligibilityReason.SUBSCRIPTION_PAIR_MISMATCH, at)
    if subscription.lifecycle is not SubscriptionLifecycle.ACTIVE:
        return _ineligible(EligibilityReason.SUBSCRIPTION_NOT_ACTIVE, at)

    if at < subscription.starts_at:
        return _ineligible(EligibilityReason.SUBSCRIPTION_NOT_YET_STARTED, at)
    if subscription.ends_at is not None and at >= subscription.ends_at:
        return _ineligible(EligibilityReason.SUBSCRIPTION_EXPIRED, at)

    return ApplicationTenantEligibility(
        eligible=True, reason=EligibilityReason.ELIGIBLE, evaluated_at=at
    )
