"""Unit tests for the PR 13 Application-registry domain model.

These exercise the pure Application/registration/subscription invariants and
the fail-closed ``evaluate_application_tenant_eligibility`` truth table
(matrix E01-E16) with a deterministic injected clock. No persistence,
transport, authentication, or authorization is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from helpers import make_id, make_tenant

from mtmf_core import (
    Application,
    ApplicationLifecycle,
    ApplicationRegistryInvariantError,
    ApplicationTenantEligibility,
    ApplicationTenantRegistration,
    DomainInvariantError,
    EligibilityReason,
    ImmutabilityError,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantApplicationSubscription,
    TenantLifecycle,
    evaluate_application_tenant_eligibility,
    normalize_application_key,
    validate_application_transition,
    validate_registration_transition,
    validate_subscription_transition,
    validate_subscription_window,
)

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _application(lifecycle: ApplicationLifecycle = ApplicationLifecycle.ACTIVE) -> Application:
    return Application(make_id(), "ati-client", "ATI Client", make_id(), lifecycle)


def _registration(
    application: Application,
    tenant_id,
    lifecycle: RegistrationLifecycle = RegistrationLifecycle.ACTIVE,
) -> ApplicationTenantRegistration:
    return ApplicationTenantRegistration(
        make_id(), application.id, tenant_id, make_id(), _NOW, lifecycle
    )


def _subscription(
    application: Application,
    tenant_id,
    lifecycle: SubscriptionLifecycle = SubscriptionLifecycle.ACTIVE,
    *,
    starts_at: datetime = _NOW - timedelta(days=1),
    ends_at: datetime | None = _NOW + timedelta(days=1),
) -> TenantApplicationSubscription:
    return TenantApplicationSubscription(
        make_id(),
        application.id,
        tenant_id,
        make_id(),
        starts_at,
        _NOW,
        ends_at,
        lifecycle,
    )


# --- Application key and identity -------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ati", "ati"),
        ("ATI-Client", "ati-client"),
        ("  ati.client_v2  ", "ati.client_v2"),
    ],
)
def test_application_key_is_normalized(raw: str, expected: str) -> None:
    assert normalize_application_key(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "  ", "-ati", "ati-", "ati client", "ati/client", "a" * 129],
)
def test_invalid_application_key_is_rejected(raw: str) -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        normalize_application_key(raw)


def test_application_normalizes_key_and_is_immutably_identified() -> None:
    application = _application()
    assert application.application_key == "ati-client"
    with pytest.raises(ImmutabilityError):
        application.application_key = "other"
    with pytest.raises(ImmutabilityError):
        application.id = make_id()


def test_application_rejects_blank_name() -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        Application(make_id(), "ati", "  ", make_id())


# --- Lifecycle transitions --------------------------------------------------


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (ApplicationLifecycle.ACTIVE, ApplicationLifecycle.SUSPENDED),
        (ApplicationLifecycle.SUSPENDED, ApplicationLifecycle.ACTIVE),
        (ApplicationLifecycle.ACTIVE, ApplicationLifecycle.RETIRED),
        (ApplicationLifecycle.SUSPENDED, ApplicationLifecycle.RETIRED),
    ],
)
def test_legal_application_transitions(
    source: ApplicationLifecycle, target: ApplicationLifecycle
) -> None:
    validate_application_transition(source, target)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (ApplicationLifecycle.ACTIVE, ApplicationLifecycle.ACTIVE),
        (ApplicationLifecycle.RETIRED, ApplicationLifecycle.ACTIVE),
        (ApplicationLifecycle.RETIRED, ApplicationLifecycle.SUSPENDED),
    ],
)
def test_illegal_application_transitions(
    source: ApplicationLifecycle, target: ApplicationLifecycle
) -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        validate_application_transition(source, target)


def test_application_transition_to_retired_is_terminal() -> None:
    application = _application()
    application.transition_to(ApplicationLifecycle.RETIRED)
    with pytest.raises(ApplicationRegistryInvariantError):
        application.transition_to(ApplicationLifecycle.ACTIVE)


def test_registration_revoke_is_terminal() -> None:
    registration = _registration(_application(), make_id())
    registration.transition_to(RegistrationLifecycle.REVOKED)
    with pytest.raises(ApplicationRegistryInvariantError):
        registration.transition_to(RegistrationLifecycle.ACTIVE)
    validate_registration_transition(RegistrationLifecycle.ACTIVE, RegistrationLifecycle.REVOKED)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (SubscriptionLifecycle.PENDING, SubscriptionLifecycle.ACTIVE),
        (SubscriptionLifecycle.PENDING, SubscriptionLifecycle.CANCELLED),
        (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.SUSPENDED),
        (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.CANCELLED),
        (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.EXPIRED),
        (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.ACTIVE),
        (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.CANCELLED),
        (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.EXPIRED),
    ],
)
def test_legal_subscription_transitions(
    source: SubscriptionLifecycle, target: SubscriptionLifecycle
) -> None:
    validate_subscription_transition(source, target)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (SubscriptionLifecycle.CANCELLED, SubscriptionLifecycle.ACTIVE),
        (SubscriptionLifecycle.EXPIRED, SubscriptionLifecycle.ACTIVE),
        (SubscriptionLifecycle.PENDING, SubscriptionLifecycle.SUSPENDED),
        (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.ACTIVE),
    ],
)
def test_illegal_subscription_transitions(
    source: SubscriptionLifecycle, target: SubscriptionLifecycle
) -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        validate_subscription_transition(source, target)


def test_subscription_transition_can_extend_the_window() -> None:
    subscription = _subscription(_application(), make_id())
    new_end = _NOW + timedelta(days=30)
    subscription.transition_to(SubscriptionLifecycle.SUSPENDED, ends_at=new_end)
    assert subscription.ends_at == new_end
    subscription.transition_to(SubscriptionLifecycle.ACTIVE)
    assert subscription.ends_at == new_end


def test_subscription_window_requires_aware_instants() -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        validate_subscription_window(datetime(2026, 1, 1), None)
    with pytest.raises(ApplicationRegistryInvariantError):
        validate_subscription_window(_NOW, _NOW)
    with pytest.raises(ApplicationRegistryInvariantError):
        validate_subscription_window(_NOW, _NOW - timedelta(seconds=1))


def test_subscription_rejects_inverted_window_at_construction() -> None:
    with pytest.raises(ApplicationRegistryInvariantError):
        TenantApplicationSubscription(make_id(), make_id(), make_id(), make_id(), _NOW, _NOW, _NOW)


def test_registration_and_subscription_pair_helpers() -> None:
    application = _application()
    tenant_id = make_id()
    registration = _registration(application, tenant_id)
    subscription = _subscription(application, tenant_id)
    assert registration.describes_pair(application.id, tenant_id)
    assert not registration.describes_pair(make_id(), tenant_id)
    assert subscription.describes_pair(application.id, tenant_id)
    assert not subscription.describes_pair(make_id(), tenant_id)


# --- Pure eligibility truth table (E01-E16) ---------------------------------


def _evaluate(
    *,
    application: Application | None,
    tenant,
    registration: ApplicationTenantRegistration | None,
    subscription: TenantApplicationSubscription | None,
    at: datetime = _NOW,
) -> ApplicationTenantEligibility:
    return evaluate_application_tenant_eligibility(
        application=application,
        tenant=tenant,
        registration=registration,
        subscription=subscription,
        at=at,
    )


def _eligible_graph() -> tuple[Application, object, ApplicationTenantRegistration, object]:
    application = _application()
    tenant = make_tenant(lifecycle=TenantLifecycle.ACTIVE)
    return (
        application,
        tenant,
        _registration(application, tenant.id),
        _subscription(application, tenant.id),
    )


def test_e01_all_prerequisites_eligible() -> None:
    application, tenant, registration, subscription = _eligible_graph()
    result = _evaluate(
        application=application, tenant=tenant, registration=registration, subscription=subscription
    )
    assert result.eligible is True
    assert result.reason is EligibilityReason.ELIGIBLE
    assert result.evaluated_at == _NOW


def test_e02_e03_application_missing_or_inactive() -> None:
    _application_value, tenant, registration, subscription = _eligible_graph()
    missing = _evaluate(
        application=None, tenant=tenant, registration=registration, subscription=subscription
    )
    assert missing.reason is EligibilityReason.APPLICATION_MISSING
    suspended = _application(ApplicationLifecycle.SUSPENDED)
    assert (
        _evaluate(
            application=suspended,
            tenant=tenant,
            registration=_registration(suspended, tenant.id),
            subscription=_subscription(suspended, tenant.id),
        ).reason
        is EligibilityReason.APPLICATION_NOT_ACTIVE
    )
    retired = _application(ApplicationLifecycle.RETIRED)
    assert (
        _evaluate(
            application=retired,
            tenant=tenant,
            registration=_registration(retired, tenant.id),
            subscription=_subscription(retired, tenant.id),
        ).reason
        is EligibilityReason.APPLICATION_NOT_ACTIVE
    )


def test_e04_e15_registration_missing_or_revoked() -> None:
    application, tenant, _registration_value, subscription = _eligible_graph()
    missing = _evaluate(
        application=application, tenant=tenant, registration=None, subscription=subscription
    )
    assert missing.reason is EligibilityReason.REGISTRATION_MISSING
    revoked = ApplicationTenantRegistration(
        make_id(),
        application.id,
        tenant.id,
        make_id(),
        _NOW,
        RegistrationLifecycle.REVOKED,
    )
    result = _evaluate(
        application=application, tenant=tenant, registration=revoked, subscription=subscription
    )
    assert result.reason is EligibilityReason.REGISTRATION_NOT_ACTIVE


def test_e05_e06_subscription_missing_or_inactive() -> None:
    application, tenant, registration, _subscription_value = _eligible_graph()
    missing = _evaluate(
        application=application, tenant=tenant, registration=registration, subscription=None
    )
    assert missing.reason is EligibilityReason.SUBSCRIPTION_MISSING
    for status in (
        SubscriptionLifecycle.PENDING,
        SubscriptionLifecycle.SUSPENDED,
        SubscriptionLifecycle.CANCELLED,
        SubscriptionLifecycle.EXPIRED,
    ):
        result = _evaluate(
            application=application,
            tenant=tenant,
            registration=registration,
            subscription=_subscription(application, tenant.id, status),
        )
        assert result.reason is EligibilityReason.SUBSCRIPTION_NOT_ACTIVE


def test_e07_e08_e09_e10_subscription_window_boundaries() -> None:
    application, tenant, registration, _ = _eligible_graph()
    starts = _NOW
    ends = _NOW + timedelta(hours=1)
    before = _evaluate(
        application=application,
        tenant=tenant,
        registration=registration,
        subscription=_subscription(application, tenant.id, starts_at=starts, ends_at=ends),
        at=starts - timedelta(seconds=1),
    )
    assert before.reason is EligibilityReason.SUBSCRIPTION_NOT_YET_STARTED
    at_start = _evaluate(
        application=application,
        tenant=tenant,
        registration=registration,
        subscription=_subscription(application, tenant.id, starts_at=starts, ends_at=ends),
        at=starts,
    )
    assert at_start.eligible is True
    at_end = _evaluate(
        application=application,
        tenant=tenant,
        registration=registration,
        subscription=_subscription(application, tenant.id, starts_at=starts, ends_at=ends),
        at=ends,
    )
    assert at_end.reason is EligibilityReason.SUBSCRIPTION_EXPIRED
    after = _evaluate(
        application=application,
        tenant=tenant,
        registration=registration,
        subscription=_subscription(application, tenant.id, starts_at=starts, ends_at=ends),
        at=ends + timedelta(seconds=1),
    )
    assert after.reason is EligibilityReason.SUBSCRIPTION_EXPIRED


def test_e11_inactive_tenant_is_ineligible() -> None:
    application, _tenant, registration, subscription = _eligible_graph()
    for tenant in (
        make_tenant(lifecycle=TenantLifecycle.PROVISIONING),
        make_tenant(lifecycle=TenantLifecycle.SUSPENDED),
    ):
        result = _evaluate(
            application=application,
            tenant=tenant,
            registration=_registration(application, tenant.id),
            subscription=_subscription(application, tenant.id),
        )
        assert result.reason is EligibilityReason.TENANT_NOT_ACTIVE
    deleted = make_tenant(lifecycle=TenantLifecycle.ACTIVE)
    deleted.soft_delete()
    result = _evaluate(
        application=application,
        tenant=deleted,
        registration=registration,
        subscription=subscription,
    )
    assert result.reason is EligibilityReason.TENANT_NOT_ACTIVE


def test_e12_wrong_tenant_is_ineligible() -> None:
    application, _tenant_value, registration, subscription = _eligible_graph()
    other_tenant = make_tenant(lifecycle=TenantLifecycle.ACTIVE)
    result = _evaluate(
        application=application,
        tenant=other_tenant,
        registration=registration,
        subscription=subscription,
    )
    assert result.reason is EligibilityReason.REGISTRATION_PAIR_MISMATCH


def test_e13_wrong_application_pair_is_ineligible() -> None:
    application, tenant, _registration_value, _ = _eligible_graph()
    other_application = _application()
    wrong_registration = _registration(other_application, tenant.id)
    result = _evaluate(
        application=application,
        tenant=tenant,
        registration=wrong_registration,
        subscription=_subscription(application, tenant.id),
    )
    assert result.reason is EligibilityReason.REGISTRATION_PAIR_MISMATCH
    right_registration = _registration(application, tenant.id)
    wrong_subscription = _subscription(other_application, tenant.id)
    result = _evaluate(
        application=application,
        tenant=tenant,
        registration=right_registration,
        subscription=wrong_subscription,
    )
    assert result.reason is EligibilityReason.SUBSCRIPTION_PAIR_MISMATCH


def test_eligibility_requires_timezone_aware_instant() -> None:
    application, tenant, registration, subscription = _eligible_graph()
    with pytest.raises(ApplicationRegistryInvariantError):
        _evaluate(
            application=application,
            tenant=tenant,
            registration=registration,
            subscription=subscription,
            at=datetime(2026, 1, 1),
        )


def test_eligibility_is_not_authorization() -> None:
    application, tenant, registration, subscription = _eligible_graph()
    result = _evaluate(
        application=application, tenant=tenant, registration=registration, subscription=subscription
    )
    # A positive prerequisite result is deliberately not an AuthorizationDecision.
    assert not hasattr(result, "effect")
    assert not hasattr(result, "allowed")


def test_application_lifecycle_rejects_illegal_enum_value() -> None:
    with pytest.raises(DomainInvariantError):
        Application(make_id(), "ati", "ATI", make_id(), lifecycle=99)  # type: ignore[arg-type]
