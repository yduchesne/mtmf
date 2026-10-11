"""Application-layer eligibility service tests (PR 13, D1).

These prove that the service loads the Application/Tenant/registration/
subscription in one UnitOfWork, returns the pure typed result, propagates
infrastructure failures distinctly from ineligibility, never caches, and
makes a committed revocation/cancellation effective on the next evaluation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from helpers import make_id, make_tenant

from mtmf_core import (
    Application,
    ApplicationTenantEligibilityIntegrityError,
    ApplicationTenantEligibilityService,
    ApplicationTenantRegistration,
    EligibilityReason,
    MtmfSpi,
    PersistenceError,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantApplicationSubscription,
    TenantLifecycle,
)
from mtmf_core.persistence import UnitOfWork
from mtmf_core.persistence.testing import InMemoryMtmfSpi

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def spi() -> MtmfSpi:
    """A fresh deterministic in-memory provider per test."""
    return InMemoryMtmfSpi()


def _seed(
    spi: MtmfSpi,
    *,
    subscription_lifecycle: SubscriptionLifecycle = SubscriptionLifecycle.ACTIVE,
    tenant_lifecycle: TenantLifecycle = TenantLifecycle.ACTIVE,
) -> tuple[Application, object]:
    application = Application(make_id(), "ati-client", "ATI Client", make_id())
    tenant = make_tenant(lifecycle=tenant_lifecycle)
    registration = ApplicationTenantRegistration(
        make_id(), application.id, tenant.id, make_id(), _NOW
    )
    subscription = TenantApplicationSubscription(
        make_id(),
        application.id,
        tenant.id,
        make_id(),
        _NOW - timedelta(days=1),
        _NOW,
        _NOW + timedelta(days=30),
        subscription_lifecycle,
    )
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        spi.create_tenant_repository(uow).add(tenant)
        spi.create_application_tenant_registration_repository(uow).add(registration)
        spi.create_tenant_application_subscription_repository(uow).add(subscription)
        uow.commit()
    return application, tenant


def _evaluate(
    spi: MtmfSpi,
    application_id,
    tenant_id,
    at: datetime = _NOW,
):
    service = ApplicationTenantEligibilityService(spi)
    with spi.create_unit_of_work() as uow:
        return service.evaluate(uow, application_id=application_id, tenant_id=tenant_id, at=at)


def test_eligible_vertical_slice(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi)
    result = _evaluate(spi, application.id, tenant.id)
    assert result.eligible is True
    assert result.reason is EligibilityReason.ELIGIBLE


def test_missing_application_and_tenant_are_ineligible(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi)
    assert _evaluate(spi, make_id(), tenant.id).reason is EligibilityReason.APPLICATION_MISSING
    assert _evaluate(spi, application.id, make_id()).reason is EligibilityReason.TENANT_MISSING


def test_inactive_tenant_is_ineligible(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi, tenant_lifecycle=TenantLifecycle.SUSPENDED)
    assert _evaluate(spi, application.id, tenant.id).reason is EligibilityReason.TENANT_NOT_ACTIVE


def test_committed_revocation_is_effective_on_next_evaluation(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi)
    assert _evaluate(spi, application.id, tenant.id).eligible is True
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_tenant_registration_repository(uow)
        registration = repository.find_by_application_and_tenant(application.id, tenant.id)[0]
        registration.transition_to(RegistrationLifecycle.REVOKED)
        repository.save(registration)
        uow.commit()
    assert _evaluate(spi, application.id, tenant.id).reason is (
        EligibilityReason.REGISTRATION_NOT_ACTIVE
    )


def test_committed_cancellation_is_effective_on_next_evaluation(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        subscription = repository.find_by_application_and_tenant(application.id, tenant.id)[0]
        subscription.transition_to(SubscriptionLifecycle.CANCELLED)
        repository.save(subscription)
        uow.commit()
    assert _evaluate(spi, application.id, tenant.id).reason is (
        EligibilityReason.SUBSCRIPTION_NOT_ACTIVE
    )


def test_time_based_expiry_without_status_transition(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi)
    assert (
        _evaluate(spi, application.id, tenant.id, at=_NOW + timedelta(days=31)).reason
        is EligibilityReason.SUBSCRIPTION_EXPIRED
    )


def test_pending_subscription_is_ineligible(spi: MtmfSpi) -> None:
    application, tenant = _seed(spi, subscription_lifecycle=SubscriptionLifecycle.PENDING)
    assert _evaluate(spi, application.id, tenant.id).reason is (
        EligibilityReason.SUBSCRIPTION_NOT_ACTIVE
    )


def test_duplicate_current_rows_are_integrity_failure() -> None:
    application = Application(make_id(), "ati-client", "ATI Client", make_id())
    tenant_id = make_id()
    first = ApplicationTenantRegistration(make_id(), application.id, tenant_id, make_id(), _NOW)
    second = ApplicationTenantRegistration(make_id(), application.id, tenant_id, make_id(), _NOW)
    with pytest.raises(ApplicationTenantEligibilityIntegrityError):
        ApplicationTenantEligibilityService._select_current_registration((first, second))


def test_terminal_row_selection_falls_back_to_latest() -> None:
    application = Application(make_id(), "ati-client", "ATI Client", make_id())
    tenant_id = make_id()
    revoked = ApplicationTenantRegistration(
        make_id(), application.id, tenant_id, make_id(), _NOW, RegistrationLifecycle.REVOKED
    )
    selected = ApplicationTenantEligibilityService._select_current_registration((revoked,))
    assert selected is revoked
    assert ApplicationTenantEligibilityService._select_current_registration(()) is None


def test_duplicate_current_subscriptions_are_integrity_failure() -> None:
    application = Application(make_id(), "ati-client", "ATI Client", make_id())
    tenant_id = make_id()
    first = TenantApplicationSubscription(
        make_id(), application.id, tenant_id, make_id(), _NOW, _NOW, None
    )
    second = TenantApplicationSubscription(
        make_id(), application.id, tenant_id, make_id(), _NOW, _NOW, None
    )
    with pytest.raises(ApplicationTenantEligibilityIntegrityError):
        ApplicationTenantEligibilityService._select_current_subscription((first, second))
    assert ApplicationTenantEligibilityService._select_current_subscription(()) is None


class _FailingSpi:
    def __init__(self) -> None:
        self._uow = object()

    def create_unit_of_work(self) -> UnitOfWork:  # pragma: no cover - not used
        raise NotImplementedError

    def create_application_repository(self, uow: UnitOfWork):
        raise PersistenceError("application store unavailable")

    def create_tenant_repository(self, uow: UnitOfWork):  # pragma: no cover - reached second
        raise PersistenceError("tenant store unavailable")

    def create_application_tenant_registration_repository(self, uow: UnitOfWork):
        raise NotImplementedError  # pragma: no cover - never reached

    def create_tenant_application_subscription_repository(self, uow: UnitOfWork):
        raise NotImplementedError  # pragma: no cover - never reached


def test_infrastructure_failure_propagates_distinctly() -> None:
    service = ApplicationTenantEligibilityService(_FailingSpi())  # type: ignore[arg-type]
    with pytest.raises(PersistenceError):
        service.evaluate(
            object(),  # type: ignore[arg-type]
            application_id=make_id(),
            tenant_id=make_id(),
            at=_NOW,
        )
