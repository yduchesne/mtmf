"""In-memory persistence contract tests for the PR 13 registry (U15-U20).

These run against the provider-neutral ``spi`` fixture (the deterministic
in-memory provider). They prove read-your-writes, commit durability,
deterministic duplicate handling, current-pair uniqueness, terminal-history
behavior, rollback, and transaction isolation for the three new repositories.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from helpers import make_id

from mtmf_core import (
    Application,
    ApplicationLifecycle,
    ApplicationRegistryInvariantError,
    ApplicationTenantRegistration,
    DuplicatePersistenceIdentityError,
    MtmfSpi,
    RegistrationLifecycle,
    SubscriptionLifecycle,
    TenantApplicationSubscription,
    UnknownPersistenceIdentityError,
)

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _application(key: str = "ati-client", name: str = "ATI Client") -> Application:
    return Application(make_id(), key, name, make_id())


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
) -> TenantApplicationSubscription:
    return TenantApplicationSubscription(
        make_id(),
        application.id,
        tenant_id,
        make_id(),
        _NOW - timedelta(days=1),
        _NOW,
        _NOW + timedelta(days=30),
        lifecycle,
    )


def test_application_add_get_by_id_and_key(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        repository.add(application)
        assert repository.get(application.id) == application
        assert repository.get_by_key("ATI-Client") == application
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        assert repository.get(application.id) == application
        assert repository.get_by_key("ati-client") == application
        assert repository.get_by_key("missing") is None


def test_application_duplicate_identity_and_key_are_rejected(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        repository.add(application)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(application)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(_application(key="ATI-CLIENT"))


def test_application_save_requires_existing_identity(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.save(_application())


def test_application_save_updates_state(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        repository.add(application)
        application.name = "Renamed"
        application.lifecycle = ApplicationLifecycle.SUSPENDED
        repository.save(application)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_application_repository(uow).get(application.id)
        assert stored is not None
        assert stored.name == "Renamed"
        assert stored.lifecycle is ApplicationLifecycle.SUSPENDED


def test_application_rollback_discards_staged_state(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
    with spi.create_unit_of_work() as uow:
        assert spi.create_application_repository(uow).get(application.id) is None


def test_application_isolation_between_unit_of_works(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as first:
        spi.create_application_repository(first).add(application)
        # A second active UnitOfWork never observes uncommitted staged state.
        with spi.create_unit_of_work() as observer:
            assert spi.create_application_repository(observer).get(application.id) is None
        first.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_application_repository(uow).get(application.id) == application


def test_registration_add_get_find_and_current_uniqueness(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    other_tenant = make_id()
    registration = _registration(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_application_tenant_registration_repository(uow)
        repository.add(registration)
        assert repository.get(registration.id) == registration
        assert repository.find_by_application_and_tenant(application.id, tenant_id) == (
            registration,
        )
        assert repository.find_by_tenant(tenant_id) == (registration,)
        assert repository.find_by_tenant(other_tenant) == ()
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(_registration(application, tenant_id))
        uow.commit()


def test_revoked_registration_history_allows_new_current(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    revoked = _registration(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_application_tenant_registration_repository(uow)
        repository.add(revoked)
        revoked.transition_to(RegistrationLifecycle.REVOKED)
        repository.save(revoked)
        replacement = _registration(application, tenant_id)
        repository.add(replacement)
        rows = repository.find_by_application_and_tenant(application.id, tenant_id)
        assert len(rows) == 2
        assert {row.lifecycle for row in rows} == {
            RegistrationLifecycle.ACTIVE,
            RegistrationLifecycle.REVOKED,
        }
        uow.commit()


def test_registration_save_requires_existing_identity(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_tenant_registration_repository(uow)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.save(_registration(_application(), make_id()))


def test_subscription_add_get_find_and_current_uniqueness(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    subscription = _subscription(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_tenant_application_subscription_repository(uow)
        repository.add(subscription)
        assert repository.get(subscription.id) == subscription
        assert repository.find_by_application_and_tenant(application.id, tenant_id) == (
            subscription,
        )
        assert repository.find_by_tenant(tenant_id) == (subscription,)
        assert repository.find_by_tenant(make_id()) == ()
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(_subscription(application, tenant_id))
        uow.commit()


def test_terminal_subscription_history_allows_new_current(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    cancelled = _subscription(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_tenant_application_subscription_repository(uow)
        repository.add(cancelled)
        cancelled.transition_to(SubscriptionLifecycle.CANCELLED)
        repository.save(cancelled)
        replacement = _subscription(application, tenant_id)
        repository.add(replacement)
        rows = repository.find_by_application_and_tenant(application.id, tenant_id)
        assert len(rows) == 2
        uow.commit()


def test_subscription_save_requires_existing_identity(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.save(_subscription(_application(), make_id()))


def test_multi_repository_atomic_commit(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    registration = _registration(application, tenant_id)
    subscription = _subscription(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        spi.create_application_tenant_registration_repository(uow).add(registration)
        spi.create_tenant_application_subscription_repository(uow).add(subscription)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_application_repository(uow).get(application.id) == application
        assert (
            spi.create_application_tenant_registration_repository(uow).get(registration.id)
            == registration
        )
        assert (
            spi.create_tenant_application_subscription_repository(uow).get(subscription.id)
            == subscription
        )


def test_multi_repository_failed_transaction_leaves_no_partial_state(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    registration = _registration(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        spi.create_application_tenant_registration_repository(uow).add(registration)
        # No commit: the context exit rolls back the whole operation.
    with spi.create_unit_of_work() as uow:
        assert spi.create_application_repository(uow).get(application.id) is None
        assert (
            spi.create_application_tenant_registration_repository(uow).get(registration.id) is None
        )


# --- PR 13-1 A1 in-memory parity (Phase 3) ---------------------------------


def _committed_subscription(
    spi: MtmfSpi,
) -> tuple[Application, object, TenantApplicationSubscription]:
    application = _application()
    tenant_id = make_id()
    subscription = _subscription(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        spi.create_tenant_application_subscription_repository(uow).add(subscription)
        uow.commit()
    return application, tenant_id, subscription


def test_a1_repository_accepts_and_persists_restrictive_shortening(spi: MtmfSpi) -> None:
    application, tenant_id, subscription = _committed_subscription(spi)
    assert subscription.ends_at is not None
    shortened = subscription.ends_at - timedelta(hours=1)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        current = repository.find_by_application_and_tenant(application.id, tenant_id)[0]
        current.shorten_end_to(shortened)
        repository.save(current)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_application_subscription_repository(
            uow
        ).find_by_application_and_tenant(application.id, tenant_id)[0]
        assert stored.ends_at == shortened


def test_a1_repository_rejects_extension_and_preserves_original(spi: MtmfSpi) -> None:
    application, tenant_id, subscription = _committed_subscription(spi)
    assert subscription.ends_at is not None
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        current = repository.find_by_application_and_tenant(application.id, tenant_id)[0]
        # Bypass the validated domain method to simulate a mutable-field caller.
        current.ends_at = current.ends_at + timedelta(days=1)
        with pytest.raises(ApplicationRegistryInvariantError):
            repository.save(current)
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_application_subscription_repository(
            uow
        ).find_by_application_and_tenant(application.id, tenant_id)[0]
        assert stored.ends_at == subscription.ends_at


def test_a1_repository_rejects_clearing_finite_end(spi: MtmfSpi) -> None:
    application, tenant_id, subscription = _committed_subscription(spi)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        current = repository.find_by_application_and_tenant(application.id, tenant_id)[0]
        current.ends_at = None
        with pytest.raises(ApplicationRegistryInvariantError):
            repository.save(current)
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_application_subscription_repository(
            uow
        ).find_by_application_and_tenant(application.id, tenant_id)[0]
        assert stored.ends_at == subscription.ends_at


def test_a1_repository_rejects_terminal_subscription_update(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    subscription = _subscription(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_tenant_application_subscription_repository(uow)
        repository.add(subscription)
        subscription.transition_to(SubscriptionLifecycle.CANCELLED)
        repository.save(subscription)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        terminal = repository.find_by_application_and_tenant(application.id, tenant_id)[0]
        with pytest.raises(ApplicationRegistryInvariantError):
            repository.save(terminal)


def test_a1_repository_rejects_terminal_registration_update(spi: MtmfSpi) -> None:
    application = _application()
    tenant_id = make_id()
    registration = _registration(application, tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_application_repository(uow).add(application)
        repository = spi.create_application_tenant_registration_repository(uow)
        repository.add(registration)
        registration.transition_to(RegistrationLifecycle.REVOKED)
        repository.save(registration)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_tenant_registration_repository(uow)
        terminal = repository.get(registration.id)
        assert terminal is not None
        with pytest.raises(ApplicationRegistryInvariantError):
            repository.save(terminal)


def test_a1_repository_rejects_terminal_application_update(spi: MtmfSpi) -> None:
    application = _application()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        repository.add(application)
        application.transition_to(ApplicationLifecycle.RETIRED)
        repository.save(application)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        repository = spi.create_application_repository(uow)
        terminal = repository.get(application.id)
        assert terminal is not None
        with pytest.raises(ApplicationRegistryInvariantError):
            repository.save(terminal)


def test_a1_reads_are_detached_from_provider_state(spi: MtmfSpi) -> None:
    application, tenant_id, subscription = _committed_subscription(spi)
    with spi.create_unit_of_work() as uow:
        repository = spi.create_tenant_application_subscription_repository(uow)
        read = repository.find_by_application_and_tenant(application.id, tenant_id)[0]
        # Mutating a detached read must not touch durable provider state.
        read.ends_at = read.ends_at - timedelta(days=1) if read.ends_at else None
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_application_subscription_repository(
            uow
        ).find_by_application_and_tenant(application.id, tenant_id)[0]
        assert stored.ends_at == subscription.ends_at
