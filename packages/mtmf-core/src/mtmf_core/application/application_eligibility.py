"""Trusted internal Application/Tenant eligibility service (PR 13, D1).

This application-layer service composes the provider-neutral persistence
SPI with the pure eligibility evaluator. It loads the Application, the
Tenant, the current registration, and the current subscription for one
``(application_id, tenant_id)`` pair in a single UnitOfWork and evaluates
all four prerequisites at one captured authoritative instant.

The service returns a typed
:class:`~mtmf_core.domain.eligibility.ApplicationTenantEligibility`; it
never evaluates a Permission or Action, never issues an ALLOW, and never
constructs a synthetic acting Identity. Persistence and infrastructure
failures propagate as :class:`~mtmf_core.persistence.errors.PersistenceError`
and are never converted into an eligibility reason.

No result is cached. A committed suspension, revoke, or cancellation is
therefore effective for the next evaluation with fresh transaction
snapshots (decision S7 and the PR 13 commit-boundary contract). The
service does not promise instantaneous invalidation of a decision or
snapshot already handed to a caller.
"""

from __future__ import annotations

from datetime import datetime

from mtmf_core.domain.application import (
    ApplicationTenantRegistration,
    TenantApplicationSubscription,
)
from mtmf_core.domain.eligibility import (
    ApplicationTenantEligibility,
    evaluate_application_tenant_eligibility,
)
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.lifecycle import (
    RegistrationLifecycle,
    SubscriptionLifecycle,
)
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = [
    "ApplicationTenantEligibilityIntegrityError",
    "ApplicationTenantEligibilityService",
]


class ApplicationTenantEligibilityIntegrityError(PersistenceError):
    """Persisted registry state is corrupt or context-inconsistent.

    Raised when more than one *current* registration or subscription row
    exists for an exact ``(application_id, tenant_id)`` pair, which the
    database partial-unique indexes should make impossible. Such state is
    rejected fail-closed rather than silently reinterpreted; it is never an
    eligibility reason and never an ALLOW.
    """


class ApplicationTenantEligibilityService:
    """Read-only internal eligibility evaluation over one UnitOfWork."""

    __slots__ = ("_spi",)

    def __init__(self, spi: MtmfSpi) -> None:
        """Bind the service to one persistence provider."""
        self._spi = spi

    def evaluate(
        self,
        uow: UnitOfWork,
        *,
        application_id: DomainId,
        tenant_id: DomainId,
        at: datetime,
    ) -> ApplicationTenantEligibility:
        """Evaluate the four prerequisites for one exact Application/Tenant pair.

        :param uow: the UnitOfWork that owns every read in this evaluation.
        :param application_id: the Application whose eligibility is asked.
        :param tenant_id: the Tenant whose eligibility is asked.
        :param at: the single authoritative, timezone-aware evaluation
            instant.
        :raises ApplicationTenantEligibilityIntegrityError: on duplicate
            current registry rows.
        :raises PersistenceError: on any infrastructure failure (which never
            becomes an eligibility reason).
        """
        application = self._spi.create_application_repository(uow).get(application_id)
        tenant = self._spi.create_tenant_repository(uow).get(tenant_id)
        registration = self._select_current_registration(
            self._spi.create_application_tenant_registration_repository(
                uow
            ).find_by_application_and_tenant(application_id, tenant_id)
        )
        subscription = self._select_current_subscription(
            self._spi.create_tenant_application_subscription_repository(
                uow
            ).find_by_application_and_tenant(application_id, tenant_id)
        )
        return evaluate_application_tenant_eligibility(
            application=application,
            tenant=tenant,
            registration=registration,
            subscription=subscription,
            at=at,
        )

    @staticmethod
    def _select_current_registration(
        rows: tuple[ApplicationTenantRegistration, ...],
    ) -> ApplicationTenantRegistration | None:
        """Select the single current registration, or the latest terminal row.

        At most one ``ACTIVE`` registration may exist for a pair. When no
        active registration exists the most recent terminal row is returned
        so the evaluator reports a not-active (rather than missing) fact.
        """
        active = [row for row in rows if row.lifecycle is RegistrationLifecycle.ACTIVE]
        if len(active) > 1:
            raise ApplicationTenantEligibilityIntegrityError(
                "more than one current Application-Tenant registration exists for a pair"
            )
        if active:
            return active[0]
        return rows[-1] if rows else None

    @staticmethod
    def _select_current_subscription(
        rows: tuple[TenantApplicationSubscription, ...],
    ) -> TenantApplicationSubscription | None:
        """Select the single current subscription, or the latest terminal row.

        A current subscription is ``PENDING``/``ACTIVE``/``SUSPENDED``. When
        no current subscription exists the most recent terminal row is
        returned so the evaluator reports a not-active (rather than missing)
        fact.
        """
        current = [
            row
            for row in rows
            if row.lifecycle
            in (
                SubscriptionLifecycle.PENDING,
                SubscriptionLifecycle.ACTIVE,
                SubscriptionLifecycle.SUSPENDED,
            )
        ]
        if len(current) > 1:
            raise ApplicationTenantEligibilityIntegrityError(
                "more than one current Tenant-Application subscription exists for a pair"
            )
        if current:
            return current[0]
        return rows[-1] if rows else None
