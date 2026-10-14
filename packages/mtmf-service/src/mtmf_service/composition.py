"""Explicit dependency composition for the PR 17 HTTP PDP.

The application factory receives already-built dependencies; this module
is the one place that wires the provider-neutral persistence SPI, the
PR 14 verified actor service, the PR 9 effective-Role resolver, the PR 16
pure-Python batch evaluator, the clock, the sensitivity classifier and
the rate limiter. It performs no import-time network/DB access and keeps
no mutable global actor state.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.effective_roles import EffectiveRoleResolver
from mtmf_core.application.management_memberships import ManagementMembershipService
from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.authorization.batch import BatchAuthorizer
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_service.authentication.composition import build_actor_context_service
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.clock import Clock, SystemClock
from mtmf_service.concurrency import EvaluationAdmission
from mtmf_service.evaluation import AuthorizationService
from mtmf_service.management import ManagementMembershipHttpService
from mtmf_service.observability import Telemetry, build_telemetry
from mtmf_service.rate_limit import RateLimiter, TokenBucketRateLimiter
from mtmf_service.readiness import ReadinessProbe, ReadinessState
from mtmf_service.sensitivity import (
    ConservativeSensitiveActionClassifier,
    SensitiveActionClassifier,
)
from mtmf_service.settings import ServiceSettings

__all__ = [
    "ServiceDependencies",
    "build_authorization_service",
    "build_dependencies",
    "build_readiness",
]


@dataclass(frozen=True, slots=True)
class ServiceDependencies:
    """The immutable, already-built dependencies of one service instance."""

    authorization_service: AuthorizationService
    management_membership_service: ManagementMembershipHttpService
    readiness: ReadinessState
    rate_limiter: RateLimiter
    admission: EvaluationAdmission
    telemetry: Telemetry


def build_authorization_service(
    *,
    spi: MtmfSpi,
    issuer_config: IssuerConfig,
    settings: ServiceSettings,
    actor_service: AuthenticatedActorContextService | None = None,
    batch_authorizer: BatchAuthorizer | None = None,
    clock: Clock | None = None,
    sensitivity: SensitiveActionClassifier | None = None,
    telemetry: Telemetry | None = None,
) -> AuthorizationService:
    """Build the transport-independent authorization orchestrator."""
    return AuthorizationService(
        actor_service=actor_service or build_actor_context_service(spi, issuer_config),
        spi=spi,
        role_resolver=EffectiveRoleResolver(spi),
        batch_authorizer=batch_authorizer or BatchAuthorizer(),
        clock=clock or SystemClock(),
        sensitivity=sensitivity or ConservativeSensitiveActionClassifier(),
        settings=settings,
        telemetry=telemetry,
    )


def build_readiness(
    *,
    spi: MtmfSpi,
    initialization_complete: Callable[[], bool],
    require_initialization: bool,
) -> ReadinessState:
    """Build a fail-closed readiness probe.

    The database check forces one low-latency round trip; the
    initialization check reflects the development-profile marker. Neither
    check exposes a public authorization oracle.
    """

    def _check_database() -> None:
        from mtmf_core.domain.identity import DomainId

        with spi.create_unit_of_work() as uow:
            spi.create_tenant_repository(uow).get(DomainId.generate())

    def _check_initialization() -> None:
        if require_initialization and not initialization_complete():
            raise RuntimeError("development initialization is incomplete")

    return ReadinessProbe((_check_database, _check_initialization))


def build_dependencies(
    *,
    spi: MtmfSpi,
    issuer_config: IssuerConfig,
    settings: ServiceSettings,
    initialization_complete: Callable[[], bool],
    require_initialization: bool,
    actor_service: AuthenticatedActorContextService | None = None,
    batch_authorizer: BatchAuthorizer | None = None,
    clock: Clock | None = None,
    sensitivity: SensitiveActionClassifier | None = None,
    rate_limiter: RateLimiter | None = None,
    telemetry: Telemetry | None = None,
    management_membership_service: ManagementMembershipHttpService | None = None,
) -> ServiceDependencies:
    """Build the complete dependency set for :func:`create_app`."""
    resolved_telemetry = telemetry or build_telemetry(settings)
    # One trusted actor service instance is shared by the evaluation path
    # and the management mutation path; token verification is never
    # reconstructed differently for the mutation route.
    resolved_actor_service = actor_service or build_actor_context_service(spi, issuer_config)
    resolved_management_service = management_membership_service or ManagementMembershipHttpService(
        membership_service=ManagementMembershipService(
            spi=spi,
            actor_service=resolved_actor_service,
            role_resolver=EffectiveRoleResolver(spi),
            authorizer=Authorizer(),
        )
    )
    return ServiceDependencies(
        authorization_service=build_authorization_service(
            spi=spi,
            issuer_config=issuer_config,
            settings=settings,
            actor_service=resolved_actor_service,
            batch_authorizer=batch_authorizer,
            clock=clock,
            sensitivity=sensitivity,
            telemetry=resolved_telemetry,
        ),
        management_membership_service=resolved_management_service,
        readiness=build_readiness(
            spi=spi,
            initialization_complete=initialization_complete,
            require_initialization=require_initialization,
        ),
        rate_limiter=rate_limiter
        or TokenBucketRateLimiter(
            per_minute=settings.rate_limit_per_minute,
            burst=settings.rate_limit_burst,
        ),
        admission=EvaluationAdmission(settings.max_in_flight_evaluations),
        telemetry=resolved_telemetry,
    )
