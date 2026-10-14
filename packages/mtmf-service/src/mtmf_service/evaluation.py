"""Authenticated batch authorization orchestration (PR 17).

This is the transport-independent core of the HTTP PDP. It composes the
already-verified PR 14 actor context, the PR 9 effective-Role resolver,
the authoritative PR 16 pure-Python batch evaluator, and the PR 15 DTOs
into one ordered batch decision. It performs no HTTP parsing, no policy
reconstruction, and no second authorization engine.

Security ordering (never reordered to broaden access):

1. verify the service credential, acting-user token, ordinary-Tenant
   context, Application registration and subscription through PR 14
   (which itself runs the PR 13 eligibility gate) in one UnitOfWork;
2. resolve the applicable Roles and the action catalog from authoritative
   persisted state in a second UnitOfWork -- never from client payload;
3. build exactly **one** shared ``AuthorizationContext`` object and one
   ``AuthorizationBatch`` sharing that object identity;
4. invoke the PR 16 pure-Python batch evaluator once;
5. map every ordered core decision to the public DTO, overriding unknown
   Actions to ``UNKNOWN_ACTION`` and unsupported ``mtmf_owned`` targets to
   ``UNSUPPORTED_RESOURCE`` (neither can ever ALLOW);
6. validate response conformance and issue one bounded UTC snapshot.

No DB transaction is held across issuer/JWKS/Admin-REST calls (those are
completed inside step 1 before the actor service opens its transaction).
"""

from __future__ import annotations

import time
from datetime import timedelta

from mtmf_api.authorization import (
    ActionDecision,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
)
from mtmf_api.conformance import validate_response_for_request
from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.effective_roles import EffectiveRoleResolver, build_authorization_context
from mtmf_core.authentication.contracts import VerifiedActorContext
from mtmf_core.authorization.batch import AuthorizationBatch, BatchAuthorizer
from mtmf_core.authorization.context import AuthorizationContext, AuthorizationRequest
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.decision import AuthorizationEffect as CoreEffect
from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.session import SessionContext
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_service.clock import Clock
from mtmf_service.observability import BatchOutcomeLabel, Telemetry
from mtmf_service.observability.spans import SpanName
from mtmf_service.sensitivity import SensitiveActionClassifier
from mtmf_service.settings import ServiceSettings

__all__ = [
    "AuthorizationService",
    "InternalEvaluationError",
    "map_core_decision",
]


class InternalEvaluationError(Exception):
    """The core evaluator produced state the public v1 contract cannot represent.

    This is a whole-request 500, never a partial response and never a
    per-item DENY that would hide the fault.
    """


def map_core_decision(
    decision: AuthorizationDecision,
) -> tuple[AuthorizationEffect, DecisionReason]:
    """Map one complete core decision to the public effect/reason pair.

    A core DENY rationale that cannot be represented on the v1 wire raises
    :class:`InternalEvaluationError`; it is never guessed or flattened to a
    per-item ``NO_PERMISSION`` that could mask a fault.
    """
    if decision.effect is CoreEffect.ALLOW:
        return AuthorizationEffect.ALLOW, DecisionReason.PERMITTED
    reason = decision.reason
    if reason is DenyReason.NO_MATCH:
        return AuthorizationEffect.DENY, DecisionReason.NO_PERMISSION
    if reason is DenyReason.MATCHED_DENY:
        return AuthorizationEffect.DENY, DecisionReason.EXPLICIT_DENY
    if reason is DenyReason.INSUFFICIENT_DOMINANCE:
        return AuthorizationEffect.DENY, DecisionReason.INVALID_SCOPE
    if reason is DenyReason.UNSUPPORTED_CONSTRAINT:
        return AuthorizationEffect.DENY, DecisionReason.UNSUPPORTED_RESOURCE
    raise InternalEvaluationError(
        f"core decision reason {reason!r} has no public v1 representation"
    )


class AuthorizationService:
    """Orchestrate one authenticated, ordered, bounded batch decision."""

    __slots__ = (
        "_actor_service",
        "_batch_authorizer",
        "_clock",
        "_role_resolver",
        "_sensitivity",
        "_settings",
        "_spi",
        "_telemetry",
    )

    def __init__(
        self,
        *,
        actor_service: AuthenticatedActorContextService,
        spi: MtmfSpi,
        role_resolver: EffectiveRoleResolver,
        batch_authorizer: BatchAuthorizer,
        clock: Clock,
        sensitivity: SensitiveActionClassifier,
        settings: ServiceSettings,
        telemetry: Telemetry | None = None,
    ) -> None:
        self._actor_service = actor_service
        self._spi = spi
        self._role_resolver = role_resolver
        self._batch_authorizer = batch_authorizer
        self._clock = clock
        self._sensitivity = sensitivity
        self._settings = settings
        self._telemetry = telemetry or Telemetry.disabled()

    def evaluate(
        self,
        *,
        service_token: str,
        user_token: str,
        request: AuthorizationBatchRequest,
    ) -> AuthorizationBatchResponse:
        """Return the ordered, conformant batch response for ``request``.

        :raises mtmf_core.authentication.contracts.AuthenticationError: on
            any trust/eligibility failure (mapped by the HTTP adapter).
        :raises mtmf_core.persistence.errors.PersistenceError: on a
            persistence/dependency failure.
        :raises InternalEvaluationError: on an unrepresentable internal
            evaluator state.
        :raises mtmf_api.conformance.ResponseConformanceError: if the
            assembled response does not conform to the request.
        """
        started = time.perf_counter()
        instant = self._clock.now()
        with self._telemetry.span(SpanName.ACTOR_VERIFY):
            actor = self._actor_service.resolve(
                service_token=service_token,
                user_token=user_token,
                tenant_id=DomainId(request.tenant_id),
                at=instant,
            )
        with self._telemetry.span(SpanName.ROLES_RESOLVE):
            context, known_actions = self._resolve_context(actor, request)
        requests = tuple(
            AuthorizationRequest(
                context=context,
                action=Action(urn=ActionUrn(item.action)),
                target_tenant_id=actor.tenant_id,
            )
            for item in request.actions
        )
        batch = AuthorizationBatch(requests=requests)
        with self._telemetry.span(SpanName.AUTHORIZATION_BATCH):
            result = self._batch_authorizer.authorize(batch)
        decisions = tuple(
            self._map_item(request, index, decision, known_actions)
            for index, decision in enumerate(result.decisions)
        )
        response = AuthorizationBatchResponse(
            tenant_id=request.tenant_id,
            organization_id=request.organization_id,
            issued_at=instant,
            expires_at=instant + self._select_ttl(request),
            decisions=decisions,
        )
        # A conformance fault is an internal error, never a partially
        # useful result. Batch metrics are recorded only after the
        # validated response is final, so a later conformance rejection can
        # never contribute an ALLOW count.
        validate_response_for_request(request, response)
        self._record_batch_metrics(decisions, duration_ms=(time.perf_counter() - started) * 1000.0)
        return response

    def _record_batch_metrics(
        self,
        decisions: tuple[ActionDecision, ...],
        *,
        duration_ms: float,
    ) -> None:
        """Record the finalized, validated batch decision distribution."""
        allow_count = sum(
            1 for decision in decisions if decision.effect is AuthorizationEffect.ALLOW
        )
        deny_count = len(decisions) - allow_count
        if allow_count == 0:
            outcome = BatchOutcomeLabel.DENY
        elif deny_count == 0:
            outcome = BatchOutcomeLabel.ALLOW
        else:
            outcome = BatchOutcomeLabel.MIXED
        self._telemetry.record_batch_metrics(
            outcome=outcome,
            duration_ms=duration_ms,
            action_count=len(decisions),
            allow_count=allow_count,
            deny_count=deny_count,
        )

    def _resolve_context(
        self,
        actor: VerifiedActorContext,
        request: AuthorizationBatchRequest,
    ) -> tuple[AuthorizationContext, frozenset[str]]:
        """Resolve roles and Action existence from authoritative state once."""
        session = SessionContext(
            tenant_id=actor.tenant_id,
            principal_id=actor.principal_id,
            identity_id=actor.identity_id,
        )
        target_organization_id = (
            DomainId(request.organization_id) if request.organization_id is not None else None
        )
        with self._spi.create_unit_of_work() as uow:
            state = self._role_resolver.resolve(
                uow,
                session=session,
                target_tenant_id=actor.tenant_id,
                target_organization_id=target_organization_id,
            )
            context = build_authorization_context(state)
            action_repository = self._spi.create_action_repository(uow)
            known = frozenset(
                item.action
                for item in request.actions
                if action_repository.get(ActionUrn(item.action)) is not None
            )
        return context, known

    def _map_item(
        self,
        request: AuthorizationBatchRequest,
        index: int,
        decision: AuthorizationDecision,
        known_actions: frozenset[str],
    ) -> ActionDecision:
        """Map one ordered occurrence, overriding unsafe unrepresentable cases."""
        item = request.actions[index]
        if item.action not in known_actions:
            # An unregistered (but syntactically valid) Action can never
            # ALLOW, regardless of any wildcard Permission text.
            return ActionDecision(
                request_id=item.request_id,
                effect=AuthorizationEffect.DENY,
                reason=DecisionReason.UNKNOWN_ACTION,
            )
        if item.resource.kind is ResourceKind.MTMF_OWNED:
            # No approved, typed, authoritative MTMF-owned target mapping
            # exists, so an MTMF-owned target can never ALLOW.
            return ActionDecision(
                request_id=item.request_id,
                effect=AuthorizationEffect.DENY,
                reason=DecisionReason.UNSUPPORTED_RESOURCE,
            )
        effect, reason = map_core_decision(decision)
        return ActionDecision(request_id=item.request_id, effect=effect, reason=reason)

    def _select_ttl(self, request: AuthorizationBatchRequest) -> timedelta:
        """Choose the bounded snapshot lifetime for the whole response.

        A single sensitive Action bounds the entire response to the
        sensitive TTL because v1 exposes one ``expires_at``.
        """
        if any(self._sensitivity.is_sensitive(item.action) for item in request.actions):
            return timedelta(seconds=self._settings.sensitive_ttl_seconds)
        return timedelta(seconds=self._settings.default_ttl_seconds)
