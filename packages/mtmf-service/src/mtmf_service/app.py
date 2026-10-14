"""FastAPI application factory for the PR 17 authenticated HTTP PDP.

The route accepts the *exact* frozen PR 15 batch request and produces the
exact PR 15 ordered response or static error envelope. It never uses a
permissive framework parser for the authorization body, never trusts a
forwarded header, never enables interactive docs/debug, and never returns
a partial authorization result. All trust, eligibility and policy work
is delegated to the transport-independent
:class:`~mtmf_service.evaluation.AuthorizationService`.

Observability is additive and fail-safe: exactly one terminal audit event
per completed request (batch, rejection, or error) is emitted at this
boundary, plus one HTTP metric. Telemetry never changes the response,
never broadens access, and a telemetry fault can never suppress a
default-deny outcome.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from opentelemetry.trace import SpanKind
from starlette.concurrency import run_in_threadpool

from mtmf_api.authorization import (
    AuthorizationBatchResponse,
    AuthorizationEffect,
)
from mtmf_api.errors import ApiErrorCode, ApiErrorResponse
from mtmf_api.json_codec import (
    parse_membership_add_json,
    parse_request_json,
    serialize_error,
    serialize_membership_add_response,
    serialize_response,
)
from mtmf_api.management import IdentityGroupMembershipAddResponse
from mtmf_service.concurrency import EvaluationAdmission, run_admitted
from mtmf_service.errors import PublicError, map_exception
from mtmf_service.evaluation import AuthorizationService
from mtmf_service.management import ManagementMembershipHttpService
from mtmf_service.observability import (
    AuditEventName,
    AuditOutcome,
    AuditReason,
    Telemetry,
    classify_failure,
)
from mtmf_service.observability.metrics import (
    BatchOutcomeLabel,
    DependencyFailureCategory,
    DependencyLabel,
    HttpMethod,
    HttpRoute,
    HttpStatusClass,
)
from mtmf_service.observability.spans import SpanName
from mtmf_service.rate_limit import RateLimiter
from mtmf_service.readiness import ReadinessState
from mtmf_service.settings import ServiceSettings
from mtmf_service.transport import (
    enforce_json_content_type,
    extract_service_token,
    extract_user_token,
    peer_key,
    read_bounded_body,
)

__all__ = ["create_app"]

_NO_STORE = {"Cache-Control": "no-store"}
_EVALUATE_ROUTE = "/v1/authorization/evaluate"
_MANAGEMENT_MEMBERSHIP_ROUTE = "/v1/management/identity-group-memberships"


def _error_response(code: ApiErrorCode, trace_id: str) -> Response:
    """Build the exact PR 15 static error envelope response."""
    envelope = ApiErrorResponse.for_code(code, request_id=trace_id)
    return Response(
        content=serialize_error(envelope),
        status_code=envelope.http_status,
        media_type="application/json",
        headers=dict(_NO_STORE),
    )


def _trace_id() -> str:
    """Return a bounded, opaque, server-generated transport correlation id.

    This is the public error-correlation token, not a W3C trace id; the
    OTel SDK owns trace context and it is never fabricated from this value.
    """
    return uuid.uuid4().hex


def _status_class(status_code: int) -> HttpStatusClass:
    if 200 <= status_code < 300:
        return HttpStatusClass.SUCCESS
    if 300 <= status_code < 400:
        return HttpStatusClass.REDIRECT
    if 400 <= status_code < 500:
        return HttpStatusClass.CLIENT_ERROR
    if 500 <= status_code < 600:
        return HttpStatusClass.SERVER_ERROR
    return HttpStatusClass.UNKNOWN


def create_app(
    *,
    settings: ServiceSettings,
    authorization_service: AuthorizationService,
    management_membership_service: ManagementMembershipHttpService,
    readiness: ReadinessState,
    rate_limiter: RateLimiter,
    admission: EvaluationAdmission | None = None,
    telemetry: Telemetry | None = None,
    on_shutdown: Callable[[], None] | None = None,
) -> FastAPI:
    """Build the ASGI application with explicit injected dependencies.

    :param on_shutdown: Optional finite-deadline telemetry shutdown hook
        invoked once when the ASGI lifespan ends.
    :raises mtmf_service.settings.ServiceConfigurationError: when the
        selected deployment profile is unsupported or unsafe.
    """
    settings.validate_startup()
    admission = admission or EvaluationAdmission(settings.max_in_flight_evaluations)
    telemetry = telemetry or Telemetry.disabled()

    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if on_shutdown is not None:
                on_shutdown()

    app = FastAPI(
        title="MTMF authorization service",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
        lifespan=_lifespan,
    )

    def _correlation_id(request: Request) -> str:
        """Return the request-scoped server-owned correlation id."""
        existing = getattr(request.state, "correlation_id", None)
        if isinstance(existing, str) and existing:
            return existing
        value = telemetry.new_correlation_id()
        request.state.correlation_id = value
        return value

    def _claim_terminal(request: Request) -> bool:
        """Mark the request terminal; return ``False`` if already marked."""
        if getattr(request.state, "terminal_event_emitted", False):
            return False
        request.state.terminal_event_emitted = True
        return True

    def _record_dependency_failure(reason: AuditReason) -> None:
        if reason is AuditReason.DATABASE_UNAVAILABLE:
            telemetry.record_dependency_failure(
                dependency=DependencyLabel.POSTGRES,
                category=DependencyFailureCategory.UNAVAILABLE,
            )
        elif reason is AuditReason.ISSUER_UNAVAILABLE:
            telemetry.record_dependency_failure(
                dependency=DependencyLabel.ISSUER,
                category=DependencyFailureCategory.UNAVAILABLE,
            )

    def _emit_failure(
        request: Request,
        correlation_id: str,
        error: BaseException,
        duration_ms: float | None,
    ) -> None:
        """Emit the one terminal rejection/error event for a failed request."""
        if not _claim_terminal(request):
            return
        classification = classify_failure(error)
        if classification.event_name is AuditEventName.AUTHORIZATION_ERROR:
            telemetry.record_error_event(
                reason_code=classification.reason_code,
                correlation_id=correlation_id,
                duration_ms=duration_ms,
            )
        else:
            telemetry.record_rejection_event(
                name=classification.event_name,
                reason_code=classification.reason_code,
                correlation_id=correlation_id,
                duration_ms=duration_ms,
            )
            telemetry.record_rejection_metric(category=classification.reason_code)
        _record_dependency_failure(classification.reason_code)

    def _emit_batch(
        request: Request,
        correlation_id: str,
        response: AuthorizationBatchResponse,
        duration_ms: float,
    ) -> None:
        """Emit the one terminal batch event for a validated response."""
        if not _claim_terminal(request):
            return
        allow_count = sum(
            1 for decision in response.decisions if decision.effect is AuthorizationEffect.ALLOW
        )
        deny_count = len(response.decisions) - allow_count
        if allow_count == 0:
            outcome = BatchOutcomeLabel.DENY
        elif deny_count == 0:
            outcome = BatchOutcomeLabel.ALLOW
        else:
            outcome = BatchOutcomeLabel.MIXED
        telemetry.record_batch_event(
            correlation_id=correlation_id,
            outcome=_audit_outcome(outcome),
            duration_ms=duration_ms,
            action_count=len(response.decisions),
            allow_count=allow_count,
            deny_count=deny_count,
        )

    def _emit_management(
        request: Request,
        correlation_id: str,
        response: IdentityGroupMembershipAddResponse,
        duration_ms: float,
    ) -> None:
        """Emit the one terminal management-mutation event (never a batch event)."""
        if not _claim_terminal(request):
            return
        telemetry.record_management_event(
            outcome=AuditOutcome.CREATED if response.created else AuditOutcome.NO_OP,
            correlation_id=correlation_id,
            duration_ms=duration_ms,
        )

    @app.exception_handler(PublicError)
    async def _handle_public_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, PublicError)
        correlation_id = _correlation_id(request)
        _emit_failure(request, correlation_id, exc, None)
        return _error_response(exc.code, correlation_id)

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> Response:
        # Defense in depth for faults raised outside the route body; the
        # route itself converts every mapped failure to a PublicError, so
        # this only sees genuinely unexpected internals.
        correlation_id = _correlation_id(request)
        _emit_failure(request, correlation_id, exc, None)
        return _error_response(map_exception(exc), correlation_id)

    async def _run_evaluation(request: Request) -> AuthorizationBatchResponse:
        if not rate_limiter.acquire(peer_key(request)):
            raise PublicError(ApiErrorCode.RATE_LIMITED)
        enforce_json_content_type(request)
        body = await read_bounded_body(request, max_bytes=settings.max_request_bytes)
        parsed = parse_request_json(body)
        service_token = extract_service_token(request)
        user_token = extract_user_token(request, header_name=settings.user_authorization_header)
        # Explicit admission: a permit is held until the worker actually
        # completes, not merely until the HTTP deadline. Saturation is a
        # deterministic 503 rather than unbounded queueing.
        permit = admission.try_acquire()
        if permit is None:
            raise PublicError(
                ApiErrorCode.DEPENDENCY_UNAVAILABLE,
                audit_reason=AuditReason.ADMISSION_REJECTED.value,
            )

        def _admitted_worker() -> AuthorizationBatchResponse:
            # Runs in the worker thread. ``run_admitted`` refuses to execute
            # if the transport already released the permit (cancellation
            # proven to precede execution) and otherwise releases it only
            # after the synchronous evaluation actually returns or raises.
            return run_admitted(
                permit,
                lambda: authorization_service.evaluate(
                    service_token=service_token,
                    user_token=user_token,
                    request=parsed,
                ),
            )

        try:
            return await asyncio.wait_for(
                run_in_threadpool(_admitted_worker),
                timeout=settings.evaluation_timeout_seconds,
            )
        except TimeoutError as exc:
            # The worker may still be running; its permit stays held until
            # it finishes. If it was cancelled before it began, release now.
            permit.release_if_not_started()
            raise PublicError(ApiErrorCode.DEPENDENCY_UNAVAILABLE) from exc
        except BaseException:
            permit.release_if_not_started()
            raise

    @app.post(_EVALUATE_ROUTE)
    async def evaluate(request: Request) -> Response:
        correlation_id = _correlation_id(request)
        started = time.perf_counter()
        with telemetry.span(
            SpanName.HTTP_EVALUATE,
            kind=SpanKind.SERVER,
            attributes={
                "http.request.method": "POST",
                "http.route": _EVALUATE_ROUTE,
            },
        ):
            try:
                batch_response = await _run_evaluation(request)
            except PublicError as exc:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_failure(request, correlation_id, exc, duration_ms)
                response: Response = _error_response(exc.code, correlation_id)
            except Exception as exc:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_failure(request, correlation_id, exc, duration_ms)
                response = _error_response(map_exception(exc), correlation_id)
            else:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_batch(request, correlation_id, batch_response, duration_ms)
                response = Response(
                    content=serialize_response(batch_response),
                    status_code=200,
                    media_type="application/json",
                    headers=dict(_NO_STORE),
                )
        telemetry.record_http_request(
            route=HttpRoute.EVALUATE,
            method=HttpMethod.POST,
            status_class=_status_class(response.status_code),
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
        return response

    async def _run_management(request: Request) -> IdentityGroupMembershipAddResponse:
        if not rate_limiter.acquire(peer_key(request)):
            raise PublicError(ApiErrorCode.RATE_LIMITED)
        enforce_json_content_type(request)
        body = await read_bounded_body(request, max_bytes=settings.max_request_bytes)
        parsed = parse_membership_add_json(body)
        service_token = extract_service_token(request)
        user_token = extract_user_token(request, header_name=settings.user_authorization_header)
        permit = admission.try_acquire()
        if permit is None:
            raise PublicError(
                ApiErrorCode.DEPENDENCY_UNAVAILABLE,
                audit_reason=AuditReason.ADMISSION_REJECTED.value,
            )

        def _admitted_worker() -> IdentityGroupMembershipAddResponse:
            return run_admitted(
                permit,
                lambda: management_membership_service.add_identity_to_group(
                    service_token=service_token,
                    user_token=user_token,
                    request=parsed,
                ),
            )

        try:
            return await asyncio.wait_for(
                run_in_threadpool(_admitted_worker),
                timeout=settings.evaluation_timeout_seconds,
            )
        except TimeoutError as exc:
            # Outcome unknown: the worker may still finish and commit. The
            # permit is retained until it actually completes. A fresh
            # authenticated retry observes the committed state as a no-op.
            permit.release_if_not_started()
            raise PublicError(ApiErrorCode.DEPENDENCY_UNAVAILABLE) from exc
        except BaseException:
            permit.release_if_not_started()
            raise

    @app.post(_MANAGEMENT_MEMBERSHIP_ROUTE)
    async def management_membership_add(request: Request) -> Response:
        correlation_id = _correlation_id(request)
        started = time.perf_counter()
        with telemetry.span(
            SpanName.HTTP_MANAGEMENT_MEMBERSHIP_ADD,
            kind=SpanKind.SERVER,
            attributes={
                "http.request.method": "POST",
                "http.route": _MANAGEMENT_MEMBERSHIP_ROUTE,
            },
        ):
            try:
                result = await _run_management(request)
            except PublicError as exc:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_failure(request, correlation_id, exc, duration_ms)
                response: Response = _error_response(exc.code, correlation_id)
            except Exception as exc:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_failure(request, correlation_id, exc, duration_ms)
                response = _error_response(map_exception(exc), correlation_id)
            else:
                duration_ms = (time.perf_counter() - started) * 1000.0
                _emit_management(request, correlation_id, result, duration_ms)
                response = Response(
                    content=serialize_membership_add_response(result),
                    status_code=201 if result.created else 200,
                    media_type="application/json",
                    headers=dict(_NO_STORE),
                )
        telemetry.record_http_request(
            route=HttpRoute.MANAGEMENT_MEMBERSHIP_ADD,
            method=HttpMethod.POST,
            status_class=_status_class(response.status_code),
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
        return response

    @app.get("/health/live")
    async def live() -> JSONResponse:
        return JSONResponse(status_code=200, content={"status": "alive"}, headers=dict(_NO_STORE))

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        if readiness.is_ready():
            return JSONResponse(
                status_code=200, content={"status": "ready"}, headers=dict(_NO_STORE)
            )
        return JSONResponse(
            status_code=503, content={"status": "not_ready"}, headers=dict(_NO_STORE)
        )

    return app


def _audit_outcome(outcome: BatchOutcomeLabel) -> AuditOutcome:
    """Map a metric batch-outcome label to the audit outcome enum."""
    return AuditOutcome(outcome.value)
