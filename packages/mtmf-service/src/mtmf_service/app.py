"""FastAPI application factory for the PR 17 authenticated HTTP PDP.

The route accepts the *exact* frozen PR 15 batch request and produces the
exact PR 15 ordered response or static error envelope. It never uses a
permissive framework parser for the authorization body, never trusts a
forwarded header, never enables interactive docs/debug, and never returns
a partial authorization result. All trust, eligibility and policy work
is delegated to the transport-independent
:class:`~mtmf_service.evaluation.AuthorizationService`.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from mtmf_api.authorization import AuthorizationBatchResponse
from mtmf_api.errors import ApiErrorCode, ApiErrorResponse
from mtmf_api.json_codec import parse_request_json, serialize_error, serialize_response
from mtmf_service.concurrency import EvaluationAdmission
from mtmf_service.errors import PublicError, map_exception
from mtmf_service.evaluation import AuthorizationService
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
    """Return a bounded, opaque, server-generated transport trace id."""
    return uuid.uuid4().hex


def create_app(
    *,
    settings: ServiceSettings,
    authorization_service: AuthorizationService,
    readiness: ReadinessState,
    rate_limiter: RateLimiter,
    admission: EvaluationAdmission | None = None,
) -> FastAPI:
    """Build the ASGI application with explicit injected dependencies.

    :raises mtmf_service.settings.ServiceConfigurationError: when the
        selected deployment profile is unsupported or unsafe.
    """
    settings.validate_startup()
    admission = admission or EvaluationAdmission(settings.max_in_flight_evaluations)

    app = FastAPI(
        title="MTMF authorization service",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
    )

    @app.exception_handler(PublicError)
    async def _handle_public_error(_: Request, exc: Exception) -> Response:
        assert isinstance(exc, PublicError)
        return _error_response(exc.code, _trace_id())

    @app.exception_handler(Exception)
    async def _handle_unexpected(_: Request, exc: Exception) -> Response:
        # Defense in depth for faults raised outside the route body; the
        # route itself converts every mapped failure to a PublicError, so
        # this only sees genuinely unexpected internals.
        return _error_response(map_exception(exc), _trace_id())

    async def _evaluate(request: Request) -> Response:
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
            raise PublicError(ApiErrorCode.DEPENDENCY_UNAVAILABLE)

        def _admitted_worker() -> AuthorizationBatchResponse:
            # Runs in the worker thread. The permit is released only when
            # the synchronous evaluation actually returns or raises, even
            # if the HTTP deadline already expired and abandoned the thread.
            permit.mark_started()
            try:
                return authorization_service.evaluate(
                    service_token=service_token,
                    user_token=user_token,
                    request=parsed,
                )
            finally:
                permit.release()

        try:
            response = await asyncio.wait_for(
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
        return Response(
            content=serialize_response(response),
            status_code=200,
            media_type="application/json",
            headers=dict(_NO_STORE),
        )

    @app.post("/v1/authorization/evaluate")
    async def evaluate(request: Request) -> Response:
        try:
            return await _evaluate(request)
        except PublicError:
            raise
        except Exception as exc:
            # Map semantic failures exactly once; never leak detail and
            # never degrade into a partial 200.
            raise PublicError(map_exception(exc)) from exc

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
