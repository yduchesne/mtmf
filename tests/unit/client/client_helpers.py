"""Deterministic helpers for the PR 18 client unit tests.

These helpers exercise the *real* production client code. The only fakes
are at external I/O seams: an ``httpx.MockTransport`` (no network), fake
monotonic/UTC clocks, and an in-memory secret provider. No policy engine
or authorization decision logic is faked.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx

from mtmf_api.authorization import (
    ActionDecision,
    ActionRequest,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
)
from mtmf_api.json_codec import parse_request_json, serialize_response
from mtmf_client import ClientConfig, HttpMtmfClient, TrustedActorContext

ACTION_ALLOW = "urn:mtmf:iam:actions:system:principal:get-object"
ACTION_DENY = "urn:mtmf:iam:actions:system:principal:update-object"
ACTION_OTHER = "urn:mtmf:iam:actions:system:role:get-object"
ACTION_UNKNOWN = "urn:mtmf:iam:actions:system:frobnicator:get-object"
TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("12121212-1212-4212-8212-121212121212")
ORGANIZATION_ID = UUID("22222222-2222-4222-8222-222222222222")
APP_ID = UUID("33333333-3333-4333-8333-333333333333")
OTHER_APP_ID = UUID("34343434-3434-4343-8343-343434343434")
PRINCIPAL_ID = UUID("44444444-4444-4444-8444-444444444444")
IDENTITY_ID = UUID("55555555-5555-4555-8555-555555555555")
BASE_URL = "https://pdp.mtmf.test:28443"
TOKEN_ENDPOINT = "https://keycloak.mtmf.test:28443/realms/mtmf-dev/protocol/openid-connect/token"
USER_TOKEN = "user-access-token-value"
SERVICE_TOKEN = "service-access-token-value"


class StaticSecret:
    """An in-memory secret provider (test seam only)."""

    def __init__(self, value: str = "service-client-secret") -> None:
        self._value = value

    def read(self) -> str:
        return self._value


class FakeClock:
    """Controllable monotonic + UTC clocks."""

    def __init__(
        self,
        *,
        mono: float = 1000.0,
        wall: datetime | None = None,
    ) -> None:
        self.mono = mono
        self.wall = wall or datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)

    def monotonic(self) -> float:
        return self.mono

    def utc(self) -> datetime:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall = self.wall + timedelta(seconds=seconds)

    def advance_monotonic(self, seconds: float) -> None:
        """Advance only the monotonic clock (wall clock unchanged)."""
        self.mono += seconds

    def advance_wall(self, seconds: float) -> None:
        """Advance only the wall clock (monotonic unchanged)."""
        self.wall = self.wall + timedelta(seconds=seconds)


def make_config(**overrides: Any) -> ClientConfig:
    """Build a valid default configuration with optional overrides."""
    values: dict[str, Any] = {
        "base_url": BASE_URL,
        "token_endpoint": TOKEN_ENDPOINT,
        "application_id": APP_ID,
        "client_id": "mtmf-evidence-same-client",
        "secret_provider": StaticSecret(),
        "clock_uncertainty_seconds": 0.0,
        "max_response_bytes": 8192,
    }
    values.update(overrides)
    return ClientConfig(**values)


def make_context(**overrides: Any) -> TrustedActorContext:
    """Build a valid trusted actor context with optional overrides."""
    values: dict[str, Any] = {
        "actor_key": "actor-1",
        "session_key": "session-1",
        "tenant_id": TENANT_ID,
        "application_id": APP_ID,
        "principal_id": PRINCIPAL_ID,
        "identity_id": IDENTITY_ID,
        "organization_id": None,
    }
    values.update(overrides)
    return TrustedActorContext(**values)


def capability() -> ResourceTarget:
    """A capability resource target."""
    return ResourceTarget(kind=ResourceKind.CAPABILITY)


def application_owned(resource_id: str = "row-1") -> ResourceTarget:
    """An application-owned resource target."""
    return ResourceTarget(
        kind=ResourceKind.APPLICATION_OWNED,
        resource_type="document",
        resource_id=resource_id,
    )


def make_request(
    *actions: tuple[str, str, ResourceTarget | None],
    tenant_id: UUID = TENANT_ID,
    organization_id: UUID | None = None,
) -> AuthorizationBatchRequest:
    """Build a request; each action is ``(request_id, action_urn, resource|None)``."""
    if not actions:
        actions = (("req-1", ACTION_ALLOW, None),)
    return AuthorizationBatchRequest(
        tenant_id=tenant_id,
        organization_id=organization_id,
        actions=tuple(
            ActionRequest(
                request_id=request_id,
                action=action,
                resource=resource if resource is not None else capability(),
            )
            for request_id, action, resource in actions
        ),
    )


def make_response(
    request: AuthorizationBatchRequest,
    *,
    effects: list[tuple[AuthorizationEffect, DecisionReason]] | None = None,
    tenant_id: UUID | None = None,
    organization_id: UUID | None = None,
    issued_at: datetime | None = None,
    lifetime: timedelta = timedelta(seconds=300),
) -> AuthorizationBatchResponse:
    """Build a response conforming to ``request`` (default all ALLOW/PERMITTED)."""
    if effects is None:
        effects = [(AuthorizationEffect.ALLOW, DecisionReason.PERMITTED)] * len(request.actions)
    decisions = tuple(
        ActionDecision(request_id=action.request_id, effect=effect, reason=reason)
        for action, (effect, reason) in zip(request.actions, effects, strict=True)
    )
    issued = issued_at or datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)
    return AuthorizationBatchResponse(
        tenant_id=request.tenant_id if tenant_id is None else tenant_id,
        organization_id=request.organization_id if organization_id is None else organization_id,
        issued_at=issued,
        expires_at=issued + lifetime,
        decisions=decisions,
    )


def json_response(
    body: str,
    *,
    status_code: int = 200,
    content_type: str = "application/json",
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a deterministic HTTP response with an exact body."""
    headers = {"content-type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Response(status_code=status_code, content=body.encode(), headers=headers)


def response_body(response: AuthorizationBatchResponse) -> str:
    """Serialize a response DTO to its canonical v1 JSON."""
    return serialize_response(response)


def token_body(
    *,
    access_token: str = SERVICE_TOKEN,
    expires_in: int | float = 300,
    token_type: str = "Bearer",
) -> str:
    """A well-formed OAuth token response."""
    return json.dumps(
        {
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": expires_in,
        }
    )


def error_envelope(code: str, message: str, *, request_id: str | None = None) -> str:
    """A well-formed v1 error envelope."""
    body: dict[str, Any] = {"code": code, "message": message}
    if request_id is not None:
        body["request_id"] = request_id
    return json.dumps({"schema_version": "1", "error": body})


class FakeServer:
    """A routing, stateful ``httpx.MockTransport`` handler.

    Records every request and serves queued or default responses for the
    token endpoint and the evaluate endpoint without opening a socket.
    """

    def __init__(
        self,
        *,
        token_response: Callable[[httpx.Request], httpx.Response] | None = None,
        evaluate_response: Callable[[httpx.Request], httpx.Response] | None = None,
    ) -> None:
        self.token_calls = 0
        self.evaluate_calls = 0
        self.token_requests: list[httpx.Request] = []
        self.evaluate_requests: list[httpx.Request] = []
        self._token_response = token_response
        self._evaluate_response = evaluate_response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            self.token_calls += 1
            self.token_requests.append(request)
            if self._token_response is not None:
                return self._token_response(request)
            return json_response(token_body())
        self.evaluate_calls += 1
        self.evaluate_requests.append(request)
        if self._evaluate_response is not None:
            return self._evaluate_response(request)
        raise AssertionError("the test did not configure an evaluate response")

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    @property
    def last_evaluate(self) -> httpx.Request:
        assert self.evaluate_requests, "no evaluate request was made"
        return self.evaluate_requests[-1]

    @property
    def last_token(self) -> httpx.Request:
        assert self.token_requests, "no token request was made"
        return self.token_requests[-1]


def build_client(
    server: FakeServer,
    *,
    config: ClientConfig | None = None,
    clock: FakeClock | None = None,
    instrumentation: Any | None = None,
) -> tuple[HttpMtmfClient, ClientConfig, FakeClock]:
    """Build a real ``HttpMtmfClient`` wired to the fake transport and clocks."""
    config = config or make_config()
    clock = clock or FakeClock()
    client = HttpMtmfClient(
        config,
        transport=server.transport,
        monotonic_clock=clock.monotonic,
        utc_clock=clock.utc,
        instrumentation=instrumentation,
    )
    return client, config, clock


def allow_response_factory(
    request_factory: Callable[[], AuthorizationBatchRequest],
) -> Callable[[httpx.Request], httpx.Response]:
    """Return a handler that always answers with a conforming ALLOW response."""

    def _handler(_: httpx.Request) -> httpx.Response:
        return json_response(response_body(make_response(request_factory())))

    return _handler


def conforming_allow(request: httpx.Request) -> httpx.Response:
    """Answer any evaluate request with a conforming all-ALLOW response."""
    parsed = parse_request_json(request.content)
    return json_response(response_body(make_response(parsed)))


def conforming_by_request_id(
    effects: dict[str, tuple[AuthorizationEffect, DecisionReason]],
) -> Callable[[httpx.Request], httpx.Response]:
    """Answer with per-``request_id`` effects for the parsed request."""

    def _handler(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        mapped = [
            effects.get(item.request_id, (AuthorizationEffect.DENY, DecisionReason.NO_PERMISSION))
            for item in parsed.actions
        ]
        return json_response(response_body(make_response(parsed, effects=mapped)))

    return _handler
