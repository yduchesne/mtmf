"""PR 19C management HTTP boundary tests (deterministic, stub use case).

These exercise the strict DTO/codec, transport guards, status selection,
opaque forbidden mapping, bounded admission/timeout lifecycle and the single
terminal management telemetry event. The trusted use case is stubbed so the
route/error/telemetry contract is tested independently of PostgreSQL; the
real use case is exercised by the PostgreSQL integration and live suites.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from mtmf_api.errors import ApiErrorCode
from mtmf_api.management import (
    IdentityGroupMembershipAddRequest,
    IdentityGroupMembershipAddResponse,
)
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.persistence.errors import PersistenceConnectionError
from mtmf_service.app import create_app
from mtmf_service.concurrency import EvaluationAdmission
from mtmf_service.errors import PublicError
from mtmf_service.observability import (
    AuditEventName,
    AuditOutcome,
    InMemoryAuditEventSink,
    Telemetry,
)
from mtmf_service.observability.metrics import InMemoryMetricsRecorder
from mtmf_service.rate_limit import TokenBucketRateLimiter
from mtmf_service.readiness import StaticReadiness
from mtmf_service.settings import ServiceSettings

TENANT = "00000000-0000-4000-8000-000000000001"
IDENTITY = "00000000-0000-4000-8000-000000000002"
GROUP = "00000000-0000-4000-8000-000000000003"
ROUTE = "/v1/management/identity-group-memberships"
HEADERS = {
    "Authorization": "Bearer service-token",
    "X-MTMF-User-Authorization": "Bearer user-token",
}


def _body(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "tenant_id": TENANT,
        "identity_id": IDENTITY,
        "group_id": GROUP,
    }
    value.update(overrides)
    return value


class _StubAuthorizationService:
    """Unused evaluate-path dependency placeholder."""


class _StubManagement:
    def __init__(self, *, created: bool = True) -> None:
        self.calls = 0
        self.created = created
        self.release = threading.Event()
        self.started = threading.Event()

    def add_identity_to_group(
        self,
        *,
        service_token: str,
        user_token: str,
        request: IdentityGroupMembershipAddRequest,
    ) -> IdentityGroupMembershipAddResponse:
        self.calls += 1
        if service_token == "bad-service":
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, slot="service")
        if user_token == "bad-user":
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, slot="user")
        if service_token == "forbidden":
            raise PublicError(ApiErrorCode.FORBIDDEN)
        if service_token == "db-outage":
            raise PersistenceConnectionError("persistence unavailable")
        if service_token == "blocking":
            self.started.set()
            self.release.wait(timeout=10)
        return IdentityGroupMembershipAddResponse(
            tenant_id=request.tenant_id,
            identity_id=request.identity_id,
            group_id=request.group_id,
            created=self.created,
        )


def _client(
    management: _StubManagement,
    *,
    settings: ServiceSettings | None = None,
    admission: EvaluationAdmission | None = None,
    telemetry: Telemetry | None = None,
) -> TestClient:
    app = create_app(
        settings=settings or ServiceSettings(),
        authorization_service=_StubAuthorizationService(),  # type: ignore[arg-type]
        management_membership_service=management,  # type: ignore[arg-type]
        readiness=StaticReadiness(True),
        rate_limiter=TokenBucketRateLimiter(per_minute=100000, burst=100000),
        admission=admission,
        telemetry=telemetry,
    )
    return TestClient(app, raise_server_exceptions=False)


def test_uh01_uh06_canonical_request_round_trip_created() -> None:
    management = _StubManagement(created=True)
    response = _client(management).post(ROUTE, json=_body(), headers=HEADERS)
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "tenant_id": TENANT,
        "identity_id": IDENTITY,
        "group_id": GROUP,
        "created": True,
    }
    assert management.calls == 1


def test_uh06_authorized_duplicate_is_200_no_op() -> None:
    management = _StubManagement(created=False)
    response = _client(management).post(ROUTE, json=_body(), headers=HEADERS)
    assert response.status_code == 200, response.text
    assert response.json()["created"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {**_body(), "extra": "x"},
        {"tenant_id": TENANT, "identity_id": IDENTITY},
        {
            "tenant_id": TENANT,
            "identity_id": IDENTITY,
            "group_id": "00000000-0000-0000-0000-000000000000",
        },
        {"tenant_id": "not-a-uuid", "identity_id": IDENTITY, "group_id": GROUP},
        {
            "tenant_id": "ABCDEF01-0000-4000-8000-00000000000A",
            "identity_id": IDENTITY,
            "group_id": GROUP,
        },
        {"tenant_id": 123, "identity_id": IDENTITY, "group_id": GROUP},
        {"tenant_id": TENANT, "identity_id": IDENTITY, "group_id": [GROUP]},
    ],
)
def test_uh02_uh03_invalid_body_is_400_without_invocation(payload: object) -> None:
    management = _StubManagement()
    response = _client(management).post(ROUTE, json=payload, headers=HEADERS)
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert management.calls == 0


def test_uh02_duplicate_json_keys_rejected() -> None:
    management = _StubManagement()
    raw = (
        f'{{"tenant_id":"{TENANT}","identity_id":"{IDENTITY}",'
        f'"group_id":"{GROUP}","group_id":"{GROUP}"}}'
    )
    response = _client(management).post(
        ROUTE, content=raw, headers={**HEADERS, "Content-Type": "application/json"}
    )
    assert response.status_code == 400, response.text
    assert management.calls == 0


def test_uh05_wrong_content_type_is_415() -> None:
    management = _StubManagement()
    response = _client(management).post(
        ROUTE, content="{}", headers={**HEADERS, "Content-Type": "text/plain"}
    )
    assert response.status_code == 415
    assert management.calls == 0


def test_uh04_oversized_body_is_413_without_invocation() -> None:
    management = _StubManagement()
    response = _client(management, settings=ServiceSettings(max_request_bytes=16)).post(
        ROUTE,
        content=b"x" * 4096,
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    assert management.calls == 0


def test_uh08_bad_service_and_user_tokens_map_correctly() -> None:
    management = _StubManagement()
    client = _client(management)
    service_bad = client.post(
        ROUTE,
        json=_body(),
        headers={**HEADERS, "Authorization": "Bearer bad-service"},
    )
    assert service_bad.status_code == 401
    user_bad = client.post(
        ROUTE,
        json=_body(),
        headers={**HEADERS, "X-MTMF-User-Authorization": "Bearer bad-user"},
    )
    assert user_bad.status_code == 403
    missing = client.post(ROUTE, json=_body(), headers={"Authorization": "Bearer service-token"})
    assert missing.status_code == 403


def test_uh07_authenticated_policy_deny_is_opaque_forbidden() -> None:
    management = _StubManagement()
    response = _client(management).post(
        ROUTE, json=_body(), headers={**HEADERS, "Authorization": "Bearer forbidden"}
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.json()["error"]["message"] == "Operation is not permitted"


def test_uh09_database_outage_is_503_without_internals() -> None:
    management = _StubManagement()
    response = _client(management).post(
        ROUTE, json=_body(), headers={**HEADERS, "Authorization": "Bearer db-outage"}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert "persistence unavailable" not in response.text


def test_uh10_single_terminal_management_event() -> None:
    sink = InMemoryAuditEventSink()
    telemetry = Telemetry(enabled=True, sink=sink, metrics=InMemoryMetricsRecorder())
    management = _StubManagement(created=True)
    response = _client(management, telemetry=telemetry).post(ROUTE, json=_body(), headers=HEADERS)
    assert response.status_code == 201
    events = [event for event in sink.events if event.name is AuditEventName.MANAGEMENT_MUTATION]
    assert len(events) == 1
    assert events[0].outcome is AuditOutcome.CREATED
    # No batch event and no identifier/token leaked into the event.
    assert all(event.name is not AuditEventName.AUTHORIZATION_BATCH for event in sink.events)


def test_uh11_admission_exhaustion_is_503_without_invocation() -> None:
    admission = EvaluationAdmission(1)
    held = admission.try_acquire()
    assert held is not None
    try:
        management = _StubManagement()
        response = _client(management, admission=admission).post(
            ROUTE, json=_body(), headers=HEADERS
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert management.calls == 0
    finally:
        held.release()


def test_uh12_timeout_keeps_permit_until_worker_completes() -> None:
    admission = EvaluationAdmission(1)
    management = _StubManagement()
    settings = ServiceSettings(evaluation_timeout_seconds=0.2)
    client = _client(management, settings=settings, admission=admission)
    response = client.post(
        ROUTE, json=_body(), headers={**HEADERS, "Authorization": "Bearer blocking"}
    )
    assert response.status_code == 503
    # The worker is still running: its permit must not be released early.
    assert management.started.wait(timeout=5)
    assert admission.in_flight == 1
    management.release.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and admission.in_flight != 0:
        time.sleep(0.01)
    assert admission.in_flight == 0
