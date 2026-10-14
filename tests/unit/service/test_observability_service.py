"""End-to-end service audit/metric emission through the real ASGI boundary.

These tests use the real PR 14 actor composition, PR 9 resolver, PR 16
batch evaluator and PR 17 HTTP surface with an in-memory audit sink and
metric recorder. They prove exactly one terminal event per request, no
per-Action fanout, no secret leakage, and that a telemetry fault cannot
change an authorization response (O-U01..O-U07, O-U12, O-U13).
"""

from __future__ import annotations

import json

from conftest import (
    ALLOW_ACTION,
    DENY_ACTION,
    UNKNOWN_ACTION,
    ExplodingBatchAuthorizer,
    VerifierSpy,
    action_body,
    auth_headers,
    seeded_harness,
)

from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.domain.lifecycle import SubscriptionLifecycle
from mtmf_service.observability import (
    AuditEventName,
    AuditOutcome,
    AuditReason,
    InMemoryAuditEventSink,
    InMemoryMetricsRecorder,
    NoopMetricsRecorder,
    Telemetry,
)
from mtmf_service.rate_limit import TokenBucketRateLimiter


def _telemetry() -> tuple[Telemetry, InMemoryAuditEventSink, InMemoryMetricsRecorder]:
    sink = InMemoryAuditEventSink()
    metrics = InMemoryMetricsRecorder()
    return Telemetry(enabled=True, sink=sink, metrics=metrics), sink, metrics


def _post(harness, body, *, headers=None, content=None, content_type="application/json"):
    if content is not None or content_type != "application/json":
        raw = content if content is not None else json.dumps(body).encode()
        return harness.client.post(
            "/v1/authorization/evaluate",
            content=raw,
            headers={"Content-Type": content_type, **(headers or auth_headers())},
        )
    return harness.client.post(
        "/v1/authorization/evaluate", json=body, headers=headers or auth_headers()
    )


def test_o_u01_success_batch_emits_exactly_one_event_and_http_metric() -> None:
    telemetry, sink, metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(
        ("r1", ALLOW_ACTION), ("r2", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id)
    )
    response = _post(harness, body)
    assert response.status_code == 200
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.name is AuditEventName.AUTHORIZATION_BATCH
    assert event.outcome is AuditOutcome.ALLOW
    assert event.action_count == 2
    assert event.allow_count == 2
    assert event.deny_count == 0
    http = [name for name, _attrs, _value in metrics.counters if name == "mtmf.http.requests"]
    assert http == ["mtmf.http.requests"]


def test_o_u02_mixed_batch_outcome_and_counts() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(
        ("r1", ALLOW_ACTION), ("r2", DENY_ACTION), tenant_id=str(harness.world.tenant.id)
    )
    assert _post(harness, body).status_code == 200
    event = sink.events[0]
    assert event.outcome is AuditOutcome.MIXED
    assert (event.allow_count, event.deny_count) == (1, 1)


def test_o_u02_unknown_action_is_deny_in_a_batch() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(("r1", UNKNOWN_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200
    assert sink.events[0].outcome is AuditOutcome.DENY
    assert sink.events[0].deny_count == 1


def test_o_u05_invalid_service_token_emits_one_rejection_and_no_batch() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    response = _post(
        harness,
        body,
        headers={"Authorization": "Bearer nope", "X-MTMF-User-Authorization": "Bearer user"},
    )
    assert response.status_code == 401
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.name is AuditEventName.AUTHENTICATION_REJECTED
    assert event.reason_code is AuditReason.SERVICE_AUTHENTICATION_FAILED
    rendered = json.dumps(event.to_attributes())
    assert "nope" not in rendered
    assert response.json()["error"]["request_id"] == event.request_correlation_id


def test_o_u05_expired_user_token_is_user_rejection() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(
        telemetry=telemetry,
        user_verifier=VerifierSpy(
            {},
            errors={"user": AuthenticationError(AuthenticationFailure.EXPIRED_TOKEN)},
        ),
    )
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    response = _post(harness, body)
    assert response.status_code == 403
    assert sink.events[0].name is AuditEventName.AUTHENTICATION_REJECTED
    assert sink.events[0].reason_code is AuditReason.USER_AUTHENTICATION_FAILED


def test_o_u06_ineligible_subscription_is_not_a_policy_deny() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(
        telemetry=telemetry,
        world_kwargs={"subscription_lifecycle": SubscriptionLifecycle.SUSPENDED},
    )
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    response = _post(harness, body)
    assert response.status_code == 403
    event = sink.events[0]
    assert event.name is AuditEventName.SUBSCRIPTION_REJECTED
    assert event.reason_code is AuditReason.SUBSCRIPTION_INELIGIBLE
    assert event.outcome is AuditOutcome.REJECTED


def test_o_u04_malformed_body_is_a_request_rejection() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    response = _post(harness, None, content=b"{not json")
    assert response.status_code == 400
    assert sink.events[0].name is AuditEventName.REQUEST_REJECTED
    assert sink.events[0].reason_code is AuditReason.INVALID_REQUEST


def test_o_u04_rate_limit_is_a_request_rejection() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(
        telemetry=telemetry,
        rate_limiter=TokenBucketRateLimiter(per_minute=1, burst=1),
    )
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200
    assert _post(harness, body).status_code == 429
    assert sink.events[-1].name is AuditEventName.REQUEST_REJECTED
    assert sink.events[-1].reason_code is AuditReason.RATE_LIMITED


def test_o_u07_internal_error_emits_error_event_only() -> None:
    telemetry, sink, _metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry, batch_authorizer=ExplodingBatchAuthorizer())
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    response = _post(harness, body)
    assert response.status_code == 500
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.name is AuditEventName.AUTHORIZATION_ERROR
    assert event.outcome is AuditOutcome.ERROR
    assert event.reason_code is AuditReason.INTERNAL_ERROR
    assert event.action_count is None


def test_o_u12_disabled_telemetry_changes_nothing() -> None:
    harness = seeded_harness(telemetry=Telemetry.disabled())
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200


class _RaisingSink:
    def emit(self, event: object) -> None:
        raise RuntimeError("sink exploded")


def test_o_u13_sink_failure_cannot_change_the_response() -> None:
    telemetry = Telemetry(
        enabled=True,
        sink=_RaisingSink(),
        metrics=NoopMetricsRecorder(),  # type: ignore[arg-type]
    )
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200
    assert telemetry.failure_count >= 1


def test_metric_attributes_are_all_bounded() -> None:
    telemetry, _sink, metrics = _telemetry()
    harness = seeded_harness(telemetry=telemetry)
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200
    allowed_keys = {
        "route",
        "method",
        "status_class",
        "outcome",
        "effect",
        "operation",
        "dependency",
        "category",
        "signal",
    }
    for _name, attributes, _value in (*metrics.counters, *metrics.histograms):
        assert set(attributes) <= allowed_keys
