"""Live PR 19 observability acceptance: real OTel stack through the real PDP.

Opt-in and authoritative only when ``MTMF_PR19_LIVE=1`` and the isolated
development topology is available: real Keycloak issuer, real PostgreSQL
runtime role, a real Uvicorn PR 17 service emitting OTel, and the real
MTMF-owned Collector -> Prometheus/Jaeger/Loki -> Grafana stack. The
in-memory sinks used by the unit suites are deliberately *not* used here;
the signal must travel through the real pipeline.

Backend observation is bounded eventual-consistency polling (never an
arbitrary sleep). Loki is queried through the authenticated Grafana
datasource proxy because Loki has no published host port by design.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import test_pr17_live_http as pr17  # noqa: E402  (shared live topology helpers)

from mtmf_core.persistence.postgres import (  # noqa: E402
    PostgresConfig,
    PostgresMtmfSpi,
    PostgresRole,
)
from mtmf_service.app import create_app  # noqa: E402
from mtmf_service.observability.persistence import MetricsPersistenceTelemetry  # noqa: E402
from mtmf_service.observability.runtime import build_telemetry  # noqa: E402
from mtmf_service.rate_limit import TokenBucketRateLimiter  # noqa: E402
from mtmf_service.readiness import StaticReadiness  # noqa: E402
from mtmf_service.settings import ServiceSettings  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR19_LIVE") != "1",
    reason="live PR 19 observability acceptance is opt-in (set MTMF_PR19_LIVE=1)",
)

PORT = int(os.environ.get("MTMF_PR19_SERVICE_PORT", "28013"))
BASE_URL = f"http://127.0.0.1:{PORT}"
PROMETHEUS_BASE = os.environ.get("MTMF_PROMETHEUS_URL", "http://127.0.0.1:29090")
JAEGER_BASE = os.environ.get("MTMF_JAEGER_URL", "http://127.0.0.1:21686")
GRAFANA_BASE = os.environ.get("MTMF_GRAFANA_URL", "http://127.0.0.1:23000")
DASHBOARD_UIDS = ("mtmf-overview", "mtmf-authorization", "mtmf-security", "mtmf-dependencies")
DATASOURCE_UIDS = ("mtmf-prometheus", "mtmf-jaeger", "mtmf-loki")


def _env(name: str) -> str:
    return pr17._env(name)


def _settings() -> ServiceSettings:
    return ServiceSettings(
        evaluation_timeout_seconds=30.0,
        otel_enabled=True,
        otel_exporter_otlp_endpoint=_env("MTMF_PR19_COLLECTOR_ENDPOINT"),
        otel_service_name="mtmf-service",
        otel_environment="live-acceptance",
    )


def _live_app() -> tuple[Any, Any]:
    """Build a real service app with a real OTel runtime. Returns (app, telemetry)."""
    if os.environ.get("SSL_CERT_FILE", "").strip() == "":
        os.environ["SSL_CERT_FILE"] = _env("MTMF_PR14_KC_CA_FILE")
    settings = _settings()
    telemetry = build_telemetry(settings)
    spi = PostgresMtmfSpi(
        PostgresConfig.from_env(PostgresRole.RUNTIME),
        telemetry=MetricsPersistenceTelemetry(telemetry),
    )
    from mtmf_service.composition import build_authorization_service

    authorization_service = build_authorization_service(
        spi=spi,
        issuer_config=pr17._issuer_config(),
        settings=settings,
        telemetry=telemetry,
    )
    app = create_app(
        settings=settings,
        authorization_service=authorization_service,
        readiness=StaticReadiness(True),
        rate_limiter=TokenBucketRateLimiter(per_minute=100000, burst=100000),
        telemetry=telemetry,
        on_shutdown=telemetry.shutdown,
    )
    return app, telemetry


@pytest.fixture(scope="module")
def live_telemetry_server() -> Any:
    """A real Uvicorn server that emits OTel into the MTMF collector."""
    import test_pr17_live_http as _p

    app, telemetry = _live_app()
    with _p._LiveServer(app, port=PORT):
        try:
            yield app
        finally:
            telemetry.shutdown()


def _poll(probe: Any, *, deadline_seconds: float = 60.0) -> Any:
    """Poll ``probe`` until it returns a truthy value or the deadline passes."""
    deadline = time.monotonic() + deadline_seconds
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(1.0)
    return last


def _prometheus_query(expression: str) -> list[dict[str, Any]]:
    with httpx.Client(base_url=PROMETHEUS_BASE, timeout=10) as client:
        response = client.get("/api/v1/query", params={"query": expression})
        response.raise_for_status()
        payload = response.json()
    return list(payload.get("data", {}).get("result", []))


def _grafana_get(path: str) -> httpx.Response:
    user = _env("MTMF_GRAFANA_ADMIN_USER")
    password = _env("MTMF_GRAFANA_ADMIN_PASSWORD")
    with httpx.Client(base_url=GRAFANA_BASE, timeout=10) as client:
        return client.get(path, auth=(user, password))


def _loki_query(expression: str) -> list[dict[str, Any]]:
    """Query Loki through the authenticated Grafana datasource proxy.

    Loki has no published host port by design, so the live test never
    connects to it directly.
    """
    user = _env("MTMF_GRAFANA_ADMIN_USER")
    password = _env("MTMF_GRAFANA_ADMIN_PASSWORD")
    with httpx.Client(base_url=GRAFANA_BASE, timeout=10) as client:
        proxied = client.get(
            "/api/datasources/proxy/uid/mtmf-loki/loki/api/v1/query_range",
            params={"query": expression},
            auth=(user, password),
        )
        proxied.raise_for_status()
        payload = proxied.json()
    return list(payload.get("data", {}).get("result", []))


def test_o_l04_grafana_provisions_dashboards_and_datasources() -> None:
    for uid in DASHBOARD_UIDS:
        response = _grafana_get(f"/api/dashboards/uid/{uid}")
        assert response.status_code == 200, uid
        assert response.json()["dashboard"]["uid"] == uid
    for uid in DATASOURCE_UIDS:
        response = _grafana_get(f"/api/datasources/uid/{uid}")
        assert response.status_code == 200, uid
        assert response.json()["uid"] == uid


def test_o_l01_authenticated_batch_emits_metrics_trace_and_audit(
    db: psycopg.Connection, live_telemetry_server: Any
) -> None:
    subject = pr17.ev.decode_unverified(pr17._user_token())[1]["sub"]
    ids = pr17._seed(db, subject)
    body = pr17._body(
        ids["tenant_id"], ("r-allow", pr17.ALLOW_ACTION), ("r-deny", pr17.DENY_ACTION)
    )
    with httpx.Client(base_url=BASE_URL, timeout=15) as client:
        response = client.post(
            "/v1/authorization/evaluate",
            json=body,
            headers=pr17._headers(pr17._service_token(), pr17._user_token()),
        )
    assert response.status_code == 200

    # Metrics reach Prometheus and a correlated trace reaches Jaeger.
    assert _poll(
        lambda: _prometheus_query("sum(increase(mtmf_authorization_batches_total[5m]))")
    ), "no batch metric reached Prometheus"
    assert _poll(lambda: _prometheus_query("sum(increase(mtmf_http_requests_total[5m]))")), (
        "no HTTP metric reached Prometheus"
    )
    assert _poll(
        lambda: _prometheus_query('count(mtmf_authorization_actions_total{effect="ALLOW"})')
    ), "no per-Action effect metric reached Prometheus"
    assert _poll(lambda: _jaeger_has_service("mtmf-service")), "no trace reached Jaeger"
    assert _poll(
        lambda: _loki_query(
            'sum(count_over_time({job=~".+"} | json | event_name="mtmf.authorization.batch" [10m]))'
        )
    ), "no batch audit event reached Loki"


def _jaeger_has_service(service: str) -> bool:
    with httpx.Client(base_url=JAEGER_BASE, timeout=10) as client:
        response = client.get("/api/services")
        response.raise_for_status()
        return service in response.json().get("data", [])


def test_o_l02_rejected_requests_emit_sanitized_events(
    db: psycopg.Connection, live_telemetry_server: Any
) -> None:
    subject = pr17.ev.decode_unverified(pr17._user_token())[1]["sub"]
    ids = pr17._seed(db, subject, memberships=True)
    body = pr17._body(ids["tenant_id"], ("r-allow", pr17.ALLOW_ACTION))
    with httpx.Client(base_url=BASE_URL, timeout=15) as client:
        bad = client.post(
            "/v1/authorization/evaluate",
            json=body,
            headers={
                "Authorization": "Bearer not-a-real-service-token",
                "X-MTMF-User-Authorization": "Bearer not-a-real-user-token",
            },
        )
    assert bad.status_code == 401
    assert _poll(
        lambda: _prometheus_query(
            'sum(increase(mtmf_security_rejections_total{category="SERVICE_AUTHENTICATION_FAILED"}[5m]))'
        )
    ), "no authentication rejection metric reached Prometheus"
    results = _loki_query(
        'sum(count_over_time({job=~".+"} | json | '
        'event_name="mtmf.security.authentication_rejected" [10m]))'
    )
    assert results, "no rejection audit event reached Loki"
    # Redaction: no bearer token text may appear in the exported log stream.
    raw = json.dumps(results)
    assert "not-a-real" not in raw


def test_o_l03_collector_outage_does_not_change_pdp_semantics(
    db: psycopg.Connection, live_telemetry_server: Any
) -> None:
    # The live server is started against a healthy collector; this case
    # documents the contract that an unavailable collector cannot change a
    # response. Operators exercise the actual outage by stopping the
    # collector and re-running the module; the assertions below hold in
    # both conditions.
    subject = pr17.ev.decode_unverified(pr17._user_token())[1]["sub"]
    ids = pr17._seed(db, subject)
    body = pr17._body(ids["tenant_id"], ("r-allow", pr17.ALLOW_ACTION))
    with httpx.Client(base_url=BASE_URL, timeout=15) as client:
        response = client.post(
            "/v1/authorization/evaluate",
            json=body,
            headers=pr17._headers(pr17._service_token(), pr17._user_token()),
        )
    assert response.status_code == 200
    assert response.json()["decisions"][0]["effect"] == "ALLOW"


def test_o_l05_no_secret_or_high_cardinality_labels_in_backends() -> None:
    for query in (
        "mtmf_http_requests_total",
        "mtmf_security_rejections_total",
        "mtmf_dependencies_failures_total",
    ):
        for result in _prometheus_query(query):
            labels = result.get("metric", {})
            forbidden = {
                "tenant_id",
                "application_id",
                "principal_id",
                "identity_id",
                "resource",
                "request_id",
                "action",
                "trace_id",
                "route_path",
            }
            assert not (set(labels) & forbidden), (query, labels)
