# PR 19 Live Acceptance Report

**PR:** roadmap PR 19.
**Date:** 2026-10-14.
**Branch:** `dev/observability` (implementation baseline `fff7016` + acceptance fixes).
**Status:** **PASS (Gate A executed).**

## 1. Topology and environment

Real local stack, no mocks on the PDP path:

| Component | Value |
|---|---|
| MTMF service | in-process real Uvicorn ASGI app, `tests/integration/postgres/test_pr19_live_observability.py` |
| Issuer | real Keycloak `26.8.0-1`, realm `mtmf-dev`, `https://keycloak.mtmf.test:28443` |
| Database | real PostgreSQL 18 (`127.0.0.1:25432`), restricted `mtmf_runtime` login |
| Collector | `otel/opentelemetry-collector-contrib:0.115.1`, host OTLP `127.0.0.1:24317`, health `127.0.0.1:24318` |
| Prometheus | `prom/prometheus:v3.1.0`, `127.0.0.1:29090` |
| Jaeger | `jaegertracing/all-in-one:1.65.0`, UI `127.0.0.1:21686` |
| Loki | `grafana/loki:3.3.2`, internal-only (`3100`), no host port |
| Grafana | `grafana/grafana:11.4.0`, `127.0.0.1:23000`, fixed datasource UIDs `mtmf-prometheus`/`mtmf-jaeger`/`mtmf-loki` |

Invocation (credentials from `.env` plus a session-only live env file; never committed):

```sh
set -a && . ./.env && . /tmp/mtmf-pr19-live.env && set +a   # MTMF_PR19_LIVE=1 etc.
export SSL_CERT_FILE=$MTMF_PR14_KC_CA_FILE
uv run --no-sync pytest tests/integration/postgres/test_pr19_live_observability.py --no-cov
```

## 2. O-L01–O-L05 results — three consecutive clean cycles

| Test | Cycle 1 | Cycle 2 | Cycle 3 |
|---|---|---|---|
| `test_o_l04_grafana_provisions_dashboards_and_datasources` | PASSED | PASSED | PASSED |
| `test_o_l01_authenticated_batch_emits_metrics_trace_and_audit` | PASSED | PASSED | PASSED |
| `test_o_l02_rejected_requests_emit_sanitized_events` | PASSED | PASSED | PASSED |
| `test_o_l03_collector_outage_does_not_change_pdp_semantics` | PASSED | PASSED | PASSED |
| `test_o_l05_no_secret_or_high_cardinality_labels_in_backends` | PASSED | PASSED | PASSED |

Totals: `5 passed` per cycle (63 s / 40 s / 56 s). Cyclic teardown resets only the
MTMF-owned PostgreSQL `mtmf` schema per test.

Assertions exercised (from the committed suite):

- **O-L01** — an authenticated mixed batch (`ALLOW` + `DENY`) returns `200`; a batch
  metric and an HTTP metric reach Prometheus; per-Action `effect` counters reach
  Prometheus; a `mtmf-service` trace reaches Jaeger; a `mtmf.authorization.batch`
  event reaches Loki.
- **O-L02** — an invalid service credential yields `401`; `mtmf.security.rejections`
  with category `SERVICE_AUTHENTICATION_FAILED` reaches Prometheus; a
  `mtmf.security.authentication_rejected` event reaches Loki with no bearer text.
- **O-L03** — with the real Collector **stopped**, three authorization batches still
  return `200`/`ALLOW`; after **restart**, fresh Prometheus samples, a Jaeger trace
  and Loki events arrive (recovery visible), all measured after the restart instant.
- **O-L04** — all four dashboard UIDs and three datasource UIDs are served by Grafana.
- **O-L05** — no forbidden high-cardinality label keys (`tenant_id`, `application_id`,
  `principal_id`, `identity_id`, `resource`, `request_id`, `action`, `trace_id`,
  `route_path`) appear on the exported metrics.

## 3. Independent verification (beyond the test assertions)

- **Metric names.** 17 `mtmf_*` series are live in Prometheus, e.g.
  `mtmf_http_requests_total`, `mtmf_authorization_batches_total`,
  `mtmf_authorization_actions_total`, `mtmf_authorization_batch_duration_milliseconds_bucket`.
- **Trace correlation.** A Loki batch stream's `trace_id`
  (`644c5d89da67a173b6a9cb8f9c451972`) resolved to a Jaeger trace with 4 spans
  (`evidence/trace_correlation.txt`).
- **Redaction.** A scan of 62 MTMF Loki streams and 20 Jaeger traces found no
  Keycloak admin password, user password, Grafana password, client secret, or
  `eyJ`-prefixed JWT material. (`'authorization'` matches only the
  `mtmf.authorization.batch` event name, not a header.)
  See `evidence/redaction_and_queries.txt`.
- **Dashboards.** All 35 panel targets were executed against the real backends;
  zero execution errors; every referenced `mtmf_*`/`otelcol_*` series exists after
  a controlled failure (see next bullet). See `evidence/dashboard_validation_final.txt`.
- **Dependency failure.** A real PostgreSQL outage produced `503
  DEPENDENCY_UNAVAILABLE` and the metric
  `mtmf_dependencies_failures_total{dependency="postgres",category="unavailable"}=1`;
  PostgreSQL was restored. See `evidence/dependency_failure.txt`.
- **Loki structure.** Only `service_name` is a Loki index label; `event_name`,
  `outcome`, counts and correlation/trace ids are structured metadata, so the audit
  stream is not high-cardinality at the index.

## 4. Defects found and fixed during Gate A

All within the approved PR 19 scope; no authorization contract changed.

1. **Log resource dropped (product defect).** `OtelAuditEventSink` built an SDK
   `LogRecord` directly, bypassing the provider resource, so Loki showed
   `unknown_service`. The sink now receives and attaches the provider `Resource`.
2. **Non-idempotent shutdown (product defect).** ASGI lifespan shutdown plus an
   owner shutdown double-shut the SDK providers. `Telemetry.shutdown()` is now
   idempotent.
3. **Unbounded gRPC reconnect backoff (product defect).** Recovery after a Collector
   restart could wait minutes. The OTLP gRPC exporters now use a bounded
   reconnect backoff (`initial 500 ms`, `max 5 s`); delivery semantics are unchanged.
4. **Dashboard audit-log panel (config defect).** The panel used a Prometheus
   datasource with a broken LogQL query. It now uses the `mtmf-loki` datasource and
   `{service_name=~".+"} | event_name="mtmf.authorization.batch"`.
5. **Collector healthcheck (infra defect).** The Collector image is distroless and
   podman-compose 1.0.6 wraps even exec-form healthchecks in `/bin/sh -c`. The
   broken container healthcheck was replaced by publishing the Collector's built-in
   `health_check` extension endpoint (`127.0.0.1:24318`).
6. **Companion script required Keycloak secrets (config defect).**
   `scripts/mtmf-observability.py` no longer includes `compose.dev.yaml`, so the
   observability stack starts without application-stack secrets.
7. **Harness re-seeding (test defect).** O-L03 re-seeded the schema repeatedly,
   creating ambiguous active credential/subject bindings. It now seeds once and
   reuses the tenant. Recovery is proven from fresh backend evidence rather than a
   flaky `increase()` on low-frequency counters.

## 5. Known limitations

- The `mtmf_dependencies_failures_total` and telemetry-export-failure counters are
  failure-conditioned and therefore appear only when the corresponding event occurs;
  the dependency counter was proven with a controlled outage.
- `mtmf.telemetry.dropped.events` is intentionally never emitted (the SDK exposes no
  reliable drop counter), so it is not referenced by any dashboard; the Collector's
  own queue/send-failure self-metrics are used instead.
- This is a development stack: Grafana/Loki credentials and default retention are
  development controls, not production security or compliance controls.
