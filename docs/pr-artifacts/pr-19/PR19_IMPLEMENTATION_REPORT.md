# PR 19 Implementation Report

**PR:** roadmap PR 19 (Observability and security/audit hardening).
**Date:** 2026-10-13.
**Base commit:** `ada8c5e`.
**Architecture authority:** `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` (PR #56, merged).

## 1. What was implemented

### Service observability package

`packages/mtmf-service/src/mtmf_service/observability/`:

- `events.py` — immutable `AuditEvent` taxonomy with closed names/outcomes/
  reasons, strict validation (UTC timestamp, bounded correlation id, OTel
  trace/span format, finite nonnegative duration, count/outcome consistency),
  allowlist serialization, forbidden/unknown-key rejection on
  `from_mapping`, and `Noop`/`InMemory`/`Otel` sinks.
- `metrics.py` — closed-enum metric recorders (`OtelMetricsRecorder`,
  `InMemoryMetricsRecorder`, `NoopMetricsRecorder`) for the frozen metric
  names/dimensions; every dimension is validated before recording, so an
  arbitrary route/identifier/exception string can never become a label.
- `spans.py` — closed span-name set and a `span_context` helper.
- `classification.py` — typed failure → closed reason taxonomy (never derived
  from exception text); admission gets its own reason via an explicit
  `PublicError.audit_reason` override.
- `runtime.py` — `Telemetry` façade (all emission methods are
  exception-contained) and `build_telemetry(settings)` constructing
  **instance-scoped** Tracer/Meter/Logger providers with bounded batch
  processors and a finite-deadline shutdown. Disabled by default.
- `persistence.py` — `MetricsPersistenceTelemetry` adapter.

### Wiring

- `settings.py` — strict `MTMF_OTEL_*` configuration with bounded ranges and
  fail-closed validation.
- `app.py` — one server-owned correlation id per request, one terminal audit
  event (batch / rejection / error), one HTTP metric, `mtmf.http.evaluate`
  SERVER span; the v1 error envelope is unchanged and its `request_id` is the
  same server-owned correlation id.
- `evaluation.py` — phase spans (`mtmf.actor.verify`, `mtmf.roles.resolve`,
  `mtmf.authorization.batch`) and batch metrics recorded only after strict
  response conformance validation.
- `composition.py` / `asgi.py` — telemetry wired at the composition seam and
  lifecycle shutdown; the PostgreSQL SPI receives the persistence adapter.
- `errors.py` — optional `audit_reason` override (plain string; no telemetry
  dependency in the error module).

### Core persistence seam

- `mtmf_core/persistence/instrumentation.py` — provider-neutral
  `PersistenceTelemetry` protocol + no-op.
- `PostgresUnitOfWork` reports bounded `read`/`write`/`transaction`
  observations; it imports no SDK or backend. `PostgresMtmfSpi` accepts the
  optional seam.

### Client

- `mtmf_client/observability.py` — `ClientInstrumentation` protocol,
  no-op default, and an `OtelClientInstrumentation` adapter over
  consumer-owned tracer/meter objects. No OTel import at module load.
- `client.py` / `credentials.py` / `transport.py` — optional injected
  instrumentation for evaluate/token/HTTP/snapshot observations; fail-closed
  behavior, retry, and TTL semantics are unchanged.
- `pyproject.toml` — optional `observability` extra; mandatory deps stay
  `mtmf-api` + `httpx`.

### Infrastructure

- `compose.observability.yaml` — opt-in MTMF-owned overlay with Collector,
  Prometheus, Jaeger, Loki and Grafana; prefix-2 loopback ports; no fixed
  container names; bounded volumes; Loki internal-only.
- `observability/` — Collector, Prometheus, Loki, Grafana provisioning and
  four dashboards-as-code with stable UIDs.
- `scripts/mtmf-observability.py` — `up`/`status`/`down` for only the
  observability services (no broad `down --volumes`).

### Database audit

- Inventory and disposition only. No new audit table, migration, or
  unverified actor attribution: see `PR19_SECURITY_AUDIT_INVENTORY.md` and
  `PR19_STOP_REPORT.md`.

## 1a. Acceptance-run fixes (2026-10-14)

The live/performance acceptance run found and fixed within-scope defects:

- `OtelAuditEventSink` now attaches the provider `Resource` (log records
  previously exported `unknown_service` to Loki).
- `Telemetry.shutdown()` is idempotent (ASGI lifespan + owner shutdown).
- OTLP gRPC exporters use a bounded reconnect backoff (500 ms initial / 5 s max)
  for deterministic recovery after a Collector restart; delivery semantics
  unchanged.
- `scripts/mtmf-observability.py` no longer includes `compose.dev.yaml`
  (observability no longer requires application-stack secrets).
- `compose.observability.yaml` publishes the Collector `health_check` endpoint
  (`127.0.0.1:24318`) because the distroless image cannot run a shell healthcheck
  under podman-compose 1.0.6.
- The audit-log Grafana panel uses the `mtmf-loki` datasource and the verified
  LogQL; telemetry drop/queue panels use the Collector's real self-metrics.
- The live harness seeds once per test and proves recovery from fresh backend
  evidence.

## 2. Deliberate non-changes

No change to `mtmf-api`/v1 schema, authorization semantics, policy
evaluator/resolver, Rust crate, issuer trust configuration, historical
migrations, or the existing membership/stewardship audit tables.

## 3. Known limitations

- Live real-stack acceptance and the performance comparison are not executed.
- Dashboard PromQL names against live-exported series are unvalidated.
- The persistence read/write classification is a bounded internal
  stored-function-name heuristic, not an SDK-visible write flag; it never
  records query text, table names, or arguments.
