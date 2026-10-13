# PR 19 Live Acceptance Report

**PR:** roadmap PR 19.
**Date:** 2026-10-13.
**Status:** **NOT EXECUTED.**

## What is required

`tests/integration/postgres/test_pr19_live_observability.py` is the real
O-L01..O-L05 acceptance module. It is opt-in (`MTMF_PR19_LIVE=1`) and must
run against the real topology: real Keycloak issuer, real PostgreSQL runtime
role, a real Uvicorn PR 17 service emitting OTel, and the real MTMF-owned
Collector → Prometheus/Jaeger/Loki → Grafana stack. It exercises a
successful batch, rejected authentication, an unavailable-collector contract
check, Grafana provisioning, and backend redaction/cardinality inspection.
Loki is queried through the authenticated Grafana datasource proxy because
Loki intentionally has no published host port.

## Why it was not executed

The real observability stack (Collector, Prometheus, Jaeger, Loki, Grafana)
was not started in this implementation cycle, and no development Grafana
credential was provisioned. The live module is committed and collected, but
the required backend signal journey was not exercised. Per the plan, this is
reported as **NOT EXECUTED**, never PASS.

## How to run it

```sh
MTMF_GRAFANA_ADMIN_PASSWORD=<dev-only> python scripts/mtmf-observability.py up
set -a && . ./.env && set +a
export MTMF_PR19_LIVE=1
export MTMF_PR19_COLLECTOR_ENDPOINT=http://127.0.0.1:24317
export MTMF_GRAFANA_ADMIN_USER=mtmf-admin
uv run --no-sync pytest tests/integration/postgres/test_pr19_live_observability.py --no-cov
```

Three consecutive clean cycles with teardown/recreate of only MTMF-owned test
resources are required before this report can record PASS.

## Not yet validated

- Dashboard PromQL names after the Collector's OTel→Prometheus normalization
  (`mtmf_http_requests_total`, `*_milliseconds_bucket`, etc.) have not been
  checked against live-exported series.
- Loki→Jaeger derived-field correlation has not been exercised end to end.
- No raw-secret scan of exported logs/traces has been run against real
  backends (the unit tests prove the serializer allowlist, but not the live
  pipeline).
