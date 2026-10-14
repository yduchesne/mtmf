# PR 19 Baseline and Phase 0 Reconciliation Report

**PR:** roadmap PR 19 (Observability and security/audit hardening), not GitHub pull request #19.
**Date:** 2026-10-13.
**Branch:** `dev/observability`.
**Base commit:** `ada8c5e25d07ef269d2e257d1813908b6a939feb` (`ada8c5e`, merge of PR #56).
**Artifact directory:** `docs/pr-artifacts/pr-19/`.

## 1. Phase 0 prerequisites

| Check | Result |
|---|---|
| Fresh `origin/main` fetched | Yes |
| PR #56 (hybrid audit/observability architecture) merged | **Yes** — `ada8c5e`; `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` present |
| Working tree clean before implementation | Yes |
| `docs/pr-artifacts/pr-19/` created | Yes |

The branch had no divergent commits; fast-forwarded `9b8a4c5 -> ada8c5e`.

## 2. Repository facts recorded

| Item | Value |
|---|---|
| Git SHA at baseline | `ada8c5e25d07ef269d2e257d1813908b6a939feb` |
| Python | 3.14.7 (uv-managed) |
| `uv` | 0.12.17 |
| Podman | 4.9.3 (socket active) |
| Alembic migration heads | `0001`–`0011`; current head `0011_authentication_bindings` |
| `uv.lock` | Locked, 109 packages after the PR 19 additions |
| Pre-existing OTel in lock | `opentelemetry-*` 1.37.0 / `0.58b0` transitively via the `semgrep` dev dependency |
| Pre-existing observability code | None in `packages/` (no Collector/Prometheus/Jaeger/Loki/Grafana config) |
| Existing audit tables | `mtmf.membership_removal_audit` (v002), `mtmf.stewardship_audit` (v008) |

## 3. Phase 0 source-inspection inventory

Searched the repository for `opentelemetry`, `prometheus`, `jaeger`, `loki`,
`grafana`, `audit`, `instrument`, `trace_id`, `logging`, `SECURITY DEFINER`,
and security-mutation stored functions.

| Capability | Classification at baseline |
|---|---|
| Structured OTel audit events | NOT STARTED |
| OTel metrics/traces in service/client | NOT STARTED |
| OTel dependencies in service/client manifests | NOT STARTED (only transitive via Semgrep) |
| MTMF-owned telemetry stack / dashboards | NOT STARTED |
| Existing atomic membership-removal audit | DONE (v002; preserved) |
| Existing atomic stewardship audit | DONE (v008; preserved) |
| Broader mutation audit coverage | PARTIAL — see `PR19_SECURITY_AUDIT_INVENTORY.md` |
| API error correlation id (`app._trace_id`) | DONE — a public error token, deliberately distinct from W3C trace ids |
| `tests/integration/postgres/test_pr17_live_http.py`, `test_pr18_live_client.py` | DONE — reusable live topology harness |

## 4. Baseline gate execution

| Command | Environment | Result |
|---|---|---|
| `uv sync --locked` | host | PASS |
| `./build.sh --qa` | host | PASS (pre-change, as reported by the committed tree) |
| `./build.sh --sec` | host | PASS |
| `./build.sh --rust` | host (cargo present) | PASS |
| `./build.sh --integration` | host, `.env` sourced, MTMF PostgreSQL/Keycloak/service containers running | PASS (564 passed, 81 opt-in live skipped) |

The running containers at baseline were the MTMF-owned `mtmf_postgres_1`,
`mtmf_keycloak_1`, `mtmf_forwarder_1`, and `mtmf_service_1`. No foreign
project resource was inspected or touched.

## 5. Notes and limitations

- The opt-in PR 17/18 live modules require `MTMF_PR17_LIVE=1` /
  `MTMF_PR18_LIVE=1` and the development PKI; they are excluded from the
  default `--integration` run and remained skipped.
- The observability stack was not yet running; the real-stack live
  acceptance (`MTMF_PR19_LIVE=1`) is **NOT EXECUTED** in this PR's
  implementation cycle. See `PR19_LIVE_ACCEPTANCE_REPORT.md`.
- The baseline performance comparison is **NOT EXECUTED**. See
  `PR19_PERFORMANCE_REPORT.md`.
