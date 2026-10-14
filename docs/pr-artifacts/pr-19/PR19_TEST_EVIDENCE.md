# PR 19 Gate and Test Evidence

**PR:** roadmap PR 19.
**Date:** 2026-10-14.
**Branch:** `dev/observability` (implementation baseline `fff7016` + acceptance fixes).

## Canonical gates (final)

| Command | Result | Detail |
|---|---|---|
| `uv sync --locked` | PASS | workspace builds |
| `./build.sh --qa` | **PASS** | Ruff format check, Ruff lint, strict Mypy (140 files), `2374 passed`; total coverage **90.80%** (gate ≥ 85%) |
| `./build.sh --sec` | **PASS** | Bandit 0 Medium / 0 High; Semgrep 0 findings |
| `./build.sh --rust` | **PASS** | cargo fmt/clippy/test, maturin, native probe, focused tests (392), clean wheel, benchmark smoke |
| `./build.sh --integration` | **PASS** | `564 passed, 86 skipped` (skips are opt-in PR 14/17/18/19 live suites) |

## Live acceptance (Gate A)

- `MTMF_PR19_LIVE=1 ... test_pr19_live_observability.py` — **O-L01–O-L05 PASS × 3 consecutive cycles**.
- Backend verification: Prometheus series, Jaeger trace correlation, Loki audit
  events, Grafana provisioning, redaction scan, controlled dependency failure.
- Details: `PR19_LIVE_ACCEPTANCE_REPORT.md`; raw evidence under `evidence/`.

## Performance acceptance (Gate B)

- Baseline `ada8c5e`, PR 19 `disabled`/`healthy`/`unavailable`.
- Drift-controlled interleaved A/B: **0% throughput loss, +4.8% p99** versus the
  no-instrumentation control (within targets).
- Details: `PR19_PERFORMANCE_REPORT.md`; raw results under `evidence/`.

## New deterministic test coverage (unchanged from implementation)

`tests/unit/service/test_observability_{events,metrics,runtime,service,classification}.py`,
`tests/unit/persistence/test_persistence_instrumentation.py`,
`tests/unit/client/test_client_observability.py`, and the extended
`tests/unit/client/test_client_package_isolation.py`. The live module is
`tests/integration/postgres/test_pr19_live_observability.py`.

## Notes

- Only pre-existing warnings remain (`starlette.testclient`/`httpx`, a PyJWT
  short-HMAC-key warning in unrelated PR 14 tests).
- `uv sync` removes the private native module; it is reinstalled by the
  canonical `--rust` gate (`build.sh` documents this).
