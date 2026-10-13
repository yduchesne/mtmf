# PR 19 Gate and Test Evidence

**PR:** roadmap PR 19.
**Date:** 2026-10-13.
**Base commit:** `ada8c5e`.
**Working branch:** `dev/observability`.

## Canonical gates

| Command | Result | Detail |
|---|---|---|
| `uv sync --locked` | PASS | 109 packages; builds `mtmf-client`/`mtmf-service` |
| `./build.sh --qa` | **PASS** | Ruff format check, Ruff lint, strict Mypy (140 files), unit tests `2374 passed`; total coverage **90.82%** (gate ≥ 85%) |
| `./build.sh --sec` | **PASS** | Bandit: 0 Medium / 0 High; Semgrep: 0 findings over 206 tracked files |
| `./build.sh --rust` | **PASS** | cargo fmt/clippy/test, maturin develop, installed-native probe, focused native/boundary/differential/compiled-policy tests, clean wheel verification, benchmark smoke |
| `./build.sh --integration` | **PASS** | `564 passed, 81 skipped` (the 81 skipped are the opt-in PR 14/17/17-B/17-C/18/19 live suites requiring `MTMF_PR*_LIVE=1`) |

The integration run required sourcing `.env` (`set -a && . ./.env && set +a`)
so the canonical `MTMF_*` role-scoped configuration was present; the tests
fail closed without it.

## New deterministic test coverage

| File | Cases |
|---|---|
| `tests/unit/service/test_observability_events.py` | event shape/outcome, count consistency, UTC/trace/correlation validation, allowlist + forbidden-key rejection, NaN/negative duration, in-memory/OTel sinks |
| `tests/unit/service/test_observability_metrics.py` | bounded-enum metric validation, high-cardinality rejection, fail-safe façade (`O-U10`, `O-U13`, `O-U14`), disabled mode, repeated-construction isolation, threaded emission |
| `tests/unit/service/test_observability_runtime.py` | disabled-by-default, strict settings validation, enabled instance-scoped runtime + shutdown, `from_env` |
| `tests/unit/service/test_observability_service.py` | exactly one terminal event per request; batch ALLOW/DENY/MIXED counts; auth/context/subscription/request rejections; error event; disabled mode; sink-failure containment; bounded metric attributes (`O-U01`–`O-U07`, `O-U12`, `O-U13`) |
| `tests/unit/service/test_observability_classification.py` | typed failure→closed-reason mapping; admission override; never text-derived |
| `tests/unit/persistence/test_persistence_instrumentation.py` | read/write classification; no-op protocol; metrics adapter mapping and unknown-value drop |
| `tests/unit/client/test_client_observability.py` | no-op default, span/status recording, token-failure categories, snapshot rejection reasons, OTel adapter bounded labels (`O-U16`, `O-U17`) |
| `tests/unit/client/test_client_package_isolation.py` (extended) | `mtmf_client.observability` imports no OTel; mandatory deps stay HTTP-only; `observability` extra declared |

## Live and benchmark status

- Real-stack live acceptance `O-L01`–`O-L05`: **NOT EXECUTED** (see
  `PR19_LIVE_ACCEPTANCE_REPORT.md`).
- Performance comparison `O-P01`: **NOT EXECUTED** (see
  `PR19_PERFORMANCE_REPORT.md`).

## Notes

- `uv sync` removed the private native module, so it was reinstalled with
  `maturin develop` before the unit and Rust gates; this is expected per the
  `build.sh` comment.
- The only test warnings are pre-existing (`starlette.testclient`/`httpx`
  and a PyJWT HMAC short-key warning in unrelated PR 14 tests).
