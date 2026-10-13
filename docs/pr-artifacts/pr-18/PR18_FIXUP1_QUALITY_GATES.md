# PR 18 Fixup 1 — Quality Gates

All gates were executed on the fixup working tip after the implementation
change, with no subsequent code edits. Secrets and credentials are absent
from the captured logs.

Start point: PR 18 implementation tip `5291ed7a2366f6e931eec8d34f8ed2a63fbba100`.

## 1. Results

| # | Gate | Exact command | Result | Exit |
| --- | --- | --- | --- | --- |
| 1 | Locked sync | `uv sync --locked` | 107 packages resolved; `mtmf-permission-engine` uninstalled by sync (reinstalled by gate 3) | 0 |
| 2 | Focused client unit | `uv run --no-sync pytest -q tests/unit/client/ --no-cov` | **148 passed** | 0 |
| 3 | Rust/native | `./build.sh --rust` | cargo fmt/clippy/test, `maturin develop`, native probe `engine_version=0.1.0`, focused native tests, clean wheel verify, benchmark smoke | 0 |
| 4 | Quality | `./build.sh --qa` | Ruff format+lint, strict Mypy, **2301 passed**, coverage **91.35%** (gate ≥85%) | 0 |
| 5 | Security | `./build.sh --sec` | Bandit 0 Medium / 0 High; Semgrep 0 findings (0 blocking) | 0 |
| 6 | PostgreSQL integration | `./build.sh --integration` | **564 passed, 81 skipped** (opt-in live modules collected and skipped) | 0 |

Gate order note: `--rust` was run before `--qa` so the native module was
reinstalled after `uv sync --locked` removed it; `--qa` therefore ran the
complete unit suite including the native-backed cases. No gate content was
weakened.

## 2. Coverage delta

| State | Unit result | Coverage |
| --- | --- | --- |
| PR 18 implementation tip | 2275 passed | 91.34% |
| Fixup 1 | 2301 passed | 91.35% |

The 26 new FX-U cases (plus the migrated cases) raised the total passed count
by 26 with no coverage regression.

## 3. Live feature gate

The full live module (`tests/integration/postgres/test_pr18_live_client.py`,
`MTMF_PR18_LIVE=1`) passed **16/16 on three consecutive runs, retries = 0**;
see `PR18_FIXUP1_CL_I16_LIVE_ACCEPTANCE.md`. The standard
`./build.sh --integration` legitimately skips this opt-in module and is not
a substitute for those runs.

## 4. Failures

None. No gate required a rerun to hide a first-attempt failure, and no
assertion, configuration, or security check was suppressed.
