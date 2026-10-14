# PR19A_BASELINE_REPORT

**PR:** roadmap PR 19A — verified-provenance mutation audit (proposed; see `docs/ROADMAP_V01.md`).
**Execution date (UTC):** 2026-10-14.
**Executing branch:** `dev/mutation-audit`.
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5` ("Merge pull request #57 from yduchesne/dev/observability").
**PR 19 dependency:** acceptance commit `3a9898a` ("PR 19 acceptance: live observability and performance gates") is an ancestor of the base commit (`git merge-base --is-ancestor 3a9898a HEAD` → true).
**Artifact directory:** `docs/pr-artifacts/pr-19a/`.

## 1. Environment

| Item | Value |
|---|---|
| Host OS | Linux `MSI` 6.18.33.2-microsoft-standard-WSL2 (`x86_64`) |
| System Python | 3.12.3 |
| uv | 0.12.17 |
| uv-managed interpreter | CPython 3.14.7 |
| PostgreSQL | 18.6 (Debian 18.6-1.pgdg13+2) in `mtmf_postgres_1`, host publication `127.0.0.1:25432` |
| Podman | 4.9.3 |
| MTMF stack | `mtmf_postgres_1`, `mtmf_keycloak_1`, `mtmf_forwarder_1`, `mtmf_service_1`, plus the PR 19 observability overlay (`collector`, `jaeger`, `loki`, `prometheus`, `grafana`) already running from PR 19 acceptance |
| Database identity | MTMF-owned database only; administrator/migrator/runtime role-scoped configuration sourced from the repository `.env` |

No destructive database reset, container removal, volume deletion, or cross-project resource mutation was performed. Only the MTMF-owned database was exercised.

## 2. Migration head and schema facts

- Alembic head from `mtmf.alembic_version`: **`0011`** (`0011_authentication_bindings`).
- `git` inspection of `migrations/versions/` confirms the linear chain `0001 → … → 0011`; `0011` has no successor.
- `mtmf` schema function count: **152** functions (`pg_proc` in schema `mtmf`).
- Existing database audit tables (unchanged): `mtmf.membership_removal_audit` (v002), `mtmf.stewardship_audit` (v008).

## 3. Baseline commands and results (before implementation changes)

| # | Command | Result |
|---|---|---|
| 1 | `git status --short` | clean working tree |
| 2 | `git rev-parse HEAD` | `44c6c0b7230ccbd4820866fb97f36896566753a5` |
| 3 | `uv sync --locked` | exit 0 (rebuilt the workspace distributions; note it removes the non-graph native `mtmf-permission-engine`, which `./build.sh --rust` reinstalls) |
| 4 | `./build.sh --qa` | **PASS** — Ruff format/lint OK, strict Mypy OK, `2085 passed, 177 skipped`, coverage **90.67%** (gate ≥ 85%) |
| 5 | `./build.sh --integration` (MTMF `.env` sourced) | **PASS** — `564 passed, 86 skipped in 251.76s` |

The 86 integration skips are the opt-in live Keycloak/Uvicorn/Collector suites that require their own live harness flags; this matches the PR 19 baseline ("564 passed / 86 opt-in live skipped"). An unavailable database is not counted as PASS; the database was available and the 564 non-optional integration tests ran.

## 4. Post-change re-run (implementation + tests added)

Recorded here for continuity; full evidence is in `PR19A_TEST_EVIDENCE.md`.

| # | Command | Result |
|---|---|---|
| 1 | `./build.sh --qa` | **PASS** — `2105 passed, 177 skipped`, coverage **90.76%**; new module `mutation_provenance.py` at **100%** |
| 2 | `./build.sh --sec` | **PASS** — Bandit Medium/High 0 findings; Semgrep 297 rules / 207 targets / 0 findings |
| 3 | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, installed-native probe, boundary/differential/Authorizer tests, isolated wheel verification, benchmark smoke |
| 4 | `./build.sh --integration` | **PASS** — `564 passed, 86 skipped in 219.35s` |

## 5. Baseline conclusion

The canonical baseline was green, so the PR 19A mandatory early-STOP condition #11 ("canonical tests unavailable or failing before changes") does not apply. Phase 0 proceeded to the trust-boundary reconciliation, whose result (no category-A mutation entry point) is recorded in
[`PR19A_TRUST_BOUNDARY_RECONCILIATION.md`](PR19A_TRUST_BOUNDARY_RECONCILIATION.md) and
[`PR19A_STOP_REPORT.md`](PR19A_STOP_REPORT.md).
