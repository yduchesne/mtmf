# PR21_ACCEPTANCE_REPORT

**PR:** roadmap PR 21 — Application-neutral onboarding architecture and API contracts
**Status:** **DOCUMENTATION ACCEPTANCE PASSES; STOP-01 CLOSED (Option B direction); narrower STOP-02–STOP-06 OPEN; PR 21 IS NOT DONE.**
**Amendment 01 (2026-10-15):** this report remains valid for the pre-amendment
documentation baseline. The amendment's acceptance is recorded in
`PR21_AMENDMENT01_ACCEPTANCE_REPORT.md`. STOP-01 is closed per D8; the narrower
open STOPs are in `PR21_AMENDMENT01_STOP_REPORT.md`.
**Nature of evidence:** documentation/design acceptance only. No runtime
capability is implemented or claimed. No production behavior is proven.

## 1. Scope delivered

PR 21 is documentation-only. Delivered artifacts:

| Artifact | Purpose |
| --- | --- |
| `docs/ONBOARDING_ARCHITECTURE.md` | Proposed onboarding architecture (PROPOSED / NOT IMPLEMENTED) |
| `docs/ONBOARDING_HTTP_CONTRACT.md` | Proposed versioned management wire contract (PROPOSED / NOT IMPLEMENTED) |
| `docs/pr-artifacts/pr-21/PR21_BASELINE_RECONCILIATION.md` | Fresh-main reconciliation |
| `docs/pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md` | Adversarial matrix C01–C36 with future owners |
| `docs/pr-artifacts/pr-21/PR21_CONTRACT_REVIEW.md` | Action-URN/error/manifest reconciliation, open questions |
| `docs/pr-artifacts/pr-21/PR21_STOP_REPORT.md` | STOP-01 record |
| `README.md`, `docs/ROADMAP_V01.md` | Navigation/status links (PR 21 not marked DONE) |

**No production change:** no file under `packages/**`, `tests/**`, Alembic/SQL,
`Cargo*`, `uv.lock`, Podman/Compose, or the built-in Action/Role manifests was
modified.

## 2. Baseline and final SHAs

| Item | Value |
| --- | --- |
| Base (fresh `main`) SHA | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Branch | `dev/onboarding-foundation` |
| Working tree at start | clean |
| Alembic head | `0013_security_mutation_audit_partitioning` |
| Documentation commit under test | recorded in `PR21_FINAL_SHA.md` (the commit whose parent is the base SHA) |

## 3. Environment

| Item | Value |
| --- | --- |
| Host | WSL2, Linux 6.18 (microsoft-standard-WSL2) |
| Python (uv) | 3.14.7 |
| PostgreSQL | 18 (`docker.io/library/postgres:18`, MTMF-owned `mtmf` Compose project, host port `25432`) |
| Database roles | administrator (provision/verify), `mtmf_migrator` (migrations), restricted `mtmf_runtime` (runtime tests) |
| Podman | 4.9.3 |
| Rust | toolchain present; native module built/installed by `./build.sh --rust` |

## 4. Gate evidence

### 4.1 Baseline (pre-change, base SHA `455ae7a`)

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **PASS** — first run 2173 passed / 177 skipped, coverage 90.23%³; after `--rust` installed the native module, 2462 passed / 90.36% |
| Security | `./build.sh --sec` | **PASS** — Bandit 0 findings; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | **PASS** |
| Integration | `set -a && . ./.env && set +a && ./build.sh --integration` | **PASS** — 593 passed / 90 skipped |

³ The 177 skips were caused by the private native module
(`_mtmf_permission_engine`) not yet being `maturin develop`-installed in this
fresh environment; the canonical `--rust` gate installs it, after which the
quality gate's full suite runs. This is an environment/harness effect, not a
test defect; both runs PASS and no gate was weakened.

### 4.2 Post-change (documentation changes present)

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **PASS** — 2462 passed, 3 warnings; coverage 90.36% (>= 85%) |
| Security | `./build.sh --sec` | **PASS** — Bandit 0 findings; Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — fmt/clippy/test, `maturin develop`, native probe, focused parity tests, isolated wheel build/install/use, benchmark smoke |
| Integration | `set -a && . ./.env && set +a && ./build.sh --integration` | **PASS** — 593 passed / 90 skipped |

Because PR 21 changed only Markdown, the post-change gate results are
regression evidence that the documentation did not disturb the codebase; they
are not evidence of any onboarding feature.

## 5. Documentation acceptance checks

| ID | Check | Result |
| --- | --- | --- |
| A01 | Both normative docs exist and all relative links resolve | PASS (link checker: 0 broken) |
| A02 | Every future capability marked PROPOSED / NOT IMPLEMENTED | PASS |
| A03 | New-Tenant, join-existing, and subscription flows distinct and fully specified | PASS |
| A04 | Pre-Tenant and pre-membership admission explicitly avoid circular actor resolution | PASS |
| A05 | Global Identity/Principal reuse, Tenant isolation, root exclusion explicit | PASS |
| A06 | Stewardship, Role, and ACTIVE transition invariants explicit | PASS |
| A07 | UUID vs `tenant_key` vs `name` vs `idempotency_key` distinguished | PASS |
| A08 | Exact future API schemas, visibility, errors, replay, audit, concurrency specified | PASS |
| A09 | Security matrix C01–C36 complete with owner/test layer | PASS (36/36 rows verified) |
| A10 | STOP-01 human decision recorded | PASS (recorded; unresolved) |
| A11 | All PR reports committed under `docs/pr-artifacts/pr-21/` | PASS |
| A12 | QA/security/Rust/integration evidence accurate; no NOT RUN shown as PASS | PASS |
| A13 | Versioned roadmap status changed but **not** marked DONE | PASS |
| A14 | No endpoint advertised as working; `POST /v1/management/tenants` labeled DEFERRED | PASS |

## 6. Failure classification

No gate failed. No introduced regression, feature defect, flaky result, or
environment/harness failure remains unresolved. The one environment effect
(native-module skips on the first baseline `--qa`) is documented in §4.1 and was
resolved by the canonical `--rust` gate, not by weakening a threshold.

## 7. Evidence categories

- **Baseline:** §4.1.
- **Regression:** §4.2 (unchanged codebase, docs-only diff).
- **Feature-document acceptance:** §5 (A01–A14).
- **Future integration/stability:** **NOT EXECUTED** — owned by PR 26; the
  C01–C36 matrix is design-time only and is not a test result.

## 8. Residuals and blockers

1. **STOP-01** — the pre-Tenant/first-user admission authority is unresolved;
   PR 21 MUST NOT be marked DONE until a human reviewer records the decision.
2. Exact Action URNs, Role/Permission composition, and the additive
   `404`/`409`/`410` error codes remain unapproved proposals (PR 22–25).

## References

- `PR21_BASELINE_RECONCILIATION.md`, `PR21_SECURITY_MATRIX.md`,
  `PR21_CONTRACT_REVIEW.md`, `PR21_STOP_REPORT.md` (this directory).
- `docs/ONBOARDING_ARCHITECTURE.md`, `docs/ONBOARDING_HTTP_CONTRACT.md`.
