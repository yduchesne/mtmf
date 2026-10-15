# PR21_AMENDMENT01_ACCEPTANCE_REPORT

**PR:** roadmap PR 21 — Amendment 01 (Application-Neutral Tenant Onboarding and Management Lifecycle Contracts)
**Status:** **DOCUMENTATION ACCEPTANCE COMPLETE; STOP-01 CLOSED; STOP-02–STOP-06 OPEN; PR 21 IS NOT DONE.**
**Explicit statement:** **documentation-only; no runtime behavior implemented.**

## 1. Branch and SHAs

| Item | Value |
| --- | --- |
| Branch | `dev/onboarding-foundation` |
| Base SHA | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Pre-amendment PR 21 tip | `739397820c064e5b7d2cc2b6cc90d3ec4f2025a2` |
| Amendment commit under test | recorded in `PR21_FINAL_SHA.md` |
| Migration head | `0013_security_mutation_audit_partitioning` |
| Production changes | none |

## 2. Changed files

All changes are Markdown documentation. No `packages/**`, `tests/**`, SQL,
Alembic, `Cargo*`, `uv.lock`, Compose, or generated file changed.

Normative docs amended: `docs/ONBOARDING_ARCHITECTURE.md`,
`docs/ONBOARDING_HTTP_CONTRACT.md`, `docs/ROADMAP_V01.md`, `README.md`.

New/updated artifacts under `docs/pr-artifacts/pr-21/`:
`PR21_AMENDMENT01_BASELINE_RECONCILIATION.md`,
`PR21_AMENDMENT01_DECISION_RECORD.md`,
`PR21_AMENDMENT01_AUTHORIZATION_MATRIX.md`,
`PR21_AMENDMENT01_CONTRACT_DIFF.md`,
`PR21_AMENDMENT01_SECURITY_CASES.md`,
`PR21_AMENDMENT01_STOP_REPORT.md`,
`PR21_AMENDMENT01_ACCEPTANCE_REPORT.md`, plus in-place amendment updates to
`PR21_STOP_REPORT.md`, `PR21_ACCEPTANCE_REPORT.md`, `PR21_SECURITY_MATRIX.md`,
`PR21_CONTRACT_REVIEW.md`, and `PR21_FINAL_SHA.md`.

## 3. Acceptance checklist (plan §9)

| # | Criterion | Result |
| --- | --- | --- |
| 1 | Existing PR 21 branch preserved and reconciled; no production changes | PASS — tip `7393978`; `git diff --name-only` shows docs only |
| 2 | Tenant independent of Application; N:M Tenant–Application subscriptions; global Identity reuse normative | PASS — architecture §17.1 |
| 3 | Resolve-or-provision state table covers all cases incl. existing Identity without Tenant and multiple choices | PASS — architecture §17.2 |
| 4 | New-Identity initial provisioning entitled, atomic, audited, includes authorized initial Application eligibility | PASS — architecture §§5.3, 17.3 |
| 5 | Existing-Tenant adoption requires independent subscription approval; no automatic second Tenant | PASS — architecture §§17.4, 6 |
| 6 | STOP-01 Option B recorded; narrower unapproved policies separated | PASS — decision record; amendment STOP report |
| 7 | Application create/inspect/suspend/retire and credential-binding boundary specified | PASS — HTTP contract §12; STOP-06 |
| 8 | Registration and subscription create/list/inspect/suspend/cancel specified without bypassing PR 13 guards | PASS — HTTP contract §§13–14 |
| 9 | No physical delete or terminal reactivation claimed without source-backed policy | PASS — architecture §17.5; STOP-05 |
| 10 | Every proposed route has admission, scope, DTO, response, idempotency, error, visibility, audit | PASS — HTTP contract §§11–15 |
| 11 | Exact Action URNs/Role grants not fabricated; authorization matrix and negative cases complete | PASS — authorization matrix; A01–A24; STOP-03 |
| 12 | Roadmap PRs 22–26 and live two-Application/one-Tenant acceptance updated | PASS — roadmap PR 21–26 |
| 13 | Original reports retained; amendment reports committed | PASS |
| 14 | All future features labeled PROPOSED / NOT IMPLEMENTED; no HTTP functionality claimed | PASS |
| 15 | Gates, SHA, branch, changed files, STOPs accurately reported | PASS |

## 4. Executed gates (exact results)

Environment: WSL2, Podman 4.9.3, Python 3.14.7 (uv), PostgreSQL 18
(`mtmf_postgres_1`, `25432`), migration head `0013`.

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **PASS** — 2462 passed, 3 warnings; coverage 90.36% (>= 85%) |
| Security | `./build.sh --sec` | **PASS** — Bandit no issues; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | **PASS** — fmt/clippy/test, `maturin develop`, native probe, focused parity tests, isolated wheel build/install/use, benchmark smoke |
| Integration | `set -a && . ./.env && set +a && ./build.sh --integration` | **PASS** — 593 passed / 90 skipped |
| Links | repository link checker over changed docs | **PASS** — 0 broken; no stale `../pr-artifacts` path |

Because the amendment changed only Markdown, these are regression checks that
the documentation did not disturb the codebase. They are **not** evidence of any
onboarding feature. No gate was skipped, weakened, or reinterpreted.

## 5. Source-grounded PR 13 constraints preserved

The amendment documents (does not change) the actual transitions: Application
`ACTIVE↔SUSPENDED`, `ACTIVE/SUSPENDED→RETIRED` (RETIRED terminal); registration
`ACTIVE→REVOKED` (REVOKED terminal); subscription `PENDING→ACTIVE/CANCELLED`,
`ACTIVE→SUSPENDED/CANCELLED/EXPIRED`, `SUSPENDED→ACTIVE/CANCELLED/EXPIRED`
(CANCELLED/EXPIRED terminal); `ends_at` restrictive only. Terminal rows are
retained history and a replacement is a new row with a new UUID (STOP-05).

## 6. Remaining open policy questions

STOP-02 entitlement issuer/state · STOP-03 exact Action URNs and Role grants ·
STOP-04 registration authority · STOP-05 terminal replacement policy ·
STOP-06 credential-binding boundary. All are recorded in
`PR21_AMENDMENT01_STOP_REPORT.md`. PR 21 remains **NOT DONE** until they are
resolved.

## 7. Verification

`git diff --name-only <base>..HEAD` contains only documentation; all Markdown
links resolve; the original PR 21 artifacts are preserved with dated amendment
sections. **documentation-only; no runtime behavior implemented.**
