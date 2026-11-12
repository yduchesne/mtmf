# PR 23 — Final Acceptance Report

**Verdict: `PR23_COMPLETE_INTERNAL_ONLY` — DONE — INTERNAL PARTICIPANT ONLY**

**Fixup content under test:** `a68177edddef46a077bf4942fbcd455cdd8a9428`
(independent-review F1/F2 corrections on top of `227fbcb`).

The verified pre-Tenant subject seam and the owner-only, non-committing
initial-stewardship transaction participants are implemented and verified on
real PostgreSQL, with genuine Keycloak token acceptance and the PR 14 live
regression passing. The independent-review F1 (fresh-Tenant graph) and F2
(cross-type canonical root UUID) defects are fixed and covered by new
real-PostgreSQL negative/positive cases. This is **not** v0.1 Tenant onboarding completion; PR 24P
(privileged execution topology) and PR 22B (one-transaction Tenant/quota/replay
composite) remain required.

## Requirements vs executed evidence

| Requirement | Evidence | Status |
| --- | --- | --- |
| Source reconciled to baseline; `git fsck --full` clean | `1bb46af…`, clean fsck/diff | PASS |
| Frozen internal pre-Tenant result | contract + A-U01…A-U18 (18 passed) | PASS |
| Reuse PR 14 token-pair trust unchanged | `_verify_token_pair` extraction; old tests pass | PASS |
| Pre-Tenant verification requires no Tenant/membership/entitlement and writes nothing | A-U11/A-U12, P23-I04/I05 | PASS |
| Global subject exact semantics, reuse, conflicts, no email merge/cross-Tenant union | P23-I04…I08, I19 | PASS |
| F2: all three proposed UUIDs exclude all canonical root Tenant/Principal/Identity UUIDs | 9 parameterized F2 cases + positive control | PASS |
| F1: fresh Tenant rejects Organizations, Groups, Group memberships/grants, Tenant Roles, management-group state | 7 parameterized F1 cases + cross-Tenant positive F1-08 | PASS |
| Owner-only non-committing B1+B2 in one transaction; rollback and concurrency | P23-I09/I10/I16 | PASS |
| Audit extension preserves four operations + `INITIAL_ONBOARDING`; append-only intact | P23-I17, v015 assertions | PASS |
| Runtime denied both functions and protected table writes; 78-grant allowlist unchanged | P23-I03/I18, postflight, role verifier | PASS |
| Root/steward guards unchanged; no ACTIVE Tenant committed by PR 23 | P23-I11/I20, all tests | PASS |
| No new Tenant/activation/quota/replay/registration/HTTP/executor/seed | scope review, diffs | PASS |
| Canonical QA + security + integration | 2490 passed / 0 skipped / 90.30%; 0 findings; 646 passed / 94 skipped | PASS |
| Pre-commit | `uv run --no-sync pre-commit run --all-files` | PASS |
| Canonical Rust gate | rustup stable 1.99.1; `./build.sh --rust` | PASS |
| Genuine signed-token live acceptance L01–L04 | 4 passed, 0 skipped | PASS |
| PR 14 live regression | 22 passed, 0 skipped | PASS |
| QA count reconciliation | `main` 2472 / branch 2490 (+18 new tests), same environment | PASS |

## Gate checklist

- [x] Source reconciled; integrity clean.
- [x] Verified pre-Tenant proof with genuine signed tokens.
- [x] Global subject semantics/conflicts tested on real PostgreSQL.
- [x] Owner-only B1+B2 executed in one PostgreSQL transaction; rollback and
      concurrency proved; no ACTIVE Tenant committed by PR 23.
- [x] Audit extension correct; append-only guards intact.
- [x] `mtmf_runtime` denied both functions and all protected writes; 78-grant
      allowlist unchanged; postflight passes.
- [x] `--qa`, `--sec`, `--rust`, `--integration`; coverage ≥85%; no unintentional
      skips or exclusions.
- [x] No protected seed change, root impersonation, HTTP, or privileged executor.
- [x] Reports and minimum documentation committed.

## Evidence index

- [PR23_INDEPENDENT_REVIEW_FIXUP_REPORT.md](PR23_INDEPENDENT_REVIEW_FIXUP_REPORT.md)
- [PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md](PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md)
- [PR23_INTEGRATION_AND_LIVE_ACCEPTANCE.md](PR23_INTEGRATION_AND_LIVE_ACCEPTANCE.md)
- [PR23_SECURITY_AND_PRIVILEGE_REPORT.md](PR23_SECURITY_AND_PRIVILEGE_REPORT.md)
- [PR23_STOP_AND_DEVIATION_REPORT.md](PR23_STOP_AND_DEVIATION_REPORT.md)
- [PR23_VERIFIED_SUBJECT_CONTRACT.md](PR23_VERIFIED_SUBJECT_CONTRACT.md)
- [PR23_SQL_TRANSACTION_PARTICIPANT_CONTRACT.md](PR23_SQL_TRANSACTION_PARTICIPANT_CONTRACT.md)

## Unimplemented adjacent PRs

PR 24P, PR 22B, PR 24, PR 25, and PR 26 remain unimplemented/blocked. Production
root recovery remains a separate release gate. No push or pull request was made.
