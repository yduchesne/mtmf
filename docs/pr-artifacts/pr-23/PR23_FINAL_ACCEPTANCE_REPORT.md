# PR 23 — Final Acceptance Report

**Verdict: `PR23_PARTIAL_BLOCKED`**

The internal verified-subject seam and the owner-only, non-committing
initial-stewardship transaction participants are implemented and verified on
real PostgreSQL. The mandatory genuine-signed-token live acceptance could not be
executed because the pre-existing PR 14 Keycloak fixture baseline drifts from
the committed attestation manifest; the unmodified PR 14 live test fails
identically on the baseline. Per the plan's STOP-08 and live-harness rules, PR 23
is **not DONE** and this is not a v0.1 onboarding completion claim.

## Requirements vs executed evidence

| Requirement | Evidence | Status |
| --- | --- | --- |
| Source reconciled to baseline; `git fsck --full` clean | `1bb46af…`, clean fsck/diff | PASS |
| Frozen internal pre-Tenant result | contract + A-U01…A-U18 (18 passed) | PASS (unit/real-DB) |
| Reuse PR 14 token-pair trust unchanged | `_verify_token_pair` extraction; old tests pass | PASS |
| Pre-Tenant verification requires no Tenant/membership/entitlement and writes nothing | A-U11/A-U12, P23-I04/I05 | PASS |
| Global subject exact semantics, reuse, conflicts, no email merge/cross-Tenant union | P23-I04…I08, I19 | PASS |
| Owner-only non-committing B1+B2 in one transaction; rollback and concurrency | P23-I09/I10/I16 | PASS |
| Audit extension preserves four operations + `INITIAL_ONBOARDING`; append-only intact | P23-I17, v015 assertions | PASS |
| Runtime denied both functions and protected table writes; 78-grant allowlist unchanged | P23-I03/I18, postflight, role verifier | PASS |
| Root/steward guards unchanged; no ACTIVE Tenant committed by PR 23 | P23-I11/I20, all tests | PASS |
| No new Tenant/activation/quota/replay/registration/HTTP/executor/seed | scope review, diffs | PASS |
| Canonical QA + security + integration | 2201 passed / 90.18%; 0 findings; 628 passed / 94 skipped | PASS |
| Canonical Rust gate | `cargo` unavailable | **BLOCKED-ENV** |
| Genuine signed-token live acceptance L01–L04 | 4 failed with pre-existing `ATTESTATION_DRIFT`; PR 14 live test fails identically | **BLOCKED-LIVE** |

## Gate checklist

- [x] Source reconciled; integrity clean.
- [ ] Verified pre-Tenant proof with genuine signed tokens (BLOCKED-LIVE).
- [x] Global subject semantics/conflicts tested on real PostgreSQL.
- [x] Owner-only B1+B2 executed in one PostgreSQL transaction; rollback and
      concurrency proved; no ACTIVE Tenant committed by PR 23.
- [x] Audit extension correct; append-only guards intact.
- [x] `mtmf_runtime` denied both functions and all protected writes; 78-grant
      allowlist unchanged; postflight passes.
- [x] `--qa`, `--sec`, `--integration`; coverage ≥85%; no newly skipped feature
      tests except the documented live opt-in.
- [ ] `--rust` (environment lacks the toolchain).
- [x] No protected seed change, root impersonation, HTTP, or privileged executor.
- [x] Reports and minimum documentation committed.

## Unimplemented adjacent PRs

PR 24P (privileged operator/pre-Tenant execution topology), PR 22B (quota/replay
+ Tenant/registration/subscription/activation one-transaction composite), PR 24
(onboarding HTTP), PR 25 (invitations/client), and PR 26 (deployed conformance)
remain unimplemented/blocked. Production root recovery remains a separate
release gate.

## Decision required

See [PR23_STOP_AND_DEVIATION_REPORT.md](PR23_STOP_AND_DEVIATION_REPORT.md) D1:
reconcile/approve the PR 14 Keycloak evidence fixture baseline (including whether
`mtmf-attestation-reader` and `mtmf-evidence-same-client-b` are approved) or
provide a separately approved live fixture so L01–L04 can run. Until then the
correct verdict remains `PR23_PARTIAL_BLOCKED`.
