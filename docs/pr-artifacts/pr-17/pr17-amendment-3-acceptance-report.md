# PR 17 — Amendment #3 acceptance report

**Branch:** `dev/pr17-http-service`. **Base:** `4eea688`; prior head `040f8d0`.
**Amendment #3 feature commit:** `__FILL_AFTER_COMMIT__` (all gates and the
pre-commit hook ran on this tree).
**Disposition: IMPLEMENTED; ACCEPTANCE INCOMPLETE — STOPPED, NOT READY FOR MERGE.**

## 1. Human decision gates (required)

| Gate | Decision | Recorded |
| --- | --- | --- |
| D1 acting-user carrier | **PENDING** | `pr17-amendment-1-carrier-decision.md` (Amendment #2/#3 re-confirmation) |
| D2 attestation architecture | **PENDING** | `pr17-amendment-3-attestation-design-decision.md` |
| D3 development topology | **PENDING** | `pr17-amendment-3-deployment-evidence.md` |

No approval was invented. Per the plan, trust-verification semantics were **not**
changed; only diagnosis, design, deterministic tests, V08, and evidence were
produced.

## 2. What this amendment verified / changed

- **Diagnosis:** reproduced the whole-realm drift exactly (before hash
  `9e9bb847…fed5`, 15 clients, matches; after initializer `2372a2bd…b75c39`,
  16 clients, added `mtmf-sample-app`; scopes/realm unchanged). Proved fail-closed
  on a client `enabled` mutation with restore.
- **Design:** submitted the realm-projection + expected-client-policy design and
  fallback for D2 approval (no implementation).
- **Deterministic tests added (no trust-semantics change):**
  `test_at03_unknown_extra_client_is_rejected`,
  `test_at13_two_clients_are_independently_bound`,
  `test_at04_duplicate_client_identity_is_detected_as_drift`.
- **V08 live acceptance completed:** real HTTP 503 with zero decisions and
  readiness 503 during a real PostgreSQL outage, then recovery to 200.
- **Live suites re-run:** PR 17 HTTP 20/20, PR 14 actor 22/22.

## 3. Final gates

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1765 passed, 0 skipped, coverage 90.04% |
| Security | `./build.sh --sec` | PASS (run on final tree) |
| Rust | `./build.sh --rust` | PASS (pre-commit hook on final tree) |
| Integration | `./build.sh --integration` | PASS — 564 passed, 42 skipped (the 42 = PR 14 live 22 + PR 17 live 20, run separately and passing) |
| PR 17 live HTTP | opt-in `MTMF_PR17_LIVE` enabled | PASS — 20 passed |
| PR 14 live actor | opt-in `MTMF_PR14_LIVE` enabled | PASS — 22 passed |
| Timeouts | `test_pr17_runtime_timeouts.py` | 5 passed |
| Initializer | `test_pr17_dev_initializer.py` | 3 passed |
| Pre-commit | commit hook | PASS |

## 4. A3 checklist status

| ID | Status | Note |
| --- | --- | --- |
| A3-01 | PASS | baseline §1–2 |
| A3-02 | PASS | diagnosis §2 (exact field-level cause) |
| A3-03 | **STOP** | D2 not approved (S3-01) |
| A3-04 | PASS for current projection; realm-settings extension is D2 | |
| A3-05 | **BLOCKED** | per-client expected policy needs D2 |
| A3-06 | PASS today (unknown client ⇒ drift); unrelated-client non-authority is D2 | |
| A3-07 | PARTIAL | initializer creates approved-state client; drift fail-closed is D2 |
| A3-08 | PASS | PR 14 live 22/22 |
| A3-09 | **STOP** | D1 pending |
| A3-10 | **STOP** | D3 pending |
| A3-11 | PASS (host-network candidate) | deployment evidence §2–3 |
| A3-12 | PASS (residual attestation reader) | deployment evidence §3 |
| A3-13 | **PASS (live)** | V08 |
| A3-14 | **BLOCKED** | V12 needs D2 |
| A3-15 | **NOT EXECUTED** | V13 |
| A3-16 | PARTIAL | V01/V12/V13 incomplete |
| A3-17 | PARTIAL | AT matrix (see security matrix) |
| A3-18 | PASS | live suites ran, no hidden mandatory skips |
| A3-19 | PASS | QA/security/Rust/integration on final tree |
| A3-20 | PARTIAL | artifacts present; approvals + V12/V13 outstanding |

## 5. Files changed

```
tests/unit/authentication/test_attestation.py        (AT-03/04/13 deterministic tests)
tests/integration/postgres/test_pr17_live_http.py    (V08 live outage/recovery)
docs/pr-artifacts/pr-17/pr17-amendment-3-*.md        (eight reports)
```

No trust-verification, DTO, policy-engine, migration, grant or production file
was changed.

## 6. Disposition

**STOPPED — NOT READY FOR MERGE.** The decisive blockers are the unapproved D1
and D2 (and D3) human decisions, plus V12/V13 not executed. PR 17 is not marked
DONE and is not merged.
