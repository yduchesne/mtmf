# PR 17 — Amendment #4 live acceptance matrix (V01–V16)

**Code tree unchanged from Amendment #3** (this amendment adds documentation and
diagnosis only); live suites are re-run on the final commit and recorded here.
Environment: real PostgreSQL 18 (`mtmf_postgres_1`, restricted `mtmf_runtime`);
pinned Keycloak `26.8.0-1`, realm `mtmf-pr14-dev`; real Uvicorn on loopback;
genuine issuer-signed tokens.

| ID | Status | Evidence |
| --- | --- | --- |
| V01 Fresh containerized deployment | PARTIAL (host-network candidate) | Amendment #2 container ALLOW + readiness; official launcher reconciliation blocked by D3 |
| V02 Real ALLOW/DENY | PASS (live) | `test_v02_real_tokens_allow_and_deny`, `test_v02_unknown_action_and_mtmf_owned` |
| V03 Ordered 100-action batch | PASS (live) | `test_v03_hundred_item_ordered_batch` |
| V04 Eligibility states | PASS (live) | lifecycle SUSPENDED/CANCELLED/EXPIRED, no-subscription, time-expired |
| V05 Forged/wrong Tenant/Org/different client | PASS (live) | forged user, foreign Organization, different-client fail-closed |
| V06 SYSTEM/root denial | PASS (live) | `test_v06_root_subject_is_denied` |
| V07 Issuer drift / no positive cache | PASS (live) | manifest mismatch, no-cache |
| V08 Live DB outage / recovery | PASS (live) | `test_v08_live_database_outage_and_recovery` |
| V09 Idempotent restart | PASS (real PostgreSQL + live Keycloak) | initializer fresh/idempotent |
| V10 Concurrent initialization | PASS (real PostgreSQL) | concurrent serialize |
| V11 Conflicting state fails closed | PASS (real PostgreSQL) | conflicting root |
| V12 Two Applications/clients | **BLOCKED (D2)** | see `pr17-amendment-4-v12-v13-evidence.md` |
| V13 MTMF-only destroy/recreate | **NOT EXECUTED** | see `pr17-amendment-4-v12-v13-evidence.md` |
| V14 Production/initializer isolation | PASS (unit) | production refusal tests |
| V15 Live HTTP size/rate/timeout/error | PASS (live + unit) | 413/415/401/429/no-store live; timeout/admission units |
| V16 Authenticated non-root conformance | PASS (live) | PR 14 live actor suite; PR 17 live HTTP suite |

## Live counts (re-run on this amendment's commit)

| Suite | Result |
| --- | --- |
| `test_pr17_live_http.py` | recorded in the acceptance report (§ live re-run) |
| `test_pr14_live_actor_context.py` | recorded in the acceptance report |
| `test_pr17_runtime_timeouts.py` | 5 passed |
| `test_pr17_dev_initializer.py` | 3 passed |

V12/V13 remain incomplete and are not promoted. A passing unit test is not
counted as live completion.
