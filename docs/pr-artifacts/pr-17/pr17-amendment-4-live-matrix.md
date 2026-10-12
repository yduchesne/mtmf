# PR 17 — Amendment #4 live acceptance matrix (V01–V16)

Environment: real PostgreSQL 18 (MTMF-owned, restricted `mtmf_runtime`); pinned
Keycloak `26.8.0-1`, realm `mtmf-pr14-dev`; real Uvicorn/ASGI; genuine
issuer-signed service and interactive-user tokens; the D2-approved realm +
expected-client artifacts.

| ID | Status | Evidence |
| --- | --- | --- |
| V01 Fresh containerized deployment | PASS | D3 host-network container `/health/ready` 200 + real ALLOW; isolated V13 fresh bootstrap + ALLOW; single-root state |
| V02 Real ALLOW/DENY | PASS (live) | `test_v02_real_tokens_allow_and_deny`, `test_v02_unknown_action_and_mtmf_owned` |
| V03 Ordered 100-action batch | PASS (live) | `test_v03_hundred_item_ordered_batch` |
| V04 Eligibility states | PASS (live) | SUSPENDED/CANCELLED/EXPIRED, no-subscription, time-expired |
| V05 Forged/wrong Tenant/Org/different client | PASS (live) | forged user, foreign Organization, different-client fail-closed |
| V06 SYSTEM/root denial | PASS (live) | `test_v06_root_subject_is_denied` |
| V07 Issuer drift / no positive cache | PASS (live) | realm/manifest mismatch + client drift + no-cache |
| V08 Live DB outage / recovery | PASS (live) | `test_v08_live_database_outage_and_recovery` |
| V09 Idempotent restart | PASS (real PostgreSQL + live Keycloak) | initializer fresh/idempotent |
| V10 Concurrent initialization | PASS (real PostgreSQL) | concurrent serialize |
| V11 Conflicting state fails closed | PASS (real PostgreSQL) | conflicting root; initializer client drift fails closed |
| V12 Two Applications/clients | PASS (live) | CL01–CL07 (`test_cl0*`) |
| V13 MTMF-only destroy/recreate | PASS | isolated `mtmf-v13` PostgreSQL volume destroy + recreate; shared resources untouched |
| V14 Production/initializer isolation | PASS | production refusal tests; runtime env has no privileged credential |
| V15 Live HTTP size/rate/timeout/error | PASS (live + unit) | 413/415/401/429/no-store live; timeout/admission units |
| V16 Authenticated non-root conformance | PASS (live) | PR 14 live actor suite 22/22; PR 17 live HTTP suite |

## Live counts (this amendment)

| Suite | Result |
| --- | --- |
| `test_pr17_live_http.py` | 26 passed (V02–V16 + CL01–CL07) |
| `test_pr14_live_actor_context.py` | 22 passed |
| `test_pr17_runtime_timeouts.py` | 5 passed |
| `test_pr17_dev_initializer.py` | 3 passed |

No mandatory scenario is skipped; each PASS was executed in the required live
topology (real Keycloak + real PostgreSQL + real HTTP).
