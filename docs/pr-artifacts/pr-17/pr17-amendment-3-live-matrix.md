# PR 17 — Amendment #3 live acceptance matrix (Part E)

**Environment:** real PostgreSQL 18 (`mtmf_postgres_1`, restricted
`mtmf_runtime`); pinned Keycloak `26.8.0-1`, realm `mtmf-pr14-dev`; real
Uvicorn on loopback; genuine issuer-signed tokens. The opt-in live suites are
enabled by setting the `MTMF_PR14_LIVE` / `MTMF_PR17_LIVE` flags and pointing
`SSL_CERT_FILE` at the development CA.

| ID | Status | Evidence |
| --- | --- | --- |
| V01 Fresh containerized deployment | PARTIAL (host-network) | Amendment #2 container run + readiness 200 + authenticated ALLOW; Compose network topology not executed (D3) |
| V02 Real ALLOW/DENY | PASS (live) | `test_v02_real_tokens_allow_and_deny`, `test_v02_unknown_action_and_mtmf_owned` |
| V03 Ordered 100-action batch | PASS (live) | `test_v03_hundred_item_ordered_batch` |
| V04 Eligibility states | PASS (live) | `test_v04_lifecycle_ineligible[SUSPENDED/CANCELLED/EXPIRED]`, `test_v04_no_subscription_is_ineligible`, `test_v04_time_expired_subscription_is_ineligible` |
| V05 Forged/wrong Tenant/Org/different client | PASS (live) | `test_v05_wrong_tenant_and_forged_user`, `test_v05_foreign_organization_is_rejected`, `test_v05_different_client_service_token_is_rejected` |
| V06 SYSTEM/root denial | PASS (live) | `test_v06_root_subject_is_denied` |
| V07 Issuer drift / no positive cache | PASS (live) | `test_v07_manifest_mismatch_fails_closed`, `test_v07_no_positive_attestation_cache` |
| V08 Live DB outage / recovery | **PASS (live)** | `test_v08_live_database_outage_and_recovery`: baseline 200 → PostgreSQL stopped → request 503 `DEPENDENCY_UNAVAILABLE` with no decisions → readiness 503 → restore → readiness 200 → ALLOW 200 |
| V09 Idempotent restart | PASS (real PostgreSQL + live Keycloak) | `test_dev17_initializer_fresh_and_idempotent` |
| V10 Concurrent initialization | PASS (real PostgreSQL) | `test_dev17_initializer_concurrent_attempts_serialize` |
| V11 Conflicting state fails closed | PASS (real PostgreSQL) | `test_dev17_initializer_rejects_conflicting_root` |
| V12 Two Applications/clients | **BLOCKED (D2)** | second live Keycloak client + independent expected-client policy require D2/manifest approval |
| V13 MTMF-only destroy/recreate | **NOT EXECUTED** | shared dev PostgreSQL volume not provably disposable; STOP per plan |
| V14 Production/initializer isolation | PASS (unit) | `test_production_mode_is_refused_before_any_work`, `test_h29_production_profile_fails_startup` |
| V15 Live HTTP size/rate/timeout/error | PASS (live + unit) | `test_v15_live_http_limits_and_errors`, `test_v15_rate_limit_saturation_is_429`; timeout/admission via G4 units |
| V16 Authenticated non-root conformance | PASS (live) | PR 14 live actor suite 22/22; PR 17 live HTTP suite (see below) |

## Live counts (this amendment)

| Suite | Result |
| --- | --- |
| `test_pr17_live_http.py` | 20 passed (19 + V08) |
| `test_pr14_live_actor_context.py` | 22 passed |
| `test_pr17_runtime_timeouts.py` | 5 passed |
| `test_pr17_dev_initializer.py` | 3 passed |

Every V case that is marked PASS was executed against the required real
Keycloak/PostgreSQL/Uvicorn topology. V12/V13 are blocked/not executed and are
not promoted.
