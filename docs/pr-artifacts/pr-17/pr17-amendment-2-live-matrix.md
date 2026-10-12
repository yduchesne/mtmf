# PR 17 — Amendment #2 live acceptance matrix (Part D)

**Environment:** real PostgreSQL 18 (MTMF-owned `mtmf_postgres_1`, restricted
`mtmf_runtime`); pinned Keycloak `26.8.0-1`, realm `mtmf-pr14-dev`; real Uvicorn
(loopback `28011`) and a real containerized service (`28001`); genuine
issuer-signed service and interactive-user tokens; `MTMF_PR17_LIVE=1`,
`MTMF_PR14_LIVE=1`, `SSL_CERT_FILE=<dev CA>`.

Command forms:

```
MTMF_PR14_LIVE=1 … pytest tests/integration/postgres/test_pr14_live_actor_context.py
MTMF_PR17_LIVE=1 … pytest tests/integration/postgres/test_pr17_live_http.py
```

| ID | Status | Evidence |
| --- | --- | --- |
| V01 Fresh containerized deployment | PARTIAL (host-network) | image build + Keycloak + reset/seed + container `/health/ready` 200 + authenticated `200 ALLOW`; network/canonical topology not executed |
| V02 Real ALLOW/DENY | PASS (live) | `test_v02_real_tokens_allow_and_deny`, `test_v02_unknown_action_and_mtmf_owned` |
| V03 Ordered 100-action batch | PASS (live) | `test_v03_hundred_item_ordered_batch` |
| V04 Eligibility states | PASS (live) | `test_v04_lifecycle_ineligible[SUSPENDED/CANCELLED/EXPIRED]`, `test_v04_no_subscription_is_ineligible`, `test_v04_time_expired_subscription_is_ineligible` |
| V05 Forged/wrong tenant/org/different client | PASS (live) | `test_v05_wrong_tenant_and_forged_user`, `test_v05_foreign_organization_is_rejected`, `test_v05_different_client_service_token_is_rejected` (fail-closed 401/403) |
| V06 SYSTEM/root denial | PASS (live) | `test_v06_root_subject_is_denied` |
| V07 Issuer drift / no positive cache | PASS (live) | `test_v07_manifest_mismatch_fails_closed`, `test_v07_no_positive_attestation_cache` |
| V08 Live HTTP DB outage / privilege mismatch | PARTIAL | DB outage unit H18; runtime privilege integration suite; no live stop/restart of PostgreSQL |
| V09 Idempotent restart | PASS (real PostgreSQL + live Keycloak) | `test_dev17_initializer_fresh_and_idempotent`; two initializer runs |
| V10 Concurrent initialization | PASS (real PostgreSQL) | `test_dev17_initializer_concurrent_attempts_serialize` |
| V11 Conflicting state fails closed | PASS (real PostgreSQL) | `test_dev17_initializer_rejects_conflicting_root` |
| V12 Two Applications/clients | PARTIAL | `test_v12_two_applications_have_isolated_bindings` (live isolation); second live Keycloak client not provisioned (manifest, STOP-01) |
| V13 MTMF-only destroy/recreate | NOT EXECUTED | shared dev volume; see deployment evidence §4 |
| V14 Production/initializer isolation | PASS (unit) | `test_production_mode_is_refused_before_any_work`, `test_h29_production_profile_fails_startup` |
| V15 Live HTTP size/rate/timeout/error | PASS (live + unit) | `test_v15_live_http_limits_and_errors`, `test_v15_rate_limit_saturation_is_429`; timeout/admission via G4 units |
| V16 Authenticated non-root conformance | PASS (live) | PR 14 live actor suite **22 passed**; PR 17 live HTTP suite (see §live counts) |

## Deterministic (H01–H32, A1-16/17, A2-15)

- `./build.sh --qa` (unit): **1762 passed, 0 skipped, coverage 90.04%**.
- `test_concurrency.py`: saturation, timeout retention, no-worker-without-permit,
  and the closed permit race.
- `test_postgres_config.py`: timeout defaults, overrides, bounds, ordering,
  admin/migrator exclusion.

No mandatory item is marked PASS from a unit test where the matrix requires a
live scenario; partial/not-executed items remain visible.
