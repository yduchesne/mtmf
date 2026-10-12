# PR 17 — Amendment #1: live acceptance matrix (G2)

**Live environment used:** MTMF-owned PostgreSQL 18 (`mtmf_postgres_1`, host
`25432`, roles `mtmf_owner`/`mtmf_migrator`/`mtmf_runtime`); pinned Keycloak
`quay.io/keycloak/keycloak:26.8.0-1`, realm `mtmf-pr14-dev`, project
`mtmf-pr14-keycloak`, loopback `28080`/`28443`; real Uvicorn on
`127.0.0.1:28011`/`28001`; genuine issuer-signed service and interactive-user
tokens. Commands required `MTMF_PR14_LIVE`/`MTMF_PR17_LIVE=1` and
`SSL_CERT_FILE=<self-signed CA>`.

## 1. Original V01–V16

| ID | Original expectation | Status | Evidence / test node |
| --- | --- | --- | --- |
| V01 | Clean MTMF-owned Podman deployment: DB, Keycloak, completed initializer, ready HTTP | PARTIAL | Image build exit 0; `mtmf-pr14-keycloak` up; fresh initializer exit 0; `python -m mtmf_service` → `/health/ready` 200. Containerized Compose path NOT EXECUTED (issuer hostname blocker). |
| V02 | Real signed service+user tokens → PR14 attestation → persisted bindings → PR13 eligibility → PR16 PDP → PR15 response; one ALLOW and one DENY | PASS (live) | `test_pr17_live_http.py::test_v02_real_tokens_allow_and_deny`, `::test_v02_unknown_action_and_mtmf_owned` |
| V03 | 100-item batch with duplicates; ordered 100 decisions; one shared context | PASS (live) | `::test_v03_hundred_item_ordered_batch` |
| V04 | Unsubscribed/suspended/cancelled/expired subscription → 403, zero grants | PARTIAL | `::test_v04_suspended_subscription_is_ineligible` (live); cancelled/expired via unit H16 mapping |
| V05 | Forged user, different-client tokens, wrong Tenant/Organization → 403 | PARTIAL | `::test_v05_wrong_tenant_and_cross_client` (live: wrong Tenant + forged user); different-client/wrong-Org via units H13/H14 |
| V06 | SYSTEM/root Tenant and root Identity attempt → zero grants | PASS (live) | `::test_v06_root_subject_is_denied` |
| V07 | Issuer config drift / Admin REST outage after success → next fails; no cached attestation | PASS (live) | `::test_v07_manifest_mismatch_fails_closed`, `::test_v07_no_positive_attestation_cache` |
| V08 | DB outage, runtime role privilege mismatch → readiness false + authorization error; no escalation | PARTIAL | DB outage unit H18; runtime privilege surface via `test_postgres_runtime_security.py`/`test_runtime_privileges.py` (75-signature allowlist); no live HTTP DB-outage case |
| V09 | Restart fully matching state → same root/Tenant/Application/subscription/binding/secret; no duplicate | PASS (real PostgreSQL + live Keycloak) | fresh + idempotent `scripts/mtmf-dev-initialize.py`; `test_pr17_dev_initializer.py::test_dev17_initializer_fresh_and_idempotent` |
| V10 | Two simultaneous initializer attempts → serialized/one deterministic loser; no partial state | PASS (real PostgreSQL) | `::test_dev17_initializer_concurrent_attempts_serialize` |
| V11 | Intentionally inconsistent/partial fixture → fails closed; no auto-repair | PASS (real PostgreSQL) | `::test_dev17_initializer_rejects_conflicting_root` |
| V12 | Two independently configured Applications → unique bindings; no cross-client grant | PARTIAL | `::test_v12_two_applications_have_isolated_bindings` (live); second keycloak client not provisioned |
| V13 | Clean destroy/recreate MTMF-owned dev resources only | NOT EXECUTED | Full MTMF volume destroy not run |
| V14 | No initializer/production mode → dev fixture never runs; no production claim | PASS (unit) | `test_development_bootstrap.py::test_production_mode_is_refused_before_any_work`; `test_app.py::test_h29_production_profile_fails_startup` |
| V15 | Real HTTP size/rate/timeout/error behavior | PARTIAL | `::test_v15_live_http_limits_and_errors` (413/415/401/no-store live); rate/timeout via units H27/G4 |
| V16 | Authenticated non-root positive and negative conformance (PR14 live, not skipped) | PASS (live, actor layer) | `tests/integration/postgres/test_pr14_live_actor_context.py` **22 passed** (was 6 failing before the amendment fixed the stale categories); HTTP layer in `test_pr17_live_http.py` |

**Live counts:** `test_pr17_live_http.py` 12 passed; `test_pr14_live_actor_context.py`
22 passed. No V case was promoted from `NOT EXECUTED` to `PASS`.

## 2. H01–H32 (deterministic unit/ASGI)

Unchanged from the original PR 17 acceptance report and still passing under
`./build.sh --qa` (1,750 passed, 89.99% coverage), plus the Amendment #1
additions:

| ID | Status | Note |
| --- | --- | --- |
| H01–H32 | PASS | `tests/unit/service/test_evaluation.py`, `test_app.py`, `test_settings_clock_rate.py` |
| A1-16 | PASS | `test_concurrency.py::test_a1_16_saturation_is_deterministic_503` |
| A1-17 | PASS | `test_concurrency.py::test_a1_17_timeout_retains_permit_until_worker_completes`, `::test_a1_17_no_worker_runs_without_a_permit` |
| A1-18 | PASS | H10/H21/H23/H24/H25/H26/H28 + `test_v02_unknown_action_and_mtmf_owned` (live) |

## 3. A1-01–A1-20 index

| ID | Status |
| --- | --- |
| A1-01 | PASS — baseline report §1–2; branch verified, no unrelated scope |
| A1-02 | **STOP** — carrier approval pending (`pr17-amendment-1-carrier-decision.md`) |
| A1-03 | PASS — unit H11/H12/H13 + live `test_v05`/missing-service |
| A1-04 | PASS — live PR14 22/22; live HTTP ALLOW/DENY |
| A1-05 | PASS — live `test_v07_manifest_mismatch_fails_closed`, `test_v07_no_positive_attestation_cache` |
| A1-06 | PARTIAL — V03/V06/V07 PASS; V01/V04/V05/V08/V12/V13/V15 partial/not executed |
| A1-07 | PASS — live `test_v03_hundred_item_ordered_batch`, `test_v02` |
| A1-08 | PASS (live) — `test_v05_wrong_tenant_and_cross_client`, `test_v06_root_subject_is_denied` |
| A1-09 | PASS (live) — `test_v04_suspended_subscription_is_ineligible` |
| A1-10 | PASS — live 503s carry no decisions; unit H18/H22 |
| A1-11 | PARTIAL — image + Keycloak + initializer + readiness executed; container Compose path not executed |
| A1-12 | PASS — real-PG initializer idempotent/concurrent |
| A1-13 | PASS (partial live) — conflict/live drift fail closed; broad outage scenarios partly unit |
| A1-14 | PARTIAL — runtime role privilege surface verified by existing integration suite; process-env proof not captured |
| A1-15 | PASS — `scripts/mtmf-dev-stack.py` implemented; image built; ordering not delegated to Compose |
| A1-16 | PASS — timeout-evidence §1–3 |
| A1-17 | PASS — timeout-evidence §3 |
| A1-18 | PASS — live `test_v15`, `test_v02_unknown_action_and_mtmf_owned`; units |
| A1-19 | PASS — final gates §1 of the acceptance report |
| A1-20 | PASS — this artifact directory + STOP register |
