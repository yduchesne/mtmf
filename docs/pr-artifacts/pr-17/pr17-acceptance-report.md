# PR 17 — Acceptance report

**Artifact directory:** `docs/pr-artifacts/pr-17/`.
**Branch:** `dev/pr17-http-service`.
**Baseline commit:** `4eea688b12005b59aa8dbee9981f08551dcb7702`.
**Final tree commit:** recorded in the PR branch head after the final gates (see §1).
**Disposition:** **implementation complete; NOT DONE / NOT MERGED.** The live
Keycloak + real-ASGI end-to-end matrix (`V01`–`V16`) was **NOT EXECUTED**, and
`NOT EXECUTED ≠ PASS` (plan §13.11). PR 17 may not be marked DONE until that
acceptance runs and a human reviewer authorizes disposition.

## 1. Canonical gates on the final tree

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1454 passed, 177 skipped; total coverage 89.5% (≥ 85%) |
| Security | `./build.sh --sec` | PASS — Bandit 0 Medium/High; Semgrep 0 findings |
| Rust/native | `./build.sh --rust` | PASS — fmt/clippy/test, `maturin develop`, native probe, focused parity, wheel verification, benchmark smoke (characterization only) |
| Integration | `./build.sh --integration` | PASS (with exported `.env`) — includes the new `test_pr17_dev_initializer.py`; the 22 skipped cases are the opt-in PR 14 live-Keycloak suite and are **not** acceptance PASS |
| Pre-commit | `uv run --no-sync pre-commit run --all-files` | recorded in the PR log |

The 22 historical PR 14 live-Keycloak skips are explicitly **not** counted as
acceptance. The required live issuer suite must be run separately with the
approved fixture.

## 2. Deterministic ASGI/unit matrix (H01–H32)

All tests are in `tests/unit/service/` and use deterministic boundary doubles
for the issuer/JWKS/attestation seam, the clock, and (for fault injection) the
persistence provider. The production PR 15 parser, PR 14 actor composition, PR 9
role resolver, PR 16 batch evaluator, ASGI application, and rate limiter are
exercised for real.

| ID | Status | Test node(s) |
| --- | --- | --- |
| H01 | PASS | `test_evaluation.py::test_h01_single_action_allow_and_deny` |
| H02 | PASS | `test_evaluation.py::test_h02_hundred_actions_with_duplicates_preserve_order` |
| H03 | PASS | `test_evaluation.py::test_h03_batch_size_bounds_rejected_without_processing[0/101]`, `::test_h03_duplicate_request_ids_rejected` |
| H04 | PASS | `test_evaluation.py::test_h04_strict_json_rejections[6 cases]` |
| H05 | PASS | `test_evaluation.py::test_h05_unknown_fields_wildcards_actor_ids_and_bad_resource_rejected[5 cases]` |
| H06 | PASS | `test_evaluation.py::test_h06_unknown_action_denies_per_item` |
| H07 | PASS | `test_evaluation.py::test_h07_mixed_known_and_unknown_actions_are_ordered` |
| H08 | PASS | `test_evaluation.py::test_h08_capability_resource_is_action_level_only` |
| H09 | PASS | `test_evaluation.py::test_h09_application_owned_resource_is_binding_metadata_only` |
| H10 | PASS | `test_evaluation.py::test_h10_mtmf_owned_resource_never_allows` |
| H11 | PASS | `test_app.py::test_h11_missing_or_malformed_service_token_is_401`, `::test_h11_expired_service_token_is_401` |
| H12 | PASS | `test_app.py::test_h12_valid_service_but_bad_user_token_is_403` |
| H13 | PASS | `test_app.py::test_h13_cross_client_user_token_is_403`, `::test_h13_user_token_with_service_class_is_403`, `::test_h13_root_subject_is_403` |
| H14 | PASS | `test_app.py::test_h14_unknown_tenant_selector_is_403`, `::test_h14_missing_membership_is_403`, `::test_h14_foreign_organization_is_403` |
| H15 | PASS | `test_app.py::test_h15_root_tenant_selector_never_allows` |
| H16 | PASS | `test_app.py::test_h16_ineligible_subscription_is_403[3 cases]`, `::test_h16_revoked_registration_is_403`, `::test_h16_suspended_application_is_403` |
| H17 | PASS | `test_app.py::test_h17_attestation_drift_is_503` |
| H18 | PASS | `test_app.py::test_h18_database_outage_is_503`, `::test_h18_policy_resolver_exception_is_500` |
| H19 | PASS | `test_evaluation.py::test_h19_one_shared_context_and_one_policy_resolution` |
| H20 | PASS | `test_evaluation.py::test_h20_python_default_needs_no_native_module` |
| H21 | PASS | `test_evaluation.py::test_h21_exhaustive_core_decision_mapping`, `::test_h21_no_policy_diagnostics_on_the_wire` |
| H22 | PASS | `test_app.py::test_h22_response_conformance_fault_is_500` |
| H23 | PASS | `test_evaluation.py::test_h23_conservative_default_ttl_is_sensitive`, `::test_h23_allowlist_classifier_uses_default_for_non_sensitive`, `::test_h23_mixed_batch_is_bounded_by_sensitive_ttl` |
| H24 | PASS | `test_evaluation.py::test_h24_issued_precedes_expires_utc` |
| H25 | PASS | `test_app.py::test_h25_exact_bound_accepted_and_over_bound_rejected`, `::test_h25_streamed_byte_count_and_false_content_length` |
| H26 | PASS | `test_app.py::test_h26_wrong_media_type_and_encoding_are_415` |
| H27 | PASS | `test_app.py::test_h27_rate_limit_saturation_is_429` |
| H28 | PASS | `test_app.py::test_h28_no_store_no_docs_no_cors_and_redaction` |
| H29 | PASS | `test_app.py::test_h29_liveness_and_readiness_are_distinct`, `::test_h29_production_profile_fails_startup`, `::test_h29_readiness_endpoint_reports_not_ready` |
| H30 | PASS | `test_app.py::test_h30_cancellation_propagates_through_the_service` (service-level `CancelledError` propagation; the app builds the whole response before writing, so no partial body) |
| H31 | PASS | `test_app.py::test_h31_error_envelope_shape[2 cases]`, `::test_h31_unauthenticated_and_unsupported_media_envelopes` |
| H32 | PASS | `test_app.py::test_h32_no_positive_attestation_cache_between_requests` |

Initializer orchestration is covered by
`test_development_bootstrap.py::test_*` (sequence, production refusal, failure
wrapping, lock release, error propagation, fixture validation).

## 3. Real-service acceptance matrix (V01–V16)

| ID | Status | Evidence / reason |
| --- | --- | --- |
| V01 | NOT EXECUTED | Live Keycloak + real Uvicorn deployment not started in this execution. |
| V02 | NOT EXECUTED | Requires a live seeded policy and real issuer tokens. |
| V03 | NOT EXECUTED | Live variant; 100-item ordering is covered at unit level (H02/H19). |
| V04 | NOT EXECUTED | Live subscription lifecycle; unit mapping covered (H16). |
| V05 | NOT EXECUTED | Live forged-token cases; unit mapping covered (H13/H14). |
| V06 | NOT EXECUTED | Live root/SYSTEM attempt; unit covered (H15). |
| V07 | NOT EXECUTED | Live issuer drift/Admin REST outage. |
| V08 | NOT EXECUTED | Live DB outage/privilege mismatch; unit DB outage covered (H18). |
| V09 | PARTIAL (real PostgreSQL) | `tests/integration/postgres/test_pr17_dev_initializer.py::test_dev17_initializer_fresh_and_idempotent` proves restart idempotency and stable binding reuse; Keycloak client-secret preservation not executed. |
| V10 | PARTIAL (real PostgreSQL) | `::test_dev17_initializer_concurrent_attempts_serialize` proves advisory-lock serialization with no duplicates. |
| V11 | PARTIAL (real PostgreSQL) | `::test_dev17_initializer_rejects_conflicting_root` proves fail-closed conflict handling for privileged root state. |
| V12 | NOT EXECUTED | Two independently configured Applications against a live issuer not run. |
| V13 | NOT EXECUTED | Clean MTMF-owned Podman destroy/recreate not run. |
| V14 | PASS (unit) | `test_development_bootstrap.py::test_production_mode_is_refused_before_any_work` and `test_app.py::test_h29_production_profile_fails_startup`. |
| V15 | NOT EXECUTED | Real HTTP size/rate/timeout behavior; unit ASGI cases cover the envelopes (H25–H27/H31). |
| V16 | NOT EXECUTED | The PR 14 live suite was skipped (22 cases) as documented; a positive/negative live conformance run is required. |

## 4. Classification of failures and skips

| Item | Classification |
| --- | --- |
| 22 PR 14 live-Keycloak tests skipped under `--integration` | Environment/harness-gated (opt-in `MTMF_PR14_LIVE=1`); not a regression and not acceptance PASS |
| `V01`–`V08`, `V12`–`V13`, `V15`–`V16` | NOT EXECUTED (environment/harness blocked: no live Keycloak started; `podman-compose 1.0.6` lacking `service_completed_successfully`) |
| No pre-existing baseline regressions observed | `--qa`, `--sec`, `--rust`, `--integration` all green on the final tree |

## 5. Non-goals verified absent

- No changes to `packages/mtmf-api` (frozen PR 15 contract).
- No `mtmf-client` implementation (PR 18).
- No observability framework (PR 19) or ATI integration (PR 20).
- No production issuer/root authentication or recovery.
- No Rust default/fallback in the HTTP path; PR 16 `BatchAuthorizer` (pure Python) only.
