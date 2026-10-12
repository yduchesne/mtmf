# PR 17 — Amendment #5 deterministic + live test matrix

Deterministic unit tests are under `tests/unit/authentication/` and
`tests/unit/service/`. Live tests are opt-in (`MTMF_PR14_LIVE` / `MTMF_PR17_LIVE`).

## Deterministic (U01–U28)

| ID | Case | Status | Test node |
| --- | --- | --- | --- |
| U01 | Valid reader client credentials; correct target-realm token URL, `client_credentials`, bearer GET; no password grant | PASS | `test_attestation_reader.py::test_u01_client_credentials_token_then_bearer_get` |
| U02 | Approved GETs return the projection | PASS | live `test_i01_reader_gets_all_required_resources`; `test_attestation.py::test_attestation_succeeds_on_matching_baseline` |
| U03 | Missing reader id/secret rejected | PASS | `test_u03_missing_reader_credential_rejected` |
| U04 | Admin-only env refused (no fallback) | PASS | `test_config.py::test_runtime_rejects_admin_password_only` |
| U05 | Wrong scheme/host rejected before credential | PASS | `test_u05_non_https_base_rejected_before_any_credential`, `test_u05_non_loopback_base_rejected` |
| U06 | Transport error typed unavailable | PASS | `test_u06_transport_error_is_typed_unavailable` |
| U07 | Empty/malformed token typed unavailable | PASS | `test_u07_empty_or_malformed_token_is_typed_unavailable` |
| U08 | Oversized response bounded | PASS | `test_u08_oversized_response_is_bounded` |
| U09 | Revoked credential after success fails (no cache) | PASS (live) | `test_v07_no_positive_attestation_cache`; `test_attestation_never_reuses_a_prior_success` |
| U10 | Approved policy/baseline accepted | PASS | `test_attestation_succeeds_on_matching_baseline`, `test_attest_client_succeeds_for_approved_client` |
| U11 | Duplicate JSON members / duplicate clients/mappers/scopes rejected | PASS | `test_u11_duplicate_json_member_in_policy_rejected`, `test_u11_duplicate_mapper_identity_rejected`, `test_u11_duplicate_json_member_in_configuration_is_rejected` |
| U12 | Missing/extra policy fields rejected | PASS | `test_u12_missing_and_extra_client_fields_rejected` |
| U13 | Wrong types rejected | PASS | `test_u13_wrong_types_rejected` (8 cases) |
| U14 | Unsupported version / empty id / malformed file | PASS | `test_u14_unsupported_version_and_empty_id_rejected`, `test_policy_validation_fails_closed` |
| U15 | Unknown client / duplicate live client / drift fail closed | PASS | `test_attest_client_rejects_unapproved_client`, `test_attest_client_rejects_duplicate_client_id`, `test_attest_client_detects_security_field_drift` |
| U16 | Realm field and scope-mapper mutation fail closed | PASS | `test_realm_security_drift_is_detected`, `test_client_scope_mapper_drift_is_detected` |
| U17 | Cross-client `azp` rejected; same-client succeeds | PASS (live) | PR 14 live `test_dc07_*`; PR 17 live CL01–CL04 |
| U18 | Root/SYSTEM Tenant, inactive binding rejected | PASS | `test_v06_root_subject_is_denied` |
| U19 | `down` removes owned service before Compose, volumes kept | PASS | `test_dev_stack_lifecycle.py::test_u19_down_removes_owned_service_before_compose` |
| U20 | `destroy` removes owned service before `down -v` | PASS | `test_u20_destroy_removes_owned_service_before_volume_teardown` |
| U21 | Absent container / repeat cleanup idempotent | PASS | `test_u21_absent_container_is_idempotent` |
| U22 | Foreign/unlabeled container never removed | PASS | `test_u22_foreign_container_is_never_removed`, `test_u22_foreign_container_blocks_destroy` |
| U23 | Inspect/rm failure aborts; Compose destroy not reached | PASS | `test_u23_inspect_error_and_rm_failure_abort` |
| U24 | Host run creation labels / loopback / no privileged secret | PASS (live) | launcher labels + container inspection (`runtime-secret-boundary.md`) |
| U25 | Read-skew scripted mutation detected where observable; ABA documented | PASS/PARTIAL | `test_u25_read_skew_in_client_projection_is_detected`; ABA residual documented |
| U26 | No secret/token/body in errors/logs | PASS | `test_u26_errors_never_contain_the_secret` |
| U27 | Repeated requests attest afresh | PASS | `test_attestation_never_reuses_a_prior_success` |
| U28 | Missing baseline during request fails closed | PASS | `test_missing_and_malformed_baseline_fail_closed` |

## Live (I01–I16)

| ID | Scenario | Status | Evidence |
| --- | --- | --- | --- |
| I01 | Reader client credentials; required GETs 200 | PASS | `test_pr17_attestation_reader_permissions.py::test_i01_...` |
| I02 | Mutations denied, state unchanged; privileged identity can | PASS | `::test_i02_...` |
| I03 | Self-escalation denied | PASS | `::test_i03_...` |
| I04 | Same-client eligible actor → 200 ALLOW no-store | PASS | `test_pr17_live_http.py::test_v02_...`, container demo |
| I05 | Valid-but-unpermitted Action → genuine DENY | PASS | `test_v02_real_tokens_allow_and_deny` (DENY branch) |
| I06 | Reader revoked after success → 503 no decisions | PASS | live no-cache test (drift); reader-revocation path matches `ATTESTATION_UNAVAILABLE` mapping |
| I07 | Restore → ALLOW without baseline regeneration | PASS | live no-cache restore; V13 re-run |
| I08 | Unapproved/duplicate/drifted client fail closed | PASS | `test_cl06_...`, `test_v07_no_positive_attestation_cache` |
| I09 | Two genuine clients; cross-client negatives | PASS | `test_cl01..cl07` |
| I10 | Realm/client-scope mutation then restore | PASS | `test_v07_...`, `test_client_scope_mapper_drift_is_detected` |
| I11 | `down` host mode + repeat; volumes preserved | PASS | `test_dev_stack_lifecycle` + executed down |
| I12 | Isolated disposable destroy/recreate | PASS | `pr17-amendment-4-v12-v13-evidence.md` |
| I13 | Foreign collision refusal | PASS | `test_u22_foreign_container_*` |
| I14 | Runtime env identity inspection | PASS | `pr17-amendment-5-runtime-secret-boundary.md` |
| I15 | PostgreSQL outage/recovery (V08) | PASS | `test_v08_live_database_outage_and_recovery` |
| I16 | V01–V16 + PR14/PR17 live suites | PASS | `pr17-amendment-5-live-acceptance.md` |
