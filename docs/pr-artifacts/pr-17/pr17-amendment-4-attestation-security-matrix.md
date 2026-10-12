# PR 17 — Amendment #4 attestation security matrix (AT01–AT18)

D2 is **APPROVED** (2026-10-12) and implemented. Rows were executed against the
production `canonical_manifest`/`canonical_client_projection`/
`BaselineConfigurationAttestor` (unit, deterministic) and the live Keycloak
fixture (integration).

| ID | Case | Status | Evidence |
| --- | --- | --- | --- |
| AT01 | Approved realm + approved clients | PASS | `test_realm_attestation_succeeds_on_matching_baseline`, `test_attest_client_succeeds_for_approved_client` |
| AT02 | Initializer adds `mtmf-sample-app` matching approved policy; fresh attestation passes | PASS (live) | initializer run + `attest_client` OK; live PR17 suites |
| AT03 | Unapproved client → fail closed | PASS | unit `test_attest_client_rejects_unapproved_client`; live `test_cl06_unapproved_client_is_rejected` |
| AT04 | Duplicate/ambiguous client id → fail closed | PASS | `test_attest_client_rejects_duplicate_client_id` |
| AT05 | Disable approved client → next auth fails | PASS | `test_attest_client_detects_security_field_drift[enabled]`; live initializer drift fails closed |
| AT06 | Change grant/flow/client-auth type | PASS | `test_attest_client_detects_security_field_drift[standardFlowEnabled/clientAuthenticatorType/publicClient]` |
| AT07 | Change direct mapper/audience | PASS | `test_attest_client_detects_security_field_drift[...]`, `test_client_scope_mapper_drift_is_detected` |
| AT08 | Change inherited/default effective mapper/scope | PASS | client projection includes default/optional scope names; realm projection includes all `clientScopes` mappers (`test_client_scope_mapper_drift_is_detected`) |
| AT09 | Change relevant realm security setting | PASS | `test_realm_security_drift_is_detected` (6 realms fields) |
| AT10 | Admin REST unavailable after success → fail, no cache | PASS | `test_reader_transport_failure_fail_closed`, `test_attestation_never_reuses_a_prior_success` |
| AT11 | Malformed/missing/duplicate expected-client policy | PASS | `test_policy_validation_fails_closed` |
| AT12 | Repeat initializer unchanged → same ids/secret, no rewrite | PASS (live) | initializer idempotent re-run; `test_pr17_dev_initializer.py` |
| AT13 | Repeat initializer with drifted client → fail, no auto-repair | PASS (live) | demonstrated: `client 'mtmf-sample-app' drifted … no automatic repair` |
| AT14 | Two approved independent clients | PASS | unit `test_two_clients_are_independently_bound`; live CL01–CL07 |
| AT15 | Cross-client service/user pairing | PASS (live) | `test_cl03_client_a_service_with_client_b_user_is_rejected`, `test_cl04_...` |
| AT16 | Unknown security-relevant realm field | PARTIAL | the projection is a documented curated 18-field allowlist; a new realm field not on the list is not compared (recorded residual) |
| AT17 | Existing PR 14 drift vectors | PASS (live) | PR 14 live actor suite 22/22 |
| AT18 | Token/log/error redaction | PASS | static PR 15 envelopes; live no-store; no policy detail on the wire |

## Fresh per-authentication check

`test_attestation_never_reuses_a_prior_success` and the live
`test_v07_no_positive_attestation_cache` prove a mutation after a success makes
the next operation fail closed with a fresh read.

## Residual

AT16: the realm projection is an explicit allowlist; expanding it requires a
reviewed field-list update. No case is marked PASS from absence of a check.
