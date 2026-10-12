# PR 17 — Amendment #4 attestation security matrix (AT01–AT18)

**D2 is PENDING; no trust semantics changed.** Rows that require the approved
design are BLOCKED. PASS rows were executed against the **current** verifier
(production `canonical_manifest` + `BaselineConfigurationAttestor`, only the
Admin REST reader faked for unit tests).

| ID | Case | Status | Evidence |
| --- | --- | --- | --- |
| AT01 | Approved realm + approved clients | PASS (unit) | `test_attestation_succeeds_on_matching_baseline` |
| AT02 | Initializer adds approved client; fresh attestation passes | **BLOCKED (D2)** | current whole-realm mismatch (diagnosis) |
| AT03 | Unapproved extra client → fail closed | PASS (current semantics) | `test_at03_unknown_extra_client_is_rejected` (extra client ⇒ drift) |
| AT04 | Duplicate/ambiguous client ID → fail closed | PASS (current semantics) | `test_at04_duplicate_client_identity_is_detected_as_drift`; explicit guard is D2 |
| AT05 | Disable approved client | PASS (unit + live) | `test_client_drift_is_detected`; live baseline/disable/restore |
| AT06 | Change grant/flow/client-auth type | PASS (unit) | `test_client_drift_is_detected[standardFlowEnabled]`; `clientAuthenticatorType` projection is D2 |
| AT07 | Change direct mapper/audience | PASS (unit) | `test_scope_and_mapper_drift_is_detected`, `test_client_drift_is_detected[audience]` |
| AT08 | Change inherited/default effective mapper/scope | **BLOCKED (D2)** | default/optional scope names are compared today, but effective inherited mappers are not separately proven |
| AT09 | Change relevant realm security setting | **BLOCKED (D2)** | realm representation not projected (baseline §3) |
| AT10 | Admin REST unavailable after success | PASS (unit) | `test_reader_error_and_transport_failure_fail_closed`, `test_attestation_never_reuses_a_prior_success` |
| AT11 | Malformed/missing/duplicate expected-client policy | PASS for missing/malformed baseline; duplicate policy is D2 | `test_missing_and_malformed_baseline_fail_closed` |
| AT12 | Repeat initializer unchanged | PASS (real PG + live, single client) | `test_pr17_dev_initializer.py`, live re-run |
| AT13 | Repeat initializer with drifted client | **BLOCKED (D2)** | explicit client-drift reconciliation is D2 |
| AT14 | Two approved independent clients | PARTIAL | `test_at13_two_clients_are_independently_bound` (unit); live two-client is D2 |
| AT15 | Cross-client service/user pairing | PASS | unit H13; PR 14 live `test_dc07_*`; live V05 fail-closed |
| AT16 | Unknown security-relevant realm field | **BLOCKED (D2)** | no realm-field projection |
| AT17 | Existing PR 14 drift vectors | PASS | `test_client_drift_is_detected`, `test_scope_and_mapper_drift_is_detected`, `test_attestation_never_reuses_a_prior_success` |
| AT18 | Token/log/error redaction | PASS | unit H21/H28; live V15 static envelopes; no policy detail on the wire |

## Fresh per-authentication check

`test_attestation_never_reuses_a_prior_success` proves a mutation after a
successful attestation causes the next `attest()` to fail with
`ATTESTATION_DRIFT` and that the reader is called again — i.e. no cross-request
positive cache. This satisfies the invariant even while the broader D2 design is
pending.

## Not PASS

AT02, AT08, AT09, AT13, AT14 (live), AT16 are BLOCKED/partial and are not
promoted to PASS.
