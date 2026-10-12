# PR 17 — Amendment #3 attestation security matrix (AT-01…AT-14)

**Important:** because D2 is **not approved**, no trust-verification semantics
were changed. The table records what is verified **today** against the existing
whole-realm contract plus the deterministic tests added by this amendment.
Rows marked “D2” require the approved design.

Deterministic tests live in `tests/unit/authentication/test_attestation.py`
(production `canonical_manifest` + `BaselineConfigurationAttestor`, only the
Admin REST reader faked).

| ID | Scenario | Status | Evidence |
| --- | --- | --- | --- |
| AT-01 | Approved realm + approved client → attestation succeeds | PASS (unit) | `test_attestation_succeeds_on_matching_baseline` |
| AT-02 | Approved initializer adds an approved client → still succeeds | **BLOCKED (D2)** | reproduction in `pr17-amendment-3-attestation-diagnosis.md` shows current whole-realm mismatch |
| AT-03 | Unknown client → rejected | PASS (unit, current semantics) | `test_at03_unknown_extra_client_is_rejected` (extra client ⇒ drift) |
| AT-04 | Duplicate client identity / ambiguous result → rejected | PASS (unit, current semantics) | `test_at04_duplicate_client_identity_is_detected_as_drift`; explicit duplicate guard is D2 |
| AT-05 | Client enabled → disabled → next op fails | PASS (unit) + PASS (live) | `test_client_drift_is_detected`, live `baseline/client-enabled-false/restored` |
| AT-06 | Client flow/authentication type changed | PASS (unit) | `test_client_drift_is_detected[standardFlowEnabled]` |
| AT-07 | Audience mapper / effective scope changed | PASS (unit) | `test_scope_and_mapper_drift_is_detected`, `test_client_drift_is_detected[audience]` |
| AT-08 | Realm-wide relevant mapper/flow changed | PASS (unit, mappers) / **D2** (realm-wide settings) | `test_scope_and_mapper_drift_is_detected`; realm lifetime/flow projection is D2 |
| AT-09 | Admin REST outage after success → next op fails, no cache | PASS (unit) | `test_reader_error_and_transport_failure_fail_closed`, `test_attestation_never_reuses_a_prior_success` |
| AT-10 | Expected-client policy missing/malformed/duplicate | PASS (baseline missing/malformed) ; policy artifact is D2 | `test_missing_and_malformed_baseline_fail_closed` |
| AT-11 | Initializer re-run, matching state → same IDs/secret, no rewrite | PASS (real PostgreSQL + live Keycloak, single client) | `test_pr17_dev_initializer.py`, live re-run |
| AT-12 | Initializer re-run, drifted existing client → fails, no auto-repair | PARTIAL | initializer conflict test; explicit client-drift guard is D2 |
| AT-13 | Two approved clients independently verify; cross-client denied | PARTIAL | `test_at13_two_clients_are_independently_bound` (unit); live two-client V12 blocked by D2/manifest |
| AT-14 | User/service token mismatch → D1 fails | PASS (unit) + PASS (live) | unit H13; PR 14 live `test_dc07_*`; live V05 |

## Deterministic normalization properties

- `test_canonical_manifest_is_deterministic_and_sorted` (stable ordering/hash).
- `test_equivalent_order_is_accepted` (order-insensitive where safe).
- `test_attestation_never_reuses_a_prior_success` (fresh per operation).
- `test_missing_and_malformed_baseline_fail_closed`.

## Live Keycloak cases executed

- Fail-closed on client `enabled` mutation with restore (AT-05).
- Before/after initializer drift with field-level diff (AT-02/AT-03 diagnosis).
- PR 14 live drift/no-cache cases (AT-09) remain passing (22/22).

## Not executed (blocked)

AT-02 live success, AT-08 realm-wide settings, AT-12 explicit client-drift
guard, and AT-13 live two-client isolation require the approved D2 design and/or
the approved second client; they remain **BLOCKED**, not PASS.
