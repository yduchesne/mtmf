# PR 17-B Creation-Provenance Test Matrix

**PR:** PR 17-B — strict created-resource provenance follow-up
**Baseline:** `docs/pr-artifacts/pr-17-b/PR17B_CREATION_PROVENANCE_BASELINE.md`
**Starting tip:** `f84cadd371a3f889fe79fd98464908b3a88b4225`
**Amended code tip:** `acddeb3f3c8caabc631ab577729df0fb236fd0f5`

Deterministic unit tests extend `tests/unit/service/test_pr17b_development_user.py`
and `tests/unit/service/test_pr17b_initialize_script.py` using the existing fake
transport. Live tests extend `tests/integration/postgres/test_pr17b_live_acceptance.py`
against real Keycloak/PostgreSQL and the loopback test fault proxy.

## PV01–PV20

| ID | Status | Executable test(s) | Result |
| --- | --- | --- | --- |
| PV01 | PASS | `test_pv01_valid_location_is_accepted`; live `test_pv_live_valid_location_via_proxy_succeeds` | Valid same-origin `/admin/realms/<realm>/users/<id>` accepted; exactly `GET, POST, GET`. |
| PV02 | PASS | `test_pv02_pv10_invalid_locations_fail_closed[None]` | Missing `Location` fails closed. |
| PV03 | PASS | same, `["", "   "]` | Empty/whitespace fails closed. |
| PV04 | PASS | same, `.../users` | Collection URL fails closed. |
| PV05 | PASS | same, `other-realm`; live `test_pv_live_wrong_realm_location_fails_closed` | Wrong realm fails closed (real Keycloak committed; no MTMF state). |
| PV06 | PASS | same, `/groups/...`, `/users/<id>/extra` | Wrong resource / extra segment fails closed. |
| PV07 | PASS | same, `.../users/other-id`; `test_sh06_success_with_mismatched_location_is_rejected`; `test_pv19_parser_does_not_fabricate_an_id` | Correct path but different id fails closed. |
| PV08 | PASS | same, `?x=1`, `#frag` | Query/fragment fails closed. |
| PV09 | PASS | same, foreign origin, `http://...`, protocol-relative `//host/...` | Foreign origin / scheme / protocol-relative fails closed. |
| PV10 | PASS | same, `user:pass@`, `:notaport`, `%2F`, `%2e%2e`, `;x=1`, trailing `\n` | Embedded credentials / malformed port / encoded separator / traversal / params / control chars fail closed. |
| PV11 | PASS | `test_pv11_assertion_does_not_override_invalid_location` | Matching `MTMF_DEV_USER_SUBJECT` cannot bypass an invalid `Location` on `CREATED`. |
| PV12 | PASS | `test_pv12_valid_location_but_mismatched_assertion_fails` | Valid `Location` but mismatched assertion fails closed. |
| PV13 | PASS | `test_pv13_preexisting_account_is_reused_read_only`; `test_u04`, `test_u22` | Pre-existing account reused read-only with only a `GET`; no POST/password read. |
| PV14 | PASS | `test_pv14_conflict_without_assertion_fails_then_reuses`; live `test_i12` | `409` without assertion fails closed; subsequent run reuses. |
| PV15 | PASS | `test_pv15_timeout_without_assertion_fails_then_reuses`; live `test_i15a` | Lost response fails closed with one POST; subsequent run reuses. |
| PV16 | PASS | `test_pv16_definite_rejection_with_later_matching_account_fails`; `test_sh04`, `test_sh05` | Definite 4xx fails closed even with a later matching account; only `GET, POST`. |
| PV17 | PASS | `test_pv17_valid_location_but_drifted_lookup_fails[disabled/federated/service/email]` | Valid `Location` but invalid lookup account fails closed. |
| PV18 | PASS | `test_pv18_valid_location_but_ambiguous_lookup_fails` | Valid `Location` but ambiguous lookup fails closed. |
| PV19 | PASS | `test_pv19_create_user_returns_the_real_location_header`, `test_pv19_create_user_returns_none_without_a_location`; live `test_pv_live_real_location_shape` | The concrete transport returns the exact real `Location` header (or `None`), not a fabricated id; real Keycloak returns `201` + `/admin/realms/<realm>/users/<id>`. |
| PV20 | PASS | `test_pv20_provenance_failure_writes_no_mtmf_state`; live `test_pv_live_stripped_location_fails_closed_then_reconciles` | A provenance failure constructs no bootstrap and writes no MTMF state; the real Keycloak account remains and the rerun reuses it. |

## Preservation

- **I12** rerun live: PASS (bounded loser failure + idempotent retry).
- **I15a/I15b/I15c** rerun live: PASS.
- **SH16** rerun live: PASS (unverified-email OIDC login).
- **I01–I20** rerun live: PASS (65-test live matrix).
- SH01–SH15 unit assertions preserved (no weakening).

## Counts

| Suite | Tests |
| --- | --- |
| `test_pr17b_development_user.py` | 92 (32 PV-named) |
| `test_pr17b_initialize_script.py` | 15 |
| `test_pr17b_live_acceptance.py` | 13 (live) |
| `test_pr17b_compose_isolation.py` | 1 (live) |
| Full unit suite (`--qa`) | 1913 passed, coverage 90.75% |
| Full live matrix | 65 passed |
