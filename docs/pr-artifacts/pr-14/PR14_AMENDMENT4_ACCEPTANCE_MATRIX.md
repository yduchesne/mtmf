# PR 14 Amendment #4 — final live security acceptance matrix

**Status: DEVELOPMENT-ONLY NON-ROOT LIVE ACCEPTANCE COMPLETE FOR THE CASES LISTED; root/production still deferred. MERGE REQUIRES HUMAN REVIEW.**
Authority: register §14J. This matrix supersedes prior matrix *statuses* only
where a case was newly executed live; historical evidence is preserved.

Live command (zero skips, authoritative):
`MTMF_PR14_LIVE=1 SSL_CERT_FILE=<dev-CA> uv run --no-sync pytest tests/integration/postgres/test_pr14_live_actor_context.py -q --no-cov`
→ **22 passed** (fixture pinned `sha256:27b3230f…`, real PostgreSQL 18).

Deterministic commands: `uv run --no-sync pytest tests/unit/authentication -q --no-cov` (61 PASS);
`uv run --no-sync pytest tests/integration/postgres/test_postgres_authentication_bindings.py -q --no-cov` (11 PASS).

## AUTH-01–36

| ID | Requirement | Live node (or other) | Status |
| --- | --- | --- | --- |
| AUTH-01 | Valid service token → mapped Application | `test_dc07_v01_positive_real_tokens_and_postgres` | PASS (live) |
| AUTH-02 | Valid user token → eligible actor | `test_dc07_v01_positive_real_tokens_and_postgres` | PASS (live) |
| AUTH-03 | Missing service token | `test_actor_context.py::test_missing_service_token_is_rejected` | PASS (unit) |
| AUTH-04 | Missing user token | `test_actor_context.py::test_missing_user_token_is_rejected` | PASS (unit) |
| AUTH-05 | Caller-supplied UUID is not authority | No API accepts a caller actor UUID (by construction); no HTTP route | NOT EXECUTED (by construction) |
| AUTH-06 | Wrong issuer | `test_service_verifier.py::test_wrong_issuer_is_rejected` | PASS (unit); live wrong-issuer token not issuable |
| AUTH-07 | Wrong audience / swap | `test_dc07_wrong_audience_rejected`, `test_dc07_v04_wrong_slot_tokens_rejected` | PASS (live) |
| AUTH-08 | Invalid signature / `none` / HS | `test_dc07_modified_signature_rejected`, `test_none_and_symmetric_algorithms_are_rejected` | PASS (live + unit) |
| AUTH-09 | Expired / future nbf / iat | `test_service_verifier.py::test_expired_token_is_rejected_with_zero_leeway`, `::test_future_*` | PASS (unit) |
| AUTH-10 | Missing time / class claim | `test_missing_required_time_claims_are_rejected`; `test_dc05_local_key_missing_azp_is_rejected_with_signature_proof` | PASS (unit); DC05-ISSUER NOT EXECUTED |
| AUTH-11 | Unknown/malformed/duplicate kid JWKS | `test_unknown_kid_is_rejected`, `test_duplicate_jwks_kid_is_rejected`, `test_malformed_jwks_is_rejected` | PASS (unit) |
| AUTH-12 | JWKS key rollover | `test_jwks_key_rotation_refreshes_on_unknown_kid` | PASS (unit) |
| AUTH-13 | JWKS outage/timeout | `test_jwks_transport_outage_fails_closed` | PASS (unit) |
| AUTH-14 | Untrusted `jku`/`x5u`/`jwk` | `test_untrusted_header_key_url_is_rejected` | PASS (unit) |
| AUTH-15 | Credential not registered/revoked | `test_dc07_v07_missing_service_binding_rejected` | PASS (live) |
| AUTH-16 | Two credentials → one Application | `test_pr14_binding08_two_credentials_map_to_one_application` | PASS (PG) |
| AUTH-17 | Same key → two Applications rejected | `test_pr14_binding09_same_key_cannot_map_to_two_applications` | PASS (PG) |
| AUTH-18 | Unknown subject / email collision | `test_dc07_v08_missing_subject_binding_rejected` | PASS (live) |
| AUTH-19 | Inactive Identity / Principal | `test_dc07_inactive_identity_rejected`, `test_dc07_inactive_principal_rejected` | PASS (live) |
| AUTH-20 | Missing membership / inactive Tenant | `test_dc07_missing_membership_rejected`, `test_dc07_inactive_tenant_rejected` | PASS (live) |
| AUTH-21 | Application not registered | `test_dc07_inactive_registration_rejected` | PASS (live) |
| AUTH-22 | No active subscription | `test_dc07_inactive_subscription_rejected` | PASS (live) |
| AUTH-23 | Service A + user delegated to B | `test_dc07_v05_cross_client_rejected` | PASS (live) |
| AUTH-24 | Unrelated valid tokens | `test_dc07_v05_cross_client_rejected` | PASS (live) |
| AUTH-25 | SYSTEM/root Tenant | `test_dc07_root_tenant_scope_rejected` | PASS (live) |
| AUTH-26 | Root external binding | DEFERRED ROOT (root fails closed; AUTH-25 + unit root test) | DEFERRED ROOT |
| AUTH-27 | Root binding mutation via runtime | No runtime root mutation grant | DEFERRED ROOT |
| AUTH-28 | Refresh/ID token as access token | `test_id_token_...`, `test_refresh_token_...` | PASS (unit) |
| AUTH-29 | Concurrent binding insert | `test_pr14_binding11_concurrent_same_key_has_one_winner` | PASS (PG) |
| AUTH-30 | Terminal reactivation / immutable rewrite | `test_pr14_binding10_terminal_revocation_cannot_reactivate`, `test_pr14_binding05_immutable_key_guard` | PASS (PG) |
| AUTH-31 | Runtime table/mutation denied | `test_pr14_binding04_runtime_cannot_mutate_or_read_tables`; `test_runtime_privileges.py` | PASS (PG) |
| AUTH-32 | DB unavailable | `test_dc07_postgres_outage_is_typed_infrastructure_failure` | PASS (live) |
| AUTH-33 | Revocation before next resolution | `test_dc07_binding_revocation_freshness` | PASS (live) |
| AUTH-34 | Different Tenant than membership | `test_dc07_cross_tenant_rejected` | PASS (live) |
| AUTH-35 | Oversize/malformed/critical header | `test_oversized_token_is_rejected`, `test_malformed_base64_segment_is_rejected`, `test_unsupported_critical_header_is_rejected` | PASS (unit) |
| AUTH-36 | No token/secret in errors/logs | `test_tokens_are_never_exposed_in_errors_or_repr` | PASS (unit) |

## D1-01–10

| ID | Requirement | Node | Status |
| --- | --- | --- | --- |
| D1-01 | Same-client verified → actor | `test_dc07_v01_positive_real_tokens_and_postgres` | PASS (live) |
| D1-02 | Different clients rejected | `test_dc07_v05_cross_client_rejected` | PASS (live) |
| D1-03 | Unverified/unsupported client claim | verifier signature/issuer/URL unit tests | PASS (unit) |
| D1-04 | Missing/ambiguous client identity | `test_dc05_local_key_...`, `test_duplicate_payload_claim_...` | PASS (local-key); DC05-ISSUER NOT EXECUTED |
| D1-05 | Wrong slot / ID / refresh | `test_dc07_v04_wrong_slot_tokens_rejected`; ID/refresh unit | PASS (live + unit) |
| D1-06 | Wrong audience/issuer/signature/key/expired | `test_dc07_wrong_audience_rejected`, `test_dc07_modified_signature_rejected`; unit | PASS (live + unit) |
| D1-07 | Inactive/absent binding/tenant/subscription | live inactive/missing-binding cases | PASS (live) |
| D1-08 | Cross-Tenant rejected | `test_dc07_cross_tenant_rejected` | PASS (live) |
| D1-09 | Caller UUID / assertion / exchange substitution | No runtime path; exchange not implemented | NOT EXECUTED (by construction) |
| D1-10 | Clean recreate reproducible | Amendment #4 clean `down -v` + setup → hash `9e9bb847…` | PASS (live) |

## V01–V16

Prior plans used conflicting V definitions. The Amendment #4 live coverage
executed (by case name) is: positive same-client; wrong slot/class;
cross-client; missing/revoked service and subject bindings; inactive
Identity/Principal/Tenant/Application; missing membership; cross-Tenant;
inactive/missing registration and subscription; root Tenant scope; repeated
resolution stability; binding revocation freshness; Admin REST outage
(bad/missing credential and manifest); wrong audience; modified signature; and
PostgreSQL outage. Cases not reachable in the approved fixture (wrong-issuer
token) remain NOT EXECUTED. No historical identifier was renamed or weakened.

## DC05 split

- DC05-LOCAL-KEY PASS (isolated test key; signature proven; shipped verifier rejects missing `azp`).
- DC05-ISSUER NOT EXECUTED (Keycloak sets typed `azp` unconditionally).
