# PR 14 Amendment #1 — named acceptance traceability matrix

**Status: EVIDENCE TRACEABILITY — NOT MERGE AUTHORIZATION.**
Source requirements: the original PR 14 AUTH-01–AUTH-36 matrix and the D1-01–D1-10
scenarios in `PR14_AUTHENTICATION_SECURITY_DECISIONS.md` §14A. Statuses are
`PASS`, `PARTIAL`, `NOT EXECUTED`, `DEFERRED ROOT`, `BLOCKED`. `PASS` requires an
executed test that directly demonstrates the case; a unit test does not cover a
cross-layer/DB case. No case is marked PASS merely because a related test exists.

Commands (unless noted): `uv run --no-sync pytest tests/unit/authentication -q --no-cov`
and `uv run --no-sync pytest tests/integration/postgres -q --no-cov` with the
`.env` role configuration exported.

| ID | Requirement (faithful) | Scope | Test node / evidence | Status |
| --- | --- | --- | --- | --- |
| AUTH-01 | Valid client-credentials token, trusted issuer/audience, mapped active Application | non-root | `test_actor_context.py::test_happy_path_composes_actor_context`; `test_service_verifier.py::test_service_token_is_verified_and_classified` | PASS (unit); live full slice NOT EXECUTED |
| AUTH-02 | Valid user token, approved binding, active Identity/Principal/Tenant | non-root | `test_actor_context.py::test_happy_path_composes_actor_context`; `test_service_verifier.py::test_user_token_is_verified_and_classified` | PASS (unit); live full slice NOT EXECUTED |
| AUTH-03 | Missing service token | non-root | `test_actor_context.py::test_missing_service_token_is_rejected` | PASS |
| AUTH-04 | Missing user token | non-root | `test_actor_context.py::test_missing_user_token_is_rejected` | PASS |
| AUTH-05 | Caller-supplied Application/Identity/Principal UUID is not authority | non-root | No API accepts a caller UUID (by construction); no runtime route exists | NOT EXECUTED |
| AUTH-06 | Wrong issuer | non-root | `test_service_verifier.py::test_wrong_issuer_is_rejected` | PASS |
| AUTH-07 | Wrong audience / cross-token swap | non-root | `test_service_verifier.py::test_wrong_audience_is_rejected`; `test_actor_context.py::test_wrong_user_class_is_rejected` | PASS |
| AUTH-08 | Invalid signature, `none`, HS/RS confusion, wrong key type | non-root | `test_service_verifier.py::test_forged_signature_is_rejected`, `::test_none_and_symmetric_algorithms_are_rejected` | PASS |
| AUTH-09 | Expired / future `nbf` / future `iat` | non-root | `test_service_verifier.py::test_expired_token_is_rejected_with_zero_leeway`, `::test_future_issued_at_is_rejected`, `::test_future_not_before_is_rejected` | PASS |
| AUTH-10 | Missing required time or token-class claim | non-root | `test_service_verifier.py::test_missing_required_time_claims_are_rejected` (times); signed missing-`azp` (DC05) NOT EXECUTED | PARTIAL |
| AUTH-11 | Unknown `kid`, malformed JWKS, duplicate key ids | non-root | `test_service_verifier.py::test_unknown_kid_is_rejected`, `::test_duplicate_jwks_kid_is_rejected`; malformed-JWKS document not directly tested | PARTIAL |
| AUTH-12 | Legitimate JWKS key rollover | non-root | `test_service_verifier.py::test_jwks_key_rotation_refreshes_on_unknown_kid` | PASS |
| AUTH-13 | JWKS unavailable / timeout / stale unknown key | non-root | `test_service_verifier.py::test_jwks_transport_outage_fails_closed` | PASS |
| AUTH-14 | Untrusted `jku`/`x5u`/`jwk` | non-root | `test_service_verifier.py::test_untrusted_header_key_url_is_rejected` | PASS |
| AUTH-15 | Credential not registered / revoked / suspended Application | non-root | `test_actor_context.py::test_revoked_application_binding_is_rejected`; `test_postgres_authentication_bindings.py::test_pr14_binding02_revoked_binding_is_not_active` | PASS |
| AUTH-16 | Two credentials for one Application | non-root | Not directly tested | NOT EXECUTED |
| AUTH-17 | Same credential attempted for two Applications | non-root | Partial-unique active index; no direct test | NOT EXECUTED |
| AUTH-18 | Unknown user `(issuer,sub)` / email collision | non-root | `test_actor_context.py::test_revoked_subject_binding_is_rejected` | PASS |
| AUTH-19 | User binding revoked / Identity or Principal inactive/deleted | non-root | `test_actor_context.py::test_inactive_identity_is_rejected` | PASS |
| AUTH-20 | User lacks Tenant membership / Tenant inactive | non-root | `test_actor_context.py::test_missing_tenant_membership_is_rejected`, `::test_inactive_tenant_is_rejected` | PASS |
| AUTH-21 | Application not registered for the Tenant | non-root | `test_actor_context.py::test_missing_active_registration_is_rejected` | PASS |
| AUTH-22 | Registration but no active subscription | non-root | `test_actor_context.py::test_ineligible_subscription_is_rejected` | PASS |
| AUTH-23 | Service A + user token delegated to client B | non-root | `test_actor_context.py::test_cross_client_pair_is_rejected` | PASS |
| AUTH-24 | Two valid independent tokens, no delegation evidence | non-root | `test_actor_context.py::test_cross_client_pair_is_rejected` | PASS |
| AUTH-25 | SYSTEM/root Tenant selected | non-root | `test_actor_context.py::test_root_identity_is_rejected`; Tenant scope gate | PASS |
| AUTH-26 | Root external binding missing/insufficient | deferred root | Root path fails closed (`test_root_identity_is_rejected`); no root binding implemented | DEFERRED ROOT |
| AUTH-27 | Root binding mutation via runtime credential | deferred root | No runtime root-mutation grant exists | DEFERRED ROOT |
| AUTH-28 | Refresh/ID token offered as access token | non-root | `test_service_verifier.py::test_id_token_is_rejected_as_access_token`, `::test_refresh_token_is_rejected_as_access_token` | PASS |
| AUTH-29 | Concurrent credential/subject insert | non-root | Partial-unique index exists; no concurrency test | NOT EXECUTED |
| AUTH-30 | Terminal reactivation / immutable rewrite | non-root | `test_postgres_authentication_bindings.py::test_pr14_binding05_immutable_key_guard`; terminal reactivation not directly tested | PARTIAL |
| AUTH-31 | Runtime mutation / direct table access denied | non-root | `test_postgres_authentication_bindings.py::test_pr14_binding04_runtime_cannot_mutate_or_read_tables`; `test_runtime_privileges.py` | PASS |
| AUTH-32 | DB unavailable during resolution | non-root | Not directly tested (mapped to `INFRASTRUCTURE` in code) | NOT EXECUTED |
| AUTH-33 | Mapping revoked before next resolution | non-root | No stale-cache test | NOT EXECUTED |
| AUTH-34 | Different selected Tenant than membership/registration | non-root | `test_actor_context.py::test_other_tenant_without_membership_is_rejected` | PASS |
| AUTH-35 | Oversized/malformed/unsupported critical headers | non-root | `test_service_verifier.py::test_oversized_token_is_rejected`, `::test_malformed_base64_segment_is_rejected`, `::test_duplicate_payload_claim_is_rejected_before_verification`; `crit` not tested | PARTIAL |
| AUTH-36 | Token/secret not in exceptions or logs | non-root | No automated redaction test | NOT EXECUTED |
| D1-01 | Same-client verified tokens → accepted context | non-root | `test_actor_context.py::test_happy_path_composes_actor_context` | PASS (unit); live NOT EXECUTED |
| D1-02 | Different-client tokens rejected | non-root | `test_actor_context.py::test_cross_client_pair_is_rejected` | PASS |
| D1-03 | Unverified/unsupported client claim rejected | non-root | `test_service_verifier.py::test_untrusted_header_key_url_is_rejected`, signature/issuer tests | PASS |
| D1-04 | Missing/ambiguous client identity rejected | non-root | `test_service_verifier.py::test_duplicate_payload_claim_is_rejected_before_verification`; DC05 NOT EXECUTED | PARTIAL |
| D1-05 | Wrong token in slot; ID/refresh rejected | non-root | `test_actor_context.py::test_wrong_user_class_is_rejected`; ID/refresh tests | PASS |
| D1-06 | Wrong audience/issuer/signature/key/expired rejected | non-root | Verifier adversarial tests | PASS |
| D1-07 | Same client but inactive/absent binding/tenant/subscription | non-root | `test_actor_context.py` inactive/membership/subscription tests | PASS |
| D1-08 | Cross-Tenant actor context rejected | non-root | `test_actor_context.py::test_other_tenant_without_membership_is_rejected` | PASS |
| D1-09 | Caller UUID / service-signed assertion / exchange substitution | non-root | No runtime path accepts these; exchange not implemented | NOT EXECUTED |
| D1-10 | Clean fixture recreation reproduces results | non-root | G0-A historical manifest hash `9e9bb847…`; separate clean-recreate verified (see report §R12) | PASS (separately verified) |

**Root fail-closed evidence:** `test_actor_context.py::test_root_identity_is_rejected`
proves the canonical root Identity/Tenant/Principal mapping raises
`ROOT_FORBIDDEN`; no root authentication exists.

**Live trust-boundary evidence (shipped classes):** the shipped
`BaselineConfigurationAttestor`/`HttpAdminRestReader` were exercised against the
live pinned issuer: clean attestation succeeded, an injected `client_id` mapper
was detected as `attestation_drift`, and restoration re-attested successfully.
The full live-token + real-PostgreSQL D1 vertical slice (DC07/V01–V16) and the
issuer-signed missing-`azp` case (DC05) were **NOT EXECUTED**; see the report for
the precise blockers.
