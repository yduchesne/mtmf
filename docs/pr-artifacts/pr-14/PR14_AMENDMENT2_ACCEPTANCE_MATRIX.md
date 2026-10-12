# PR 14 Amendment #2 — acceptance matrix (delta over Amendment #1)

**Status: PARTIAL — DC07/V01–V16 blocked.** This document is a crosswalk over
`docs/PR14_AMENDMENT1_ACCEPTANCE_MATRIX.md`; Amendment #1 rows not listed here
keep their recorded status. No historical status is rewritten. New rows use
Amendment #2 identifiers where the plan defines them; the Amendment #1 V01–V16
identifiers are preserved by crosswalk.

Commands: `uv run --no-sync pytest tests/unit/authentication -q --no-cov`;
`uv run --no-sync pytest tests/integration/postgres -q --no-cov` with `.env`
roles exported.

## Statuses changed or added in Amendment #2

| ID | Requirement | Layer | Test node / evidence | Status |
| --- | --- | --- | --- | --- |
| DC05-ISSUER | Issuer-signed user token missing `azp` rejected | Keycloak | Issuer sets typed `azp` unconditionally; no supported mapper omits it | NOT EXECUTED (issuer limitation) |
| DC05-LOCAL-KEY | Locally RS256-signed missing-`azp` user token rejected by the shipped verifier, with signature proof | Verifier | `test_service_verifier.py::test_dc05_local_key_missing_azp_is_rejected_with_signature_proof`, `::test_dc05_local_key_negative_controls` | PASS |
| DC07 | Real same-client tokens → shipped composition → real PostgreSQL actor | Full | Blocked: same-client distinct audiences impossible on pinned Keycloak (Amendment #2 report §2) | NOT EXECUTED (BLOCKED) |
| V01–V16 (Amd#2 table) | Live positive and negative actor cases | Full | Same blocker as DC07 | NOT EXECUTED (BLOCKED) |
| AUTH-10 / D1-04 | Missing/ambiguous class claim | Verifier | DC05-LOCAL-KEY + `::test_duplicate_payload_claim_is_rejected_before_verification` | PARTIAL (local-key PASS; issuer NOT EXECUTED) |
| AUTH-11 | Malformed JWKS document, duplicate or unknown `kid` | Verifier | `::test_malformed_jwks_is_rejected`, `::test_duplicate_jwks_kid_is_rejected`, `::test_unknown_kid_is_rejected` | PASS |
| AUTH-16 | Two credentials for one Application | PostgreSQL | `test_postgres_authentication_bindings.py::test_pr14_binding08_two_credentials_map_to_one_application` | PASS |
| AUTH-17 | Same key cannot actively map to two Applications | PostgreSQL | `::test_pr14_binding09_same_key_cannot_map_to_two_applications` | PASS |
| AUTH-29 | Concurrent same-key insert: one winner | PostgreSQL | `::test_pr14_binding11_concurrent_same_key_has_one_winner` | PASS |
| AUTH-30 | Terminal revocation / immutable rewrite | PostgreSQL | `::test_pr14_binding10_terminal_revocation_cannot_reactivate`, `::test_pr14_binding05_immutable_key_guard` | PASS |
| AUTH-32 | DB unavailable during resolution | Actor + SPI | `test_actor_context.py::test_database_unavailable_is_typed_infrastructure_failure` | PASS (unit; no live PG outage run) |
| AUTH-33 | Revocation before next resolution | Actor | `test_actor_context.py::test_revoked_binding_is_not_reused_on_next_resolution` | PASS (unit) |
| AUTH-35 | Unsupported critical header / malformed / oversized | Verifier | `::test_unsupported_critical_header_is_rejected`, `::test_malformed_base64_segment_is_rejected`, `::test_oversized_token_is_rejected` | PASS |
| AUTH-36 | No token/secret in errors or repr | Verifier | `::test_tokens_are_never_exposed_in_errors_or_repr` | PASS |
| D1-10 | Clean fixture recreation + baseline consistency | Fixture | Historical G0-A recreate (hash `9e9bb847…`) retained; Amendment #2 experiment did not change the baseline | PARTIAL (live re-run NOT EXECUTED) |

## Preserved from Amendment #1 (unchanged)

- AUTH-01–09, 12–15, 18–25, 28, 31, 34 and D1-01–09 keep their Amendment #1
  statuses (largely PASS at unit/integration with live DC07 gaps).
- **AUTH-26/27:** DEFERRED ROOT; root fails closed
  (`test_actor_context.py::test_root_identity_is_rejected`).
- Historical G0-T09 FAIL, R06 and R12 `NOT EXECUTED` artifacts unmodified.

## Blocker crosswalk

The Amendment #2 plan's V01–V16 execution table maps onto the Amendment #1
original V01–V16 meanings; because the canonical live slice is blocked, no
original identifier is renamed or weakened. All remain NOT EXECUTED for the
live-token/real-PostgreSQL path.
