# PR 14 Amendment #3 — shared-audience D1 acceptance matrix (delta)

**Status: PARTIAL — live positive and key negatives executed; remaining live V/AUTH cases not executed.**
This is a delta over `docs/PR14_AMENDMENT2_ACCEPTANCE_MATRIX.md` (which is a
delta over Amendment #1). Unlisted rows keep their prior status; no historical
status is rewritten. Authority: register §14J.

Command for the live rows: `MTMF_PR14_LIVE=1 SSL_CERT_FILE=<dev CA> uv run
--no-sync pytest tests/integration/postgres/test_pr14_live_actor_context.py -q
--no-cov` with the real PostgreSQL role env exported. Result: 6 passed.

| ID / case | Requirement | Layer | Test node | Status |
| --- | --- | --- | --- | --- |
| DC07-positive | Genuine same-client tokens → shipped composition → real PostgreSQL actor | Live full | `test_pr14_live_actor_context.py::test_dc07_v01_positive_real_tokens_and_postgres` | PASS |
| DC07 slot confusion | Service token in user slot / user token in service slot rejected | Live full | `::test_dc07_v04_wrong_slot_tokens_rejected` | PASS |
| DC07 cross-client | Independently signed tokens from different clients rejected | Live full | `::test_dc07_v05_cross_client_rejected` | PASS |
| DC07 missing service binding | Revoked credential binding → no Application | Live full | `::test_dc07_v07_missing_service_binding_rejected` | PASS |
| DC07 missing subject binding | Revoked subject binding → no Identity | Live full | `::test_dc07_v08_missing_subject_binding_rejected` | PASS |
| DC07 attestation freshness | Per-resolve fresh attestation; mapper drift blocks; restore succeeds | Live full | `::test_dc07_v15_mapper_drift_blocks_and_restores` | PASS |
| Shared-audience config | Equal audiences rejected by default; accepted only under explicit gated profile | Unit | `test_config.py::test_equal_audiences_are_rejected_without_explicit_shared_profile`, `::test_equal_audiences_are_allowed_only_with_the_shared_profile_flag` | PASS |
| Inactive identity/principal/tenant, membership, registration/subscription | Fail closed | Live full | NOT EXECUTED live (unit: `test_actor_context.py`) | PARTIAL |
| Canonical root | Root Identity/Tenant/Principal rejected | Live full | NOT EXECUTED live (unit: `test_root_identity_is_rejected`) | PARTIAL |
| Admin REST outage / invalid credential / missing baseline | Fail closed | Live full | NOT EXECUTED live (unit: `test_attestation.py`) | PARTIAL |
| JWKS/verifier outage; wrong issuer/signature/audience | Fail closed | Live full | NOT EXECUTED live (unit: `test_service_verifier.py`) | PARTIAL |
| Real PG outage; revocation freshness | Typed fail-closed | Live full | NOT EXECUTED live (unit: `FailingSpi`, revocation freshness) | PARTIAL |
| Amendment #3 clean recreate | Reproducible baseline after any change | Fixture | Fixture/baseline unchanged; historical G0-A recreate retained | NOT EXECUTED |
| DC05-ISSUER | Issuer-signed missing `azp` rejected | Keycloak | Issuer sets `azp` unconditionally | NOT EXECUTED (issuer limitation) |
| DC05-LOCAL-KEY | Locally signed missing `azp` rejected with signature proof | Verifier | `test_service_verifier.py::test_dc05_local_key_missing_azp_is_rejected_with_signature_proof` | PASS |
| AUTH-26/27 | Root authenticates / runtime root mutation | Root | DEFERRED ROOT; root fails closed (`test_root_identity_is_rejected`) | DEFERRED ROOT |

## Preserved

- Amendment #1 and #2 matrices and all their PASS rows remain authoritative for
  the layers they cover; the live DC07 gap they record is now partially closed
  for the positive and key negative cases above.
- Historical G0-T09 FAIL, R06 and R12 `NOT EXECUTED` artifacts are unmodified.
- DC05-ISSUER remains NOT EXECUTED and is never conflated with DC05-LOCAL-KEY.

## Remaining before merge

Each `PARTIAL`/`NOT EXECUTED` live row above must either be executed in the live
topology (real Keycloak tokens + real PostgreSQL) or explicitly excepted by the
human reviewer. No inferred PASS is asserted.
