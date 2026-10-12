# PR 14 Amendment #3 — shared-audience D1 acceptance report

**Status: LIVE D1 SLICE EXECUTED (core positive + key negatives); FULL V01–V16 NOT COMPLETE — MERGE NOT RECOMMENDED.**
Branch `dev/service-auth`. Architecture authority: register §14J. This amendment
resolved Amendment #2's audience blocker without changing D1's same-client model:
the shared audience is a recipient check only; grant class is the freshly
attested signed `client_id`/`azp` predicate.

## 1. Baseline and changes

| Item | Value |
| --- | --- |
| Refreshed `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Reconciled base | `99d40daa2e4e0545e6f7d3f875d26f7d64c33d6b` |
| Final commit | the commit that adds this report |
| Pinned issuer | `quay.io/keycloak/keycloak:26.8.0-1`, digest `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Reviewed baseline | `dev/keycloak/expected-config-manifest.json`, canonical hash `9e9bb847e35060b2aab18c876d52c23648c137668c08fa6766c69a30dbc6fed5` — **unchanged** (no fixture/baseline edit was needed) |

**Changed:** `packages/mtmf-service/.../config.py` adds a development-only,
explicitly gated `allow_shared_audience` field (equal audiences remain rejected
by default); `tests/unit/authentication/test_config.py` (new); the live harness
`tests/integration/postgres/test_pr14_live_actor_context.py` (new, opt-in);
Amendment #3 report/matrix; status-only gate/roadmap notes. No schema, migration,
grant, route or root change.

## 2. Fixture / class predicate

- The existing `mtmf-evidence-same-client` client issues both client-credentials
  and auth-code+PKCE tokens with the single configured audience
  `mtmf-same-client-api`; no grant-specific or custom mappers were added.
- Sanitized verified claims: both tokens RS256, `iss` = pinned issuer,
  `aud` includes `mtmf-same-client-api`, `typ=Bearer`, equal `azp`
  (`mtmf-evidence-same-client`); the **service** token carries `client_id == azp`;
  the **user** token has no `client_id` and has `sub`. Swapped slots are rejected
  by the class predicate even though the audience matches.
- Malicious `client_id` mapper injection is detected as `attestation_drift` and
  the resolver fails before token acceptance; removal restores success.

## 3. Live DC07 vertical slice

Harness: `tests/integration/postgres/test_pr14_live_actor_context.py`, run as
`MTMF_PR14_LIVE=1 SSL_CERT_FILE=<dev CA> uv run --no-sync pytest
tests/integration/postgres/test_pr14_live_actor_context.py -q --no-cov`, with the
real PostgreSQL role topology exported. Result: **6 passed** (no skips).

| Node | Covers | Result |
| --- | --- | --- |
| `test_dc07_v01_positive_real_tokens_and_postgres` | Genuine same-client service+user tokens → `build_actor_context_service` → real `PostgresMtmfSpi`/UoW/stored functions; exact Application/Identity/Principal/Tenant | PASS |
| `test_dc07_v04_wrong_slot_tokens_rejected` | Service token in user slot and user token in service slot → `WRONG_TOKEN_CLASS` | PASS |
| `test_dc07_v05_cross_client_rejected` | Valid independently signed tokens from different clients → `CROSS_CLIENT` | PASS |
| `test_dc07_v07_missing_service_binding_rejected` | Revoked service credential binding → `UNKNOWN_APPLICATION` | PASS |
| `test_dc07_v08_missing_subject_binding_rejected` | Revoked subject binding → `UNKNOWN_SUBJECT` | PASS |
| `test_dc07_v15_mapper_drift_blocks_and_restores` | Fresh per-resolve attestation; injected `client_id` mapper → `ATTESTATION_DRIFT`; restored → success | PASS |

No fake SPI/verifier/attestor was used; every call uses the shipped composition
and real PostgreSQL. No transaction spans Keycloak I/O (attestation/verification
complete before the UoW opens).

## 4. V case coverage

The V01–V16 identifiers have conflicting definitions across the preceding
amendment plans; the executed coverage is reported by case name rather than
renaming any historical ID.

| Coverage | Status |
| --- | --- |
| Positive same-client actor; repeated resolve stable | PASS (`v01`) |
| Wrong slot/class (service↔user) | PASS (`v04`) |
| Cross-client | PASS (`v05`) |
| Invalid binding (service/subject) | PASS (`v07`, `v08`) |
| Trust boundary: mapper drift + restore | PASS (`v15`) |
| Inactive Identity/Principal; inactive Tenant; missing membership; cross-Tenant | NOT EXECUTED (live); unit-covered in `test_actor_context.py` |
| Missing/inactive Application registration/subscription | NOT EXECUTED (live); unit-covered |
| Canonical root selected | NOT EXECUTED (live); unit-covered (`test_root_identity_is_rejected`) |
| Admin REST outage / invalid credential / missing baseline | NOT EXECUTED (live); `test_attestation.py` unit `ATTESTATION_UNAVAILABLE` |
| JWKS/verifier outage; wrong issuer/signature/audience | NOT EXECUTED (live); unit-covered |
| Real PG outage; revocation between resolves | NOT EXECUTED (live); unit-covered (`FailingSpi`, revocation freshness) |
| Clean `down -v` recreate for Amendment #3 | NOT EXECUTED (fixture not changed; historical G0-A recreate retained) |

## 5. DC05 split

- **DC05-LOCAL-KEY:** PASS (isolated test key; signature proven, shipped verifier
  rejects missing-`azp` with `INVALID_TOKEN`; positive/negative controls). Rerun
  within `tests/unit/authentication` (61 passed).
- **DC05-ISSUER:** NOT EXECUTED (issuer limitation) — retained, not conflated.

## 6. Gates

| Gate | Result |
| --- | --- |
| `tests/unit/authentication` | PASS — 61 |
| `tests/integration/postgres/test_postgres_authentication_bindings.py` | PASS — 11 |
| Live DC07 harness (opt-in, `MTMF_PR14_LIVE=1`) | PASS — 6 |
| `./build.sh --integration` | PASS — 556 passed, 6 skipped (live opt-in) |
| `./build.sh --qa` | PASS — 1418 tests, 88.28% coverage |
| `./build.sh --sec` | PASS — 0 findings |
| `pre-commit run --all-files` | PASS |
| 77-signature runtime verifier; runtime table/mutation denial | PASS |

Fixture started, mutated, restored, and torn down; only `mtmf-pr14-keycloak`
resources touched; no tokens/secrets committed.

## 7. Residual risks

Configuration-backed class predicate (not a JWT guarantee); attestation TOCTOU
and privileged issuer administrator; bearer replay / separate-session
acquisition; bounded JWKS rotation cache. Production issuer, root, RFC 8693,
cross-client propagation and public HTTP routes remain unimplemented.

## 8. Merge recommendation

**NOT RECOMMENDED.** The canonical positive DC07 actor slice and key negative
cases now pass live, but the full original V01–V16 live coverage and a fresh
Amendment #3 clean-recreate proof are not complete. Remaining live cases are
unit/integration-covered but not executed in the live topology. The implementation
and verifier hardenings are safe to retain pending reviewer completion of the
remaining live acceptance.
