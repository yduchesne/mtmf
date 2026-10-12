# PR 14 Amendment #2 — acceptance report

**Status: STOPPED AT PHASE 1 (fixture blocker); PARTIAL CLOSURE — MERGE NOT RECOMMENDED.**
Branch `dev/service-auth`. Independent Phase 2/4 items were completed; the
canonical DC07 live vertical slice could not be started because the Phase 1
prerequisite fails on the pinned issuer.

## 1. Baseline

| Item | Value |
| --- | --- |
| Refreshed `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Reconciled base | `4d5c30294be3dfbe3c799f06da6654127da1b89e` (Amendment #2 authorization §14I) |
| Final commit | the commit that adds this report |
| Pinned issuer | `quay.io/keycloak/keycloak:26.8.0-1`, digest `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Fixture state | started, experimented on, **torn down**; only `mtmf-pr14-keycloak` resources touched |

## 2. Phase 1 — same-client distinct-audience fixture: BLOCKED (STOP)

The pinned fixture's same-client candidate (`mtmf-evidence-same-client`) was
configured with two audience mappers (`mtmf-service-api` and `mtmf-user-api`)
and both grants were issued. Observed access-token `aud`:

- service (client_credentials): `['mtmf-same-client-api', 'mtmf-user-api', 'mtmf-service-api', 'account']`
- user (auth-code+PKCE):       `['mtmf-same-client-api', 'mtmf-user-api', 'mtmf-service-api', 'account']`

Keycloak audience mappers are client-scope-based and apply to **every** grant
for the client; they are not per-grant. Therefore a same-client service/user
pair **cannot** carry distinct class-specific audiences, and the wrong-grant
token satisfies the audience contract. Per Phase 1.3 and STOP #1, this is a
STOP: DC07/V01–V16 are **NOT EXECUTED**, and no permissive multi-audience
policy, alternate issuer, custom mapper, or runtime heuristic was introduced.
The approved mapper-lockdown contract (no custom `aud`/`azp`/`client_id`/`typ`
mappers) was not violated, and the baseline was not modified.

**Smallest reviewer decision required** (one of):
1. amend the approved profile to accept the same-client **shared-audience**
   configuration and rely solely on the attested signed `client_id` class
   predicate (drift-detected) for grant discrimination; or
2. require **distinct clients** for the service credential and the interactive
   user flow (changes the D1 same-client architecture); or
3. authorize a specifically reviewed issuer-side conditional mapper (alters
   the G0-A mapper-lockdown contract).

## 3. Phase 2 — DC05

| Case | Status | Evidence |
| --- | --- | --- |
| DC05-ISSUER | NOT EXECUTED (issuer limitation) | Keycloak 26.8.0 sets typed `azp` unconditionally; no supported mapper omits it |
| DC05-LOCAL-KEY | PASS | `tests/unit/authentication/test_service_verifier.py::test_dc05_local_key_missing_azp_is_rejected_with_signature_proof` |

`DC05-LOCAL-KEY` uses an isolated test RSA keypair and a bounded fake JWKS
transport; the missing-`azp` token's signature is proven by a normal
`pyjwt.decode` against the test public key, then the shipped
`PyJWTTokenVerifier` rejects it with `INVALID_TOKEN`. Negative controls
(tampered signature, missing `sub`, duplicate `azp`, wrong audience, untrusted
key) and a positive control are exercised. The original issuer-signed DC05
result is retained unchanged.

## 4. Phase 3 — DC07 / V01–V16: NOT EXECUTED

Blocked by §2. No fake verifier/attestor/SPI was substituted; the shipped
`build_actor_context_service` path was not exercised with live tokens. The
existing Amendment #1 in-memory/DB-boundary analogues remain, and no real-token
actor context was claimed.

## 5. Phase 4 — completed deterministic closures

| ID | New evidence | Status |
| --- | --- | --- |
| AUTH-10 / D1-04 | DC05-LOCAL-KEY missing-`azp` + duplicate-claim rejection | PASS (local-key) / issuer NOT EXECUTED |
| AUTH-11 | malformed/incomplete JWKS key (`INVALID_TOKEN`), non-list JWKS (`INFRASTRUCTURE`), unknown/duplicate `kid` | PASS |
| AUTH-16 | two distinct credentials → one Application (real PG) | PASS |
| AUTH-17 | same `(issuer, client_id)` cannot actively map to two Applications (real PG) | PASS |
| AUTH-29 | concurrent same-key insert: exactly one winner, loser blocked/rolled back (real PG) | PASS |
| AUTH-30 | terminal revocation cannot reactivate; immutable key rewrite rejected (real PG) | PASS |
| AUTH-32 | SPI/DB unavailable → typed `INFRASTRUCTURE`, no context | PASS (unit, FailingSpi) |
| AUTH-33 | revoke binding between two resolutions → second fails (no positive cache) | PASS (unit) |
| AUTH-35 | unsupported `crit` header rejected; malformed/oversized token rejected | PASS |
| AUTH-36 | bearer token absent from verifier exception strings and verified-value `repr` | PASS |
| D1-10 | historical G0-A clean-recreate proof retained; Amendment #2 fixture experiment did not alter the baseline | PARTIAL (live re-run NOT EXECUTED) |

**Minimal defect fixes made (with failing tests first):** JOSE `crit` headers
are now rejected; malformed key material from JWKS is typed
`INVALID_TOKEN` rather than escaping.

## 6. Gates

| Gate | Result |
| --- | --- |
| `tests/unit/authentication` | PASS — 55 |
| binding/property integration (`test_postgres_authentication_bindings.py`) | PASS — 11 |
| `./build.sh --integration` | PASS — 556 |
| `./build.sh --qa` | PASS — 1412 tests, 87.88% coverage |
| `./build.sh --sec` | PASS — 0 findings |
| `pre-commit run --all-files` | PASS |
| 77-signature runtime verifier | PASS |

## 7. Residual risk and scope

Configuration-backed class predicate; attestation TOCTOU and privileged issuer
administrator; bearer replay / separate-session acquisition; bounded JWKS
rotation window. Production issuer, root, RFC 8693, cross-client propagation
and public HTTP routes remain unimplemented.

## 8. Merge recommendation

**NOT RECOMMENDED.** Phase 1 is blocked on a Keycloak capability limit, so
DC07/V01–V16 are unexecuted. The smallest decision is §2 (shared-audience
predicate, distinct clients, or a reviewed conditional mapper). Independent
verifier hardenings and Phase 4 closures above are safe to retain.
