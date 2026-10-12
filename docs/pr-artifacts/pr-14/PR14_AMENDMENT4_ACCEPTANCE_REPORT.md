# PR 14 Amendment #4 — final live security acceptance report

**Status: DEVELOPMENT-ONLY NON-ROOT LIVE ACCEPTANCE EXECUTED; ROOT/PRODUCTION DEFERRED. MERGE REQUIRES HUMAN REVIEW — NOT AUTO-MERGED.**
Authority: register §14J. This amendment completed the live acceptance gaps left
by Amendments #1–#3 without changing the authentication architecture.

## 1. Baseline

| Item | Value |
| --- | --- |
| Refreshed `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Reconciled base | `7d4710b0df5b58b082f79aceb27c41992a243599` |
| Final commit | the commit that adds this report |
| Pinned issuer | `quay.io/keycloak/keycloak:26.8.0-1`, digest `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Reviewed baseline | `dev/keycloak/expected-config-manifest.json`, canonical hash `9e9bb847e35060b2aab18c876d52c23648c137668c08fa6766c69a30dbc6fed5` |

**Changed:** `tests/integration/postgres/test_pr14_live_actor_context.py`
(extended live harness; the six Amendment #3 cases preserved), Amendment #4
matrix/report, and status-only gate/roadmap notes. No production service/core
change, schema, migration, grant, route, root or authorization change; the
reviewed manifest was not regenerated.

## 2. Live acceptance (zero skips)

Command: `MTMF_PR14_LIVE=1 SSL_CERT_FILE=<dev-CA> uv run --no-sync pytest
tests/integration/postgres/test_pr14_live_actor_context.py -q --no-cov`
→ **22 passed** on the pinned Keycloak fixture and real PostgreSQL 18 through the
shipped `build_actor_context_service` → `AuthenticatedActorContextService.resolve`
→ `PostgresMtmfSpi`/UnitOfWork/versioned stored functions.

Cases (new in #4 in bold):

- Positive same-client actor context (exact Application/Identity/Principal/Tenant);
  **repeated resolution stable**; **binding revocation freshness**.
- **Wrong slot** (service↔user); cross-client; **wrong configured audience**;
  **modified signature**.
- **Inactive Identity**, **Principal**, **Tenant**, **Application**;
  **missing membership**; **cross-Tenant**; **inactive registration**;
  **inactive subscription**; **root Tenant scope**.
- **Admin REST outage** (bad credential), **missing/bad manifest**.
- **Real PostgreSQL outage** → typed `INFRASTRUCTURE`.
- Mapper drift injected → `ATTESTATION_DRIFT`; restore → success (Amendment #3 case retained).

All failure cases assert the exact typed `AuthenticationError.failure`; positive
precedes negative; no fake verifier/attestor/SPI is used.

## 3. Fixture, clean recreate and trust anchor

- Clean `podman-compose -p mtmf-pr14-keycloak … down -v`, recreate the pinned
  digest, rerun idempotent `setup-realm.py`.
- Canonical manifest recomputed → **exact match** to the reviewed baseline hash
  `9e9bb847e35060b2aab18c876d52c23648c137668c08fa6766c69a30dbc6fed5`; the full
  22-case live suite re-ran green on the fresh fixture (zero skips).
- The trusted manifest was never learned from live state. Only
  `mtmf-pr14-keycloak` resources were touched; the fixture was torn down and
  ephemeral secrets removed.

## 4. DC05 split

- DC05-LOCAL-KEY: PASS (isolated test key; signature proven by normal decode;
  shipped verifier rejects missing `azp` with `INVALID_TOKEN`).
- DC05-ISSUER: NOT EXECUTED (Keycloak 26.8.0 sets typed `azp` unconditionally).
  Not conflated.

## 5. PostgreSQL / privilege proof

Migration `0011` at head; canonical 77-signature post-upgrade runtime verifier
PASS; `mtmf_runtime` denied direct table `SELECT` and operator mutation; only the
reviewed `SECURITY DEFINER` reads are granted. The live harness seeds fixture
state only through administrator/operator-authorized SQL and never as
`mtmf_runtime`; no transaction spans Keycloak network I/O.

## 6. Gates

| Gate | Result |
| --- | --- |
| `uv run --no-sync pytest tests/unit/authentication -q --no-cov` | PASS — 61 |
| `test_postgres_authentication_bindings.py` | PASS — 11 |
| Live harness (`MTMF_PR14_LIVE=1`) | PASS — 22 (zero skips) |
| `./build.sh --integration` | PASS — 556 passed, 22 skipped (live opt-in) |
| `./build.sh --qa` | PASS — 1418 tests, 88.28% coverage |
| `./build.sh --sec` | PASS — 0 findings |
| `pre-commit run --all-files` | PASS |
| Migration `0011` + 77-signature verifier + runtime denial | PASS |

## 7. Remaining exceptions / residual risks

- AUTH-05 / D1-09 (caller-supplied UUID or assertion): no PR 14 runtime path
  accepts one; no HTTP route exists. Disposition: not executable in scope
  without PR 17; not marked PASS by construction alone.
- AUTH-06 wrong issuer: not issuable from the approved fixture; unit-covered.
- V-case numbering across plans is inconsistent; executed coverage is reported
  by case name (matrix §V01–V16) rather than renaming historical IDs.
- AUTH-26/27 DEFERRED ROOT; root remains fail-closed.
- Residual: configuration-backed class predicate, attestation TOCTOU, privileged
  issuer admin, bearer replay/separate-session acquisition, bounded JWKS rotation.
- Production issuer, root authentication/recovery, RFC 8693, cross-client
  delegation and public HTTP routes remain unimplemented.

## 8. Merge recommendation

**MERGE RECOMMENDED FOR HUMAN REVIEW** for the development-only, non-root scope:
the canonical live DC07 slice and the named negative AUTH/D1/V cases execute
green in the prescribed topology with a reproducible trusted baseline. This is a
recommendation only; the human security reviewer retains final acceptance and
merge authority, and must accept the AUTH-05/D1-09 disposition and the residual
risks above.
