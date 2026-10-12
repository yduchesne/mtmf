# PR 14 Amendment #1 — acceptance report

**Status: ACCEPTANCE CLOSURE PARTIAL — MERGE NOT RECOMMENDED.**
Branch `dev/service-auth`. This amendment tested the shipped PR 14 implementation,
fixed two demonstrated verifier defects, and executed the live configuration
attestation boundary. The full live-token + real-PostgreSQL D1 vertical slice
(DC07/V01–V16) and DC05 remain **NOT EXECUTED** (precise blockers in §4–§5).

## 1. Baseline and changes

| Item | Value |
| --- | --- |
| Refreshed `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Base (`origin/dev/service-auth`) | `a8ed9f431599f278c8d87212ac49e499ffa5bba6` |
| Final commit | the commit that adds this report (recorded in the agent handoff) |
| Worktree | clean at start; refreshed reconciliation found no branch drift |

**Changed in this amendment**

- `packages/mtmf-service/src/mtmf_service/authentication/jwt_verifier.py` —
  two demonstrated defect fixes: strict pre-verification payload parsing
  (duplicate JSON member rejection) and strict base64url segment validation;
  JWKS transport exceptions are now wrapped as typed `INFRASTRUCTURE` failures.
- `tests/unit/authentication/test_service_verifier.py` — added duplicate
  payload-claim, malformed-base64, forged-signature, wrong-issuer,
  missing-time, `none`/HS, JWKS outage, key-rotation and class-mismatch cases.
- `tests/unit/authentication/test_attestation.py` — new production-class
  attestor tests (canonical equality, drift, missing/malformed baseline,
  reader failure, no positive cache, order normalization).
- `tests/unit/authentication/test_actor_context.py` — added missing-token,
  inactive-Tenant, missing-registration and cross-Tenant cases.
- `docs/PR14_AMENDMENT1_ACCEPTANCE_MATRIX.md` — named AUTH/D1 traceability.
- `docs/PR14_DEVELOPMENT_FIRST_IMPLEMENTATION_GATE.md`, `docs/ROADMAP_V01.md` —
  status-only.

No production schema, migration, grant, route or authorization semantics changed.
No existing versioned SQL was edited.

## 2. Production-path proof (configuration attestation)

The **shipped** `mtmf_service.authentication.attestation.BaselineConfigurationAttestor`
and `HttpAdminRestReader` were exercised against the live pinned Keycloak
`26.8.0` fixture (`quay.io/keycloak/keycloak:26.8.0-1`, digest
`sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741`),
loopback `https://127.0.0.1:28443`, dev CA trusted via `SSL_CERT_FILE`:

1. clean attestation against the committed baseline → **ok** (canonical hash
   `9e9bb847e35060b2aab18c876d52c23648c137668c08fa6766c69a30dbc6fed5`);
2. injected `client_id` hardcoded-claim mapper via privileged Admin REST →
   `attestation_drift`;
3. mapper removed → **ok** again.

This proves the shipped reader/attestor fail closed on real configuration drift
and re-attest fresh after restoration. It does **not** prove per-operation
attestation at the actor boundary (no live actor slice) — that remains NOT
EXECUTED. No expected manifest was learned from the live issuer.

## 3. Deterministic acceptance evidence

| Gate | Result |
| --- | --- |
| `tests/unit/authentication` (48 tests) | PASS |
| `./build.sh --integration` (with `.env` roles) | PASS — 552 |
| `./build.sh --qa` | PASS — 1405 tests, 87.55% coverage |
| `./build.sh --sec` | PASS — Bandit 0 medium/high; Semgrep 0 |
| `pre-commit run --all-files` | PASS |
| migration `0011` + 77-signature runtime verifier | PASS on real PostgreSQL |
| runtime direct table SELECT / operator mutation denied | PASS |
| R12 | Historical matrix `NOT EXECUTED`; separately verified (see §6) |

## 4. DC05 — issuer-signed missing `azp`: BLOCKED

Keycloak 26.8.0 sets the access-token `azp` from the authenticated client
unconditionally (`TokenManager.initToken` → `JsonWebToken.issuedFor`, the only
typed `azp` writer). No supported per-client protocol-mapper mechanism removes a
typed claim; hardcoded-claim mappers can only add/override. Producing a
genuinely RS256-signed user access token with `azp` absent therefore requires an
unsupported issuer alteration. Per the plan, this is a **STOP**: DC05 is **NOT
EXECUTED** and no substitute (local key, monkeypatched claims, or re-signed
payload) was used. The verifier/class rule is nevertheless covered at the
payload level: missing/ambiguous `azp` raises `INVALID_TOKEN`
(`test_service_verifier.py` missing/duplicate-claim tests).

## 5. DC07 / V01–V16 — real-token + real-PostgreSQL slice: NOT EXECUTED

Blockers, in order:

1. **Fixture gap.** The pinned fixture's only client able to issue *both*
   client-credentials and interactive tokens (`mtmf-evidence-same-client`)
   carries a single audience (`mtmf-same-client-api`). The approved `IssuerConfig`
   requires distinct service and user audiences, so a same-client D1 pair cannot
   satisfy the shipped `build_actor_context_service` configuration without a
   fixture + committed-baseline change. That change was not authorized/executed
   in this amendment.
2. **Orchestration.** The full slice additionally requires a live-token
   acquisition harness and real-PostgreSQL domain/binding provisioning driven
   through the shipped composition seam. This was not completed within the
   amendment; no fake SPI/verifier/attestor was substituted.

Consequently V01–V16 are **NOT EXECUTED**, not PASS. `V01`/`V05`/`V06`/`V12`/
`V14` have in-memory or DB-boundary analogues only (see the matrix).

## 6. R12 reconciliation

`dev/keycloak/evidence/pr14-g0a-mapper-matrix.json` retains its historical
`R12 NOT EXECUTED (separate step)` status. The separate clean-recreate run
performed during the prior G0-A amendment produced the identical canonical
manifest hash `9e9bb847…` and a passing attestation; that is recorded here as
**separately verified**, not merged into the historical artifact and not
relabeled PASS in the matrix.

## 7. Runtime grant proof

`tests/integration/postgres/test_postgres_authentication_bindings.py` proves the
restricted `mtmf_runtime` login is denied direct `SELECT` on the new tables and
denied execution of the operator-only add function, while the two reviewed
`SECURITY DEFINER` reads are the only v011 runtime entry points. The
post-upgrade verifier confirms the 77-signature allowlist.

## 8. Residual risk

Configuration-backed class predicate (not a JWT guarantee); attestation
time-of-check/time-of-use window and privileged issuer administrator;
bearer-token replay and separate-session acquisition; bounded JWKS rotation
window. Production issuer trust, root authentication/recovery, RFC 8693 actor
delegation, cross-client propagation and public HTTP routes remain
unimplemented and gated.

## 9. Merge recommendation

**NOT RECOMMENDED.** Deterministic unit/integration/QA/security gates are green
and the live attestation boundary passes, but mandatory acceptance criteria
remain unmet: DC05 is BLOCKED on an unsupported issuer capability, and the full
DC07 live-token + real-PostgreSQL actor slice and V01–V16 are NOT EXECUTED.
The smallest reviewer decisions needed:

1. authorize a fixture+baseline change adding a same-client D1 client with
   distinct service/user audiences (or amend the distinct-audience requirement);
2. accept the DC05 disposition as BLOCKED (or authorize an issuer-side
   mechanism capable of omitting `azp`).
