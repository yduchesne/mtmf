# PR 17 — Amendment #5 baseline reconciliation

**UTC:** 2026-10-12. **Branch:** `dev/pr17-http-service` (clean). **Head:** `e6bdcbc`
(A#4 feature `07a349f`). **`origin/main`:** `4eea688`. **merge-base:** `4eea688`.

## 1. Reconciled findings

| Finding | Prior state | Amendment #5 treatment |
| --- | --- | --- |
| SEC-01 HIGH: runtime uses master `admin-cli` password grant + admin credential | present | replaced with a dedicated `client_credentials` reader |
| SEC-02 MEDIUM: `down_volumes()` omitted host-network cleanup | present | unified ownership-verified cleanup on both paths |
| SEC-03 MEDIUM: expected-client policy schema not strict | partial | strict versioned field/type/duplicate validation |
| SEC-04 MEDIUM: projection coverage not inventoried | partial | field inventory + drift tests; AT16 kept PARTIAL |
| SEC-05 LOW: non-atomic Admin REST reads | not verified | read-skew tests + documented residual |

## 2. Exact seams inspected

- `packages/mtmf-service/src/mtmf_service/authentication/attestation.py` — `HttpAdminRestReader`, `canonical_manifest`, `canonical_client_projection`, `ExpectedClientPolicy`, `BaselineConfigurationAttestor`.
- `.../authentication/config.py` — `IssuerConfig`; `.../composition.py`; `.../jwt_verifier.py`.
- `packages/mtmf-core/src/mtmf_core/authentication/ports.py`, `.../application/authentication.py`.
- `dev/keycloak/setup-realm.py`, `expected-realm-security.json`, `expected-client-policy.json`.
- `scripts/mtmf-dev-stack.py`, `scripts/mtmf-dev-initialize.py`, `compose.dev.yaml`, `.env.example`.
- Live suites: `tests/integration/postgres/test_pr14_live_actor_context.py`, `test_pr17_live_http.py`.

## 3. Admin REST operations actually required (traced)

`GET /admin/realms/{realm}`; `GET .../client-scopes`; `GET .../client-scopes/{id}/protocol-mappers/models`;
`GET .../clients?clientId={id}`; `GET .../clients/{uuid}/default-client-scopes`;
`GET .../clients/{uuid}/optional-client-scopes`; `GET .../clients/{uuid}/protocol-mappers/models`.

## 4. Baseline test evidence (pre-change, historical)

A#4 reported QA 1775/89.98%, PR 14 live 22/22, PR 17 live 26/26, integration 564/48,
security zero findings, Rust pass. Re-executed on the A#5 tree in
`pr17-amendment-5-final-acceptance-report.md`.

## 5. Environment

Keycloak `26.8.0-1`, realm `mtmf-pr14-dev`, loopback `https://127.0.0.1:28443`,
CA `/tmp/mtmf-pr14-kc-tls/server.crt`; Podman 4.9.3; PostgreSQL 18
(`mtmf_postgres_1`, restricted `mtmf_runtime`).
