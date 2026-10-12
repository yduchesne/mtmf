# PR 17 — Amendment #4 deployment evidence (D3 APPROVED 2026-10-12)

**Status: IMPLEMENTED and VERIFIED (development only).** D3 approved by the
human reviewer on 2026-10-12 — development-only `--network=host`, loopback
binding, retained issuer.

## 1. Launcher

`scripts/mtmf-dev-stack.py` gained an explicit `up-host-network` path:

1. validates the development profile and requires the runtime/migrator URLs and
   issuer config;
2. starts PostgreSQL + Keycloak and waits for health;
3. runs the privileged one-shot initializer (migrations + postflight + fixture);
4. runs the unprivileged service with `podman run --network=host`, binding
   `MTMF_SERVICE_HOST=127.0.0.1` / port `28001`, with only the restricted runtime
   DB credential and the approved attestation-reader credential;
5. waits for `/health/ready`.

`down` removes the host-network container and stops the MTMF-owned Compose
project; no other project is touched.

## 2. Executed container verification (new D2 code, image `localhost/mtmf-service:dev`)

| Check | Result |
| --- | --- |
| Image build | exit 0 |
| `/health/ready` | `{"status":"ready"}` HTTP 200 |
| Real-token `POST /v1/authorization/evaluate` | HTTP 200 `ALLOW`/`PERMITTED`, `Cache-Control: no-store` |
| Loopback bind | service host bound to `127.0.0.1` (host-network mode ignores `ports:`) |
| Issuer / TLS | retained `https://127.0.0.1:28443`, CA-trusted, verification enabled |
| Runtime env | only `MTMF_RUNTIME_*`, `MTMF_AUTH_*` (attestation reader), `MTMF_SERVICE_*`; **no** `MTMF_MIGRATOR_*`, `MTMF_POSTGRES_*` admin/owner, root or bootstrap variable |

The container used the real `expected-realm-security.json` +
`expected-client-policy.json` artifacts and freshly attested per request.

## 3. Residual / limits

- `--network=host` removes the service container's network-namespace isolation;
  approved for local development only, never production.
- The attestation reader is the realm admin credential (not yet a dedicated
  read-only reader) — recorded in the STOP register.
- The canonical-hostname/isolated-network topology remains a future hardening
  option.
