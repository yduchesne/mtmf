# PR 18 Fixup 1 — CL-I16 Live Acceptance (Owned-Service Restart)

## 1. Scope and ownership

`test_cl_i16_owned_uvicorn_restart_recovery` proves
**ALLOW → owned service stop → typed transport failure / no new grant →
owned service restart → ALLOW** through the real `HttpMtmfClient` over real
TLS, a real Keycloak issuance, and real PostgreSQL.

Only a `_TlsLiveServer` **created by the test itself** on an ephemeral
loopback port is stopped and restarted. The test does **not**:

- restart, remove, or reconfigure Keycloak or PostgreSQL;
- run `podman restart`/`rm`/`volume rm`, `mtmf-dev-stack.py down`, or any
  destructive operation;
- contact the module-scoped `live_server` instance owned by other tests.

**Keycloak restart is NOT TESTED** (deliberate: restarting the shared
development IdP would disrupt the operator environment and other work). A
human reviewer decides whether a separate, fully isolated disposable
Keycloak restart gate is required. The coding agent did not waive it.

## 2. Test-owned lifecycle

1. `_free_loopback_port()` binds an ephemeral loopback port and releases it
   immediately; `_TlsLiveServer` then binds it. A bind race fails the
   fixture with a clear startup error rather than contacting a foreign
   listener.
2. A disposable Keycloak user (module fixture, additive, deleted after) is
   used with real Keycloak Authorization-Code + PKCE issuance.
3. `pr17._seed` creates the eligible Application/Tenant/Identity in real
   PostgreSQL; the shared `mtmf-dev` issuer and `mtmf_runtime` login are
   used unchanged.
4. A real PR 17 app instance is served by test-owned server A over TLS with
   a leaf certificate signed by the development CA (`127.0.0.1` SAN).
5. `HttpMtmfClient` evaluates a real ALLOW and `require`s the exact
   capability target; snapshot S1 records its server-issued `expires_at`.
6. Server A is stopped; `_wait_port_closed` confirms the listener no longer
   accepts connections.
7. A fresh `evaluate` raises `DependencyUnavailableError` (typed transport
   failure) and creates no snapshot.
8. Keycloak and PostgreSQL are independently shown still running: a fresh
   real user token is acquired and `SELECT 1` succeeds.
9. Server B is started on the **same** port with the same certificate; the
   **same** `HttpMtmfClient` instance evaluates a fresh request and gets a
   new ALLOW snapshot S2.
10. S1's server-issued expiry is byte-for-byte unchanged; no authorization
    retry occurred and no snapshot was extended. Server B and the client are
    closed in `finally`.

## 3. Commands and results

Targeted diagnostic (not a substitute for full acceptance):

```bash
MTMF_PR18_LIVE=1 uv run --no-sync pytest -q --no-cov \
  tests/integration/postgres/test_pr18_live_client.py -k cl_i16
# 1 passed, 15 deselected in 22.85s
```

Full module, three consecutive runs (single-process, no xdist, `--no-cov`,
`retries = 0`):

| Run | Command | Exit | Result | Duration |
| --- | --- | --- | --- | --- |
| 1 | `MTMF_PR18_LIVE=1 uv run --no-sync pytest -q --no-cov tests/integration/postgres/test_pr18_live_client.py` | 0 | **16 passed** | 43.87 s |
| 2 | same | 0 | **16 passed** | 43.74 s |
| 3 | same | 0 | **16 passed** | 45.05 s |

No skipped tests, no first-attempt failure, no retry.

## 4. Environment

External live prerequisites (see `docs/DEVELOPMENT_SETUP.md`):
`MTMF_PR14_KC_BASE=https://keycloak.mtmf.test:28443`,
`MTMF_PR14_KC_ADMIN_USERNAME`, `MTMF_PR14_KC_ADMIN_PASSWORD`,
`MTMF_PR14_KC_CA_FILE=/tmp/mtmf-dev-ca/dev-ca.crt`,
`MTMF_AUTH_ADMIN_REALM=mtmf-dev`, `MTMF_PR18_LIVE=1`, and the
`MTMF_RUNTIME_POSTGRES_*` configuration. Real realm `mtmf-dev`, real
PostgreSQL 18. No secret appears in this report or in captured output.

## 5. Dispositions

- CL-I01–CL-I15, CL-I16, CL-I17, CL-I18: **PASS** (16/16 × 3).
- Keycloak restart: **NOT TESTED** (separate operator-controlled validation;
  human reviewer decision).
- No shared service, IdP, database, or volume was restarted or deleted.
