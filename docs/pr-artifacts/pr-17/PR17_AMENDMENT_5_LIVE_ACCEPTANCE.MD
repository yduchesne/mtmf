# PR 17 — Amendment #5 live acceptance

**Topology:** real PostgreSQL 18 (restricted `mtmf_runtime`); pinned Keycloak
`26.8.0-1`, realm `mtmf-pr14-dev`, real HTTPS issuer; dedicated
`mtmf-attestation-reader` client; real Uvicorn/ASGI; genuine issuer-signed
tokens; approved loopback host-network development topology.

| Suite | Command | Result |
| --- | --- | --- |
| PR 14 live actor | `MTMF_PR14_LIVE=1 SSL_CERT_FILE=<CA> pytest tests/integration/postgres/test_pr14_live_actor_context.py` | **22 passed** |
| PR 17 live HTTP | `MTMF_PR17_LIVE=1 … pytest tests/integration/postgres/test_pr17_live_http.py` | **26 passed** |
| Reader permissions | `MTMF_PR17_LIVE=1 … pytest tests/integration/postgres/test_pr17_attestation_reader_permissions.py` | **3 passed** |
| Runtime timeouts | `pytest tests/integration/postgres/test_pr17_runtime_timeouts.py` | 5 passed |
| Initializer | `pytest tests/integration/postgres/test_pr17_dev_initializer.py` | 3 passed |

## V01–V16

All V01–V16 remain PASS in the required topology (see Amendment #4 live matrix),
re-executed after the reader change:

- V01 fresh containerized deployment (host-network) — PASS; containerized
  reader-credential run reached `/health/ready` 200 and a genuine `200 ALLOW`.
- V02–V07, V09–V11, V14–V16 — PASS via the live suites.
- V08 database outage/recovery — PASS.
- V12 two-client isolation — PASS (`test_cl01..cl07`).
- V13 isolated destroy/recreate — PASS (Amendment #4).

## Reader-boundary live evidence

- Reader authenticates with `client_credentials` and all required GETs return
  200; all mutation/escalation attempts return 403 with unchanged state.
- Revoking/drifting configuration makes the next operation fail closed with no
  decisions; restoring recovers without regenerating any trusted baseline.
- The runtime container carries no admin/migrator/owner/root credential; the
  reader secret is mounted via `_FILE` and absent from `podman inspect`.
