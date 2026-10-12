# PR 17 — Amendment #4 deployment evidence (Phase 2, D3 PENDING)

**Status: D3 PENDING. The launcher and `compose.dev.yaml` were not changed.**

## 1. Proposal (not approved)

Development-only `podman run --network=host` service container, HTTP bound to
`127.0.0.1`, retained approved issuer `https://127.0.0.1:28443`, connecting to
MTMF PostgreSQL/Keycloak over host loopback. Development profile only; not
production.

## 2. Verified platform facts

| Fact | Observed |
| --- | --- |
| OS/runtime | Linux (WSL2), rootless Podman 4.9.3, `podman-compose` 1.0.6 |
| `--network=host` behavior | container shares the host namespace; `127.0.0.1:25432`/`:28443` reachable |
| Issuer under host networking | discovery advertises exactly `https://127.0.0.1:28443/realms/mtmf-pr14-dev` |
| TLS | model CA mounted read-only; validation + hostname checks enabled |
| Loopback bind | the Amendment #2 container ran with the service host bound to `127.0.0.1` |

## 3. Not executed (D3 pending)

- No launcher change to select host networking (plan: do not finalize the
  host-network path without D3).
- `compose.dev.yaml` network topology still cannot reach the trusted issuer from
  the service container (loopback namespace).
- Real container ALLOW/DENY under an official launcher path is not re-run; the
  Amendment #2 candidate evidence stands and is not promoted.

## 4. Runtime credential isolation (unchanged)

The Amendment #2 container run received only the restricted runtime DB
credential and the issuer attestation credential; no migrator/owner/root/admin/
bootstrap variable was present. Residual: the attestation credential is the
realm admin, not a dedicated read-only reader (recorded in the STOP register).
