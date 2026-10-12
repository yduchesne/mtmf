# PR 17 — Amendment #3 deployment evidence (Part D)

**Status: D3 (development topology) PENDING. No launcher/topology behavior was
changed in this amendment pending that decision.**

## 1. Recommendation (design, not approval)

Retain the approved issuer `https://127.0.0.1:28443` and use a **development-only
`podman run --network=host`** service container, which Amendment #2 demonstrated
with a real signed-token ALLOW. This avoids changing the trusted issuer identity
and avoids requiring host DNS/sudo. The network-isolated canonical-hostname
topology remains a future hardening option (blocked by host DNS control and the
issuer-identity approval).

## 2. Verified environment facts

| Fact | Value |
| --- | --- |
| OS / runtime | Linux WSL2, rootless Podman 4.9.3, `podman-compose` 1.0.6 |
| Pooled bridge networking | containers on `mtmf-pr14-keycloak_default` cannot reach `127.0.0.1:28443` (loopback namespace) |
| Host networking | container shares the host namespace; `127.0.0.1` reaches Keycloak/PostgreSQL |
| Issuer under host networking | discovery advertises exactly `https://127.0.0.1:28443/realms/mtmf-pr14-dev` |
| TLS | model self-signed CA mounted read-only; certificate validation + hostname check enabled |

## 3. Required checks (A3-11/A3-12 status)

| Check | Status |
| --- | --- |
| Service container loopback-bound (`127.0.0.1:28001`) | VERIFIED in the Amendment #2 run (the service host was bound to `127.0.0.1`); the Compose wildcard-bind variant is for the network topology and is **not** used in host-network mode |
| PostgreSQL reachable from the container | VERIFIED (host networking, `127.0.0.1:25432`) |
| Keycloak discovery/JWKS/Admin REST from the container | VERIFIED (Amendment #2 `200 ALLOW`) |
| `/health/ready` gated on dependencies | VERIFIED (Amendment #3 V08: readiness 503 during outage, 200 after recovery) |
| Runtime container excludes migrator/owner/bootstrap secrets | VERIFIED (only runtime + attestation reader present) |
| ALLOW and DENY via real tokens | VERIFIED (Amendment #2/A#3 live suites) |

## 4. Not executed / blockers

- The `compose.dev.yaml` network topology was **not** executed end to end
  (issuer unreachable from the service container without host DNS).
- No launcher change was made to select the host-network topology, because D3 is
  not approved (plan: do not execute phase 6 without the gate).
- The initializer still creates `mtmf-sample-app`, which fails whole-realm
  attestation (D2); the demonstrated ALLOW required the approved-client state.
- A dedicated read-only attestation reader is not provisioned (residual).

## 5. Cleanup

Only MTMF-owned resources were used (`mtmf`, `mtmf-pr14-keycloak`). The
Keycloak fixture was stopped after use; `mtmf_postgres_1` was left healthy. No
global prune or cross-project action was performed.
