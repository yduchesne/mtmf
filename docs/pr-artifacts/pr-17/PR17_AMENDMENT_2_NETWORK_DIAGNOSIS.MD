# PR 17 — Amendment #2 network diagnosis (Part A)

## 1. Reproduced failure and classification (A2-01)

A diagnostic container (`localhost/mtmf-service:dev`) attached to the MTMF
Keycloak network `mtmf-pr14-keycloak_default`, with the self-signed development
CA mounted, produced:

```
dns-keycloak:      OK   -> 10.89.22.24
dns-127:           OK   -> 127.0.0.1
dns-postgres:      FAIL -> gaierror: Name or service not known
tls-keycloak-8443: OK   -> 200
loopback-28443:    FAIL -> URLError: [Errno 111] Connection refused
```

And discovery handling from the same container:

```
https://keycloak:8443  -> issuer=https://keycloak:8443/realms/mtmf-pr14-dev
https://127.0.0.1:28443 -> FAIL (connection refused)
```

**Confirmed root causes:**

1. **Loopback namespace (primary).** Inside a container `127.0.0.1` is the
   container, not the host, so the approved issuer
   `https://127.0.0.1:28443/...` is unreachable (connection refused).
2. **Separate networks.** PostgreSQL (`mtmf`) and Keycloak
   (`mtmf-pr14-keycloak_default`) are not on one shared MTMF network, so the
   service container cannot resolve `postgres`.
3. **Issuer host derivation (two identities).** Keycloak (with
   `hostname-strict=false`) advertises the issuer from the request host. A
   container reaching `https://keycloak:8443` is told the issuer is
   `https://keycloak:8443/...`, while host clients reaching
   `https://127.0.0.1:28443` are told `https://127.0.0.1:28443/...`. A single
   service-configured issuer therefore cannot both accept host-obtained tokens
   and be reachable inside the container.

**Not present:** the TLS certificate already includes SAN
`IP:127.0.0.1,DNS:localhost,DNS:keycloak`, and CA trust succeeded from the
container. DNS, TCP, TLS, discovery, JWKS and Admin REST are all reachable
*within the Keycloak network*; the failures are the loopback/origin issues
above, not certificate or trust gaps.

## 2. Candidate topologies evaluated

| Topology | Reachability | One issuer identity | Verdict |
| --- | --- | --- | --- |
| Compose network + service alias `keycloak` | yes (container) | **no** — issuer becomes `keycloak:8443` | rejected (two identities) |
| Canonical hostname `keycloak.mtmf.test` resolvable from host + containers | yes | yes | **blocked** — requires a host `/etc/hosts`/DNS change (no sudo) and an issuer-identity change (STOP-01) |
| `--network=host` for the dev service container | yes (`127.0.0.1` = host) | **yes** — issuer unchanged | implemented for the executed demonstration |

## 3. Executed resolution (A2-02–A2-07)

The executed demonstration runs the built service image with
`podman run --network=host`, so the container reuses the host loopback
addresses and the **approved issuer identity is unchanged**:

- A2-02: the service container reaches `https://127.0.0.1:28443`.
- A2-03: discovery advertises exactly `https://127.0.0.1:28443/realms/mtmf-pr14-dev`.
- A2-04: TLS CA + hostname verification pass (no verification weakened).
- A2-05: JWKS and fresh Admin REST attestation succeed from the container
  (proved by a real authenticated `200 ALLOW`).
- A2-06: PostgreSQL reachable at `127.0.0.1:25432`.
- A2-07: the containerized service reached `/health/ready` **200** only after
  initialization.

## 4. Deviation and limits

- `--network=host` reduces the dev service container's network isolation. It is
  a development-only measure; it changes no authentication, TLS, issuer or
  authorization rule.
- The recommended single-network canonical-hostname topology was **not**
  adopted because it requires (a) host DNS control (no sudo) and (b) a change to
  the approved issuer identity/TLS/manifest (STOP-01, reviewer approval
  required). `compose.dev.yaml` retains the network topology and the
  `scripts/mtmf-dev-stack.py` launcher; the host-network run is documented as
  the executed candidate.
- A shared secretless assumption is not made: the container still only receives
  the restricted runtime credential and the issuer attestation credential.
