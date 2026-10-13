# PR 17-C Network and Issuer Decision

## Canonical authority

| Item | Value |
| --- | --- |
| Hostname | `keycloak.mtmf.test` |
| Public issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev` |
| JWKS URI | `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs` |
| Admin base | `https://keycloak.mtmf.test:28443` |
| Keycloak internal HTTPS | `8443` (unchanged) |
| HTTP service readiness | `http://127.0.0.1:28001/health/ready` |
| PostgreSQL | `127.0.0.1:25432` → internal `5432` |

The identical issuer string appears in discovery `issuer`, token `iss`,
`MTMF_AUTH_ISSUER`, and `MTMF_AUTH_JWKS_URI`.

## Verified topology

```
Windows browser ─┐
                 ├─(hosts: 127.0.0.1 keycloak.mtmf.test)─► WSL2 127.0.0.1:28443 ─► keycloak:8443
WSL2 host ───────┘                                          (loopback publish, TLS passthrough)

initializer/service ─(extra_hosts keycloak.mtmf.test=<forwarder-ip>)─► forwarder:28443
                                                                       │ raw TCP, no TLS termination
                                                                       ▼
                                                                    keycloak:8443
```

A single authority is not a single IP address: Windows/WSL resolve the name to
loopback, containers resolve it to the MTMF-owned forwarder IP. In every namespace the
TLS endpoint, hostname, SAN, and issuer are identical.

## Option A: MTMF-owned internal TCP forwarder

The port mismatch (canonical `28443` vs. Keycloak listener `8443`) is resolved by a
small, non-privileged forwarder service (`scripts/mtmf-dev-forwarder.py`), built from
the already-present `docker.io/library/python:3.14-slim` image:

- listens on `0.0.0.0:28443` **inside** the isolated `mtmf_default` network;
- forwards bytes to `keycloak:8443` without terminating or inspecting TLS;
- is never host-published, has no admin/health HTTP surface, and runs unprivileged;
- carries the `keycloak.mtmf.test` network alias;
- retries its target connection briefly so a Keycloak restart window does not drop a
  live request.

This satisfies the plan's preferred "internal TLS TCP forwarding listener" and keeps
Keycloak's certificate/hostname validation end to end. No second issuer, no host
networking, no new third-party image, and no wildcard exposure are introduced.

## Two verified hazards and their fixes

1. **Host `/etc/hosts` is copied into containers.** Rootless Podman copies the host
   `hosts` file into every container. An operator entry
   `127.0.0.1 keycloak.mtmf.test` therefore shadows the network alias and makes
   containers dial their own loopback. The initializer and service receive an explicit
   `extra_hosts` entry pinned to the forwarder IP (the launcher resolves it after the
   forwarder is healthy). Podman writes `--add-host` entries before the copied host
   entries, so the canonical mapping wins; the container path also no longer depends on
   host DNS.
2. **Containers cannot use host loopback for PostgreSQL.** The launcher rewrites the
   migrator/runtime database URLs from `127.0.0.1:25432` to the Compose service
   authority `postgres:5432` before invoking Compose.

## Loopback-only publications

`compose.yaml` PostgreSQL was changed from `"${MTMF_POSTGRES_PORT:-25432}:5432"` to
`"127.0.0.1:${MTMF_POSTGRES_PORT:-25432}:5432"` so every development host publication
is loopback-only. This does not change the port, the volume, or the data. Keycloak
(`28080`, `28443`) and the service (`28001`) were already loopback-only; the forwarder
is unpublished.

## Keycloak hostname configuration

`compose.dev.yaml` now passes `--hostname=https://keycloak.mtmf.test:28443`,
`--hostname-strict=true`, `--hostname-backchannel-dynamic=false`, and explicit
`--https-certificate-file`/`--https-certificate-key-file`. `--hostname-strict=false`
is removed. Only the public CA certificate and the leaf certificate/key are mounted;
the CA private key never enters a container.

## Rejected alternatives

- **Host networking** (`up-host-network`): retained only as a documented fallback, not
  the normal path.
- **Static subnet / fixed container IP**: rejected to avoid host-network collisions and
  cross-project coupling.
- **Changing Keycloak's internal listener to 28443**: rejected to preserve the plan's
  "keep 8443" guidance and the existing loopback publication.
- **`verify=False` / issuer rewriting / HTTP issuer**: never used.
