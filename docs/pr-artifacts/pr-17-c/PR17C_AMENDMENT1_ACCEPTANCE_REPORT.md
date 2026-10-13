# PR 17-C Amendment 1 — Acceptance Report

**Amended code:** `dev/pr17c-keycloak-issuer` working tree on base `f4d1905`.
**Environment:** Windows browser → Ubuntu 24.04.5 WSL2 → rootless Podman 4.9.3 /
`podman-compose` 1.0.6; Keycloak `26.8.0-1`; PostgreSQL 18.
**Topology:** canonical `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`
via the MTMF-owned forwarder; isolated `mtmf` network; no host networking.

## Canonical gates (amended tip)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — **2004 passed** (was 1947; +57 AM/N regression tests), coverage **90.75%** (≥85%) |
| `./build.sh --sec` | PASS — Bandit Medium/High **0**, Semgrep **0 findings** |
| `./build.sh --rust` | PASS — no native change |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |

## Live acceptance (amended tip)

### Standard isolated `up` (no host networking)

```text
$ python scripts/mtmf-dev-stack.py up
preflight[host] OK
preflight[container] OK
development initialization complete
MTMF development stack is ready
exit 0
$ curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:28001/health/ready
200
```

### Exact live issuer / JWKS / token

```text
discovery issuer: https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
discovery jwks_uri: https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs
token iss: https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
token azp: mtmf-evidence-service
```

`preflight` (host + a throwaway container on the isolated network) returned
exit 0 with `discovery issuer == …`, `discovery jwks_uri == …`, and JWKS keys
present after Keycloak reached healthy.

### Restart / idempotency / PKI

- Second `up`: exit 0; PostgreSQL tenant/principal/identity/application/
  subscription/membership counts **identical**; Keycloak `mtmf-dev-user` count 1.
- `server.crt` bytes unchanged across normal `up`; `server.key` remains
  owner-mapped `0600` (host-UID `100999`).
- `generate`/`check` on the hardened set succeed (pairing verified via
  `podman unshare`), proving normal startup never rewrites PKI material.

### Live negative controls

- **Wrong issuer** (`https://evil-keycloak.mtmf.test:28443/…`): `up` exit 1
  before any mutation; Keycloak/service `StartedAt` unchanged; the untrusted URL
  and any `secret` are not echoed.
- **Partial PKI** (`MTMF_DEV_CA_DIR` containing only `dev-ca.key`): `up` exit 1
  at certificate generation; Keycloak untouched; the one existing file's bytes
  unchanged.
- **SAN mismatch** (offline cert check with `--hostname other.mtmf.test`): fail
  closed.

### Isolation / exposure

```text
mtmf_postgres_1:  net=bridge publish=[127.0.0.1:25432->5432/tcp]
mtmf_keycloak_1:  net=bridge publish=[127.0.0.1:28080->8080/tcp, 127.0.0.1:28443->8443/tcp]
mtmf_forwarder_1: net=bridge publish=none
mtmf_service_1:   net=bridge publish=[127.0.0.1:28001->28001/tcp] extra_hosts=[keycloak.mtmf.test:<forwarder-ip>]
```

`podman inspect mtmf_service_1` shows no migrator/admin/bootstrap/owner/
development-user variables.

### Live regression suites (amended tip)

| Suite | Result |
| --- | --- |
| PR 17-B live (`MTMF_PR17B_LIVE=1`) | **13 passed** |
| PR 14 live (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live HTTP/reader (`MTMF_PR17_LIVE=1`) | **26 passed** |

## Not executed (not claimed)

- **N17/N18 Windows-browser** TLS-trust and authorization-code+PKCE checks: a
  real Windows browser is required; reported **NOT EXECUTED**.

## Recorded transient

An *immediate* `preflight` right after `up` can fail with a transient connection
reset while the pre-existing launcher sequencing recreates Keycloak (see
`PR17C_AMENDMENT1_STOP_DEVIATIONS.md`). After Keycloak reaches healthy,
`preflight` passes; the second `up` and all live suites passed. This transient is
present on the base tip and is not caused by the amendment.
