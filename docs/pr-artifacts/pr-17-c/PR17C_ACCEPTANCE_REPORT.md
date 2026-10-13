# PR 17-C Acceptance Report

**Final code revision under test:** working tree on `dev/keycloak`, base
`669337c1b496a5660d36e5d72cff5544f6c04722` plus the PR 17-C changes.
**Environment:** Windows browser → Ubuntu 24.04.5 WSL2 → rootless Podman 4.9.3 /
`podman-compose` 1.0.6; Keycloak `26.8.0-1`; PostgreSQL 18.
**Topology:** canonical `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev` via
the MTMF-owned forwarder; isolated `mtmf` Compose network; no host networking.

## Canonical repository gates (all on the final code)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — Ruff format/lint, strict Mypy, unit suite **1947 passed**, coverage **90.75%** (≥85%) |
| `./build.sh --sec` | PASS — Bandit (Medium/High gate) + Semgrep registry rules, **0 findings** |
| `./build.sh --rust` | PASS — cargo fmt/clippy/test, `maturin develop`, native probe, focused tests, clean wheel, benchmark smoke |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** (live-Keycloak tests skipped without opt-in) |

## Real live acceptance (final code)

### Standard isolated `up` — no host networking

```text
$ python scripts/mtmf-dev-stack.py up
preflight[host]      dns keycloak.mtmf.test -> 127.0.0.1
preflight[host]      tcp keycloak.mtmf.test:28443 reachable
preflight[host]      tls verified against /tmp/mtmf-dev-ca/dev-ca.crt
preflight[host]      discovery issuer == https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
preflight[host]      jwks … contains 2 key(s)
preflight[container] dns keycloak.mtmf.test -> … 10.89.26.x
preflight[container] tls verified against /certs/mtmf-ca.crt
preflight[container] discovery issuer == https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
development initialization complete
MTMF development stack is ready
exit 0
```

- **Restart idempotency:** a second `up` returned exit 0; PostgreSQL row counts for
  tenant/principal/identity/application/subscription/membership were **identical**
  (diff empty) and the Keycloak `mtmf-dev-user` count stayed 1.
- **Teardown:** `down` removed only `mtmf_*` containers and preserved the
  `mtmf-dev-keycloak-data` and `mtmf-postgres-data` volumes; a subsequent `up`
  recreated the stack with the canonical issuer stable.

### Isolation and exposure (redacted `podman inspect`)

```text
mtmf_postgres_1:  net=bridge publish=[127.0.0.1:25432->5432/tcp]
mtmf_keycloak_1:  net=bridge publish=[127.0.0.1:28080->8080/tcp, 127.0.0.1:28443->8443/tcp]
mtmf_forwarder_1: net=bridge publish=none
mtmf_service_1:   net=bridge publish=[127.0.0.1:28001->28001/tcp]  extra_hosts=[keycloak.mtmf.test:<forwarder-ip>]
```

`podman inspect mtmf_service_1` confirmed **no** migrator/admin/bootstrap/owner/
development-user variables and only a read-only public-CA mount.

### Negative controls (fail closed)

- missing CA → `cannot load the development CA file` (no insecure retry);
- untrusted/wrong CA → TLS verification failure;
- wrong realm → discovery failure, no fallback;
- container DNS pinned to an unreachable endpoint → `Connection refused`;
- SAN mismatch (`--hostname other.mtmf.test check`) → `missing SAN DNS:other.mtmf.test`.

### Existing authoritative live regression suites (canonical issuer)

| Suite | Result |
| --- | --- |
| PR 17-B live acceptance (`MTMF_PR17B_LIVE=1`) | **13 passed** — includes I10, I12, I13/I14, I15a/b/c, I18, I20, SH16, PV01–PV03 (strict created-resource `Location`) |
| PR 14 live actor context (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live HTTP/reader (`MTMF_PR17_LIVE=1`) | **26 passed** |

The only source change required to run these against the canonical issuer was the
evidence collector's `Issuer.guard()` approved-host set (see the security review);
assertions were not weakened.

## Not executed (not claimed)

- **N17** Windows browser canonical HTTPS discovery.
- **N18** real Windows-browser auth-code+PKCE login.
- **N12-live** deliberately breaking the forwarder and restoring it (unit coverage
  exists; the live break/restore was not run).

These require a real Windows browser / interactive operator and are recorded as
operator/manual acceptance in the test matrix and deviation register. No PASS is
claimed for them.
