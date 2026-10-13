# PR 17-C Amendment 2 — Acceptance Report

**Amended code:** `dev/pr17c-keycloak-issuer` working tree on base `896f472`.
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose` 1.0.6;
Keycloak `quay.io/keycloak/keycloak:26.8.0-1`; PostgreSQL 18.
**Canonical issuer:** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

## Canonical gates (amended tip)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — **2014 passed** (was 2004; +10 LC tests), coverage **90.75%** |
| `./build.sh --sec` | PASS — Bandit Medium/High **0**, Semgrep **0 findings** |
| `./build.sh --rust` | PASS — no native change |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |

## Live lifecycle acceptance (the mandatory, non-mockable part)

### Reproduction before the fix (baseline)

One ordinary `up` recreated all four containers; Compose hashes changed
`3e921d3c… → 2dfb60c6… → af8809e4…` and the log contained `podman stop`/`rm`
for `service`, `initializer`, `forwarder`, `keycloak`, `postgres`. Full
snapshots are in `PR17C_AMENDMENT2_BASELINE_REPORT.md`.

### After the fix

**Transition run** (first `up` with the new static model): one expected recreate;
all containers then carried the stable hash `1840ce6acd500bbc…`.

**Three consecutive unchanged `up` cycles:**

| Cycle | `up` exit | `podman stop`/`rm` lines | IDs + `StartedAt` | immediate `preflight` |
| --- | --- | --- | --- | --- |
| 1 | 0 | 0 | IDENTICAL | exit 0 (host + container OK) |
| 2 | 0 | 0 | IDENTICAL | exit 0 (host + container OK) |
| 3 | 0 | 0 | IDENTICAL | exit 0 (host + container OK) |

PostgreSQL, Keycloak, forwarder and service kept the same container IDs and
`State.StartedAt` across every cycle.

**`down` → `up` with preserved volumes (step 6):** `down` removed only MTMF
containers and preserved both MTMF volumes; the new `up` had `stop/rm=0`
(no recreation after initial start), the same stable Compose hash, `preflight`
exit 0, and the Keycloak development user `sub`
(`5d198663-d3a7-413b-a6fc-269910096799`) persisted unchanged.

**Live canonical routing:** the running service resolves
`keycloak.mtmf.test → 10.89.26.111` (the current forwarder), even though the
copied `/etc/hosts` still contains `127.0.0.1 keycloak.mtmf.test`, and
`/etc/nsswitch.conf` in the container is `hosts: dns files`. Discovery `issuer`,
`jwks_uri` and token `iss` remained exactly canonical.

**Isolation / exposure (live `podman inspect`):**

```text
mtmf_postgres_1:  net=bridge publish=[127.0.0.1:25432->5432/tcp]
mtmf_keycloak_1:  net=bridge publish=[127.0.0.1:28080->8080/tcp, 127.0.0.1:28443->8443/tcp]
mtmf_forwarder_1: net=bridge publish=none
mtmf_service_1:   net=bridge publish=[127.0.0.1:28001->28001/tcp]
```

The service environment contains no migrator/admin/bootstrap/owner/
development-user variables.

## Live regression suites (amended tip)

| Suite | Result |
| --- | --- |
| PR 17-B live (`MTMF_PR17B_LIVE=1`) | **13 passed** |
| PR 14 live (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live HTTP/reader (`MTMF_PR17_LIVE=1`) | **26 passed** |

## Failure classification

- **Fixed:** the Compose configuration-hash recreation was an **introduced
  regression** from the dynamic `extra_hosts` IP in PR 17-C; now proven absent.
- **Mitigated / recorded:** the intermittent container-namespace TLS handshake
  timeout through the forwarder is a **deterministic pre-existing failure** in
  `scripts/mtmf-dev-forwarder.py`'s long-running event loop (direct keycloak
  connections were 0/15 failures; forwarder connects occasionally took 5–23 s).
  It is recorded in `PR17C_AMENDMENT2_STOP_DEVIATIONS.md`; the forwarder file was
  left unchanged and `preflight()` uses the bounded probe retry already used by
  `up()`.
- **Not executed:** live LC13 (rebuilding only the forwarder) was skipped to
  avoid disturbing the preserved stack; the plan marks it optional and the
  deterministic counterpart passes.
- **Unchanged:** Windows-browser N17/N18 remain **NOT EXECUTED**.
