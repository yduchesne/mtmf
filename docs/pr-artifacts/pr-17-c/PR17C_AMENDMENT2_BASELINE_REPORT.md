# PR 17-C Amendment 2 — Baseline Report

**Base branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `896f472` (PR 17-C Amendment 1: exact issuer/JWKS + fail-closed PKI)
**Comparator:** `main` = `669337c1b496a5660d36e5d72cff5544f6c04722`
**Date:** 2026-10-13
**Environment:** Windows browser → Ubuntu 24.04.5 WSL2 → rootless Podman 4.9.3,
`podman-compose` 1.0.6 (netavark, rootless); Keycloak `quay.io/keycloak/keycloak:26.8.0-1`;
PostgreSQL 18; canonical issuer `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

Amendment 1 (exact issuer/JWKS validation and fail-closed PKI state) is present and
was preserved. No source was changed before the measurements below.

## Reproduced defect (measured, not assumed)

A single `python scripts/mtmf-dev-stack.py up` recreated **all four** MTMF
containers (`postgres`, `keycloak`, `forwarder`, `service`). Evidence:

`podman inspect` snapshots (ID / `State.StartedAt` / config-hash) before and after
one ordinary `up`:

```text
BEFORE (hash 3e921d3c…):
  mtmf_postgres_1  id=6381e2743d76 started=2026-10-13T07:06:31…
  mtmf_keycloak_1  id=1a211f7e841b started=2026-10-13T07:01:23…
  mtmf_forwarder_1 id=aaaaa72692ac started=2026-10-13T07:01:26…
  mtmf_service_1   id=edfc63ddc29a started=2026-10-13T07:01:33…

AFTER (hash af8809e4…, all four IDs/timestamps changed):
  mtmf_postgres_1  id=c732a076fd97 started=2026-10-13T07:28:42…
  mtmf_keycloak_1  id=2cfbc3be7023 started=2026-10-13T07:28:45…
  mtmf_forwarder_1 id=41a69f91c58b started=2026-10-13T07:28:48…
  mtmf_service_1   id=b98c7ec613aa started=2026-10-13T07:28:55…
```

The launcher log shows two different Compose config hashes and explicit
recreation:

- first invocation `compose up -d postgres keycloak forwarder` → hash
  `2dfb60c60de0…` (because `MTMF_DEV_FORWARDER_IP` was unset, so the
  interpolated `extra_hosts` used the default `127.0.0.1`);
- later invocation `compose up -d service` → hash `af8809e490fc…` (after the
  launcher set `MTMF_DEV_FORWARDER_IP` to the discovered forwarder address);
- the log contains `podman stop -t 10` / `podman rm` for `service`,
  `initializer`, `forwarder`, `keycloak`, and `postgres`.

## Root cause (demonstrated)

`compose.dev.yaml` interpolated the dynamic forwarder address into both
`initializer` and `service`:

```yaml
extra_hosts:
  - "keycloak.mtmf.test:${MTMF_DEV_FORWARDER_IP:-127.0.0.1}"
```

`podman-compose 1.0.6` derives a **project-wide** configuration hash from the
rendered model and recreates containers when it changes. `up()` discovers the
forwarder address only after infrastructure is created and then exports
`MTMF_DEV_FORWARDER_IP` mid-run, so the second invocation renders a different
model and recreates every container. Because the forwarder address is
re-assigned across restarts, the hash also changed between repeated `up` runs,
so even a repeated unchanged `up` recreated infrastructure.

The cause is exactly the plan's stated mechanism and is confirmed by rendered
config hashes and container identity changes, not by inference.

## Secondary pre-existing finding (out of Amendment 2 scope)

While validating the required immediate post-`up` `preflight`, the standalone
`preflight` command was observed to fail intermittently (~40% of runs) with a
container-namespace TLS handshake timeout through the forwarder. Diagnosis:

- direct host `https://127.0.0.1:28443` and direct container `keycloak:8443`
  connections were reliable (0/15 failures);
- instrumentation showed the forwarder received the ClientHello immediately but
  its `asyncio.open_connection("keycloak", 8443)` occasionally took 5–23 s
  inside the long-running process (while a fresh process resolved/connected in
  <25 ms).

This is a pre-existing defect in `scripts/mtmf-dev-forwarder.py`'s event-loop
handling, unrelated to the Compose configuration hash. It is recorded in
`PR17C_AMENDMENT2_STOP_DEVIATIONS.md`; the forwarder file was left at its
committed state, and `preflight()` uses the same bounded probe retry as `up()`
(which already retried) so the mandatory acceptance is not flaky. The core
lifecycle invariant is proven independently by container identity/timestamp
snapshots.

## Reconciliation classification

| Capability | Class |
| --- | --- |
| Amendment 1 exact issuer/JWKS/PKI hardening | DONE + VERIFIED (preserved, tests pass) |
| PR 17-C canonical forwarder/TLS/loopback topology | DONE + VERIFIED (preserved) |
| Stable Compose model across staged `up` | NOT STARTED (this amendment) |
| Immediate `preflight` reliability | PARTIAL — forwarder transport transient mitigated by bounded probe retry; forwarder defect recorded for a separate fix |
