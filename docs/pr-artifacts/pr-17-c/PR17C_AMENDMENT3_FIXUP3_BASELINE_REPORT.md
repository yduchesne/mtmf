# PR 17-C Amendment 3 Fixup 3 — Baseline Report

**Branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `d7cec0663772c2ec95e310ebb2f4ef1ab2aa5949` (Fixup 2)
**Comparator:** `main` = `669337c1b496a5660d36e5d72cff5544f6c04722`
**Date:** 2026-10-13
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose`
1.0.6; Keycloak `26.8.0-1`; PostgreSQL 18; Python 3.14.7.

## Status at baseline

- Working tree clean at `d7cec06`; `main` does not contain PR 17-C.
- The standard development realm was `mtmf-pr14-dev`; Fixup 2 had made
  `mtmf-admin` the canonical master-realm administrator.
- Persistent MTMF-owned volumes at baseline:
  `mtmf-dev-keycloak-data` (standard stack), `mtmf_mtmf-postgres-data`
  (standard Postgres), `mtmf-pr14-keycloak-data` (independent PR 14 fixture).

## Current topology (measured)

```text
standard stack issuer : https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
master administrator  : mtmf-admin (enabled, role admin); legacy admins disabled
development user sub  : 5d198663-d3a7-413b-a6fc-269910096799
Keycloak realm/clients: mtmf-pr14-dev, 18 clients
```

## Verified vs unverified

| Capability | Class |
| --- | --- |
| Canonical issuer/TLS/forwarder/Compose lifecycle (old realm) | DONE + previously reported VERIFIED |
| Bounded DNS / cancellation-safe pumps (Fixup 1) | DONE + VERIFIED |
| Canonical master admin `mtmf-admin` (Fixup 2) | DONE + VERIFIED |
| Standard realm `mtmf-dev` configuration | **NOT STARTED** (this fixup) |
| Existing persistent volume conversion | **OUT OF SCOPE / requires separate operator approval** |
| Fresh-objective live evidence for `mtmf-dev` | **NOT STARTED** |

## Mandatory reset decision

This fixup delivers the new configuration and a fresh-environment provisioning
path only. The existing persistent volume is **not** reset, renamed, imported, or
mutated. A branch build can be verified with disposable MTMF-only resources
without touching the operator's volume. Per the plan, the destructive clean
reset is an explicit, separately operator-approved action and was **not
performed** by this execution.

## Old-realm reference search

`git grep -n 'mtmf-pr14-dev' -- ':!docs/pr-artifacts/**'` found 108 references
across 44 files; each is classified in
`PR17C_AMENDMENT3_FIXUP3_REFERENCE_INVENTORY.md`. Only standard-stack active
references were changed.
