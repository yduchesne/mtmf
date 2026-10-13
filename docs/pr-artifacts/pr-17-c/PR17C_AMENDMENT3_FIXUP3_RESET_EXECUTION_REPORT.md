# PR 17-C Amendment 3 Fixup 3 — Clean-Reset Execution Report

**Branch:** `dev/pr17c-keycloak-issuer`
**Executed against tip:** `4d16070` (Fixup 3)
**Date:** 2026-10-13
**Authorization:** Explicit user instruction to execute the documented clean-reset
procedure in `docs/DEVELOPMENT_SETUP.md` and verify the new environment.

## Summary

The documented destructive clean reset was executed on the standard MTMF
development environment. The old `mtmf-pr14-dev` Keycloak realm and the old
PostgreSQL MTMF state were discarded, and a fresh canonical `mtmf-dev`
environment was provisioned and verified. Only the two standard-stack volumes
were removed; the independent PR 14 evidence volume and all host CA material
were preserved.

## Pre-reset inventory (Step 2)

```text
containers: mtmf_postgres_1 (up, healthy); keycloak/forwarder/service stopped
volumes   : mtmf-dev-keycloak-data, mtmf_mtmf-postgres-data, mtmf-pr14-keycloak-data
CA material: /tmp/mtmf-dev-ca/dev-ca.crt present (preserved)
old issuer : https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev
old dev sub: 5d198663-d3a7-413b-a6fc-269910096799
```

## Procedure executed (per `docs/DEVELOPMENT_SETUP.md`)

1. **Operator consent** confirmed by the user's explicit instruction.
2. **Inventory recorded** (above); the independent PR 14 fixture volume identified.
3. **`scripts/mtmf-dev-stack.py down`** — exit 0, all standard `mtmf_*` containers
   removed, volumes preserved.
4. **Removed only the two standard-stack volumes** —
   `podman volume rm mtmf-dev-keycloak-data mtmf_mtmf-postgres-data` (exit 0).
   `mtmf-pr14-keycloak-data` was **not** removed.
5. **New `mtmf-admin` credential prepared** in an owner-only file outside
   `/tmp` (`~/.config/mtmf/dev-admin.env`, mode `0600`, not committed).
6. **Clean stack started and provisioned**:
   - PostgreSQL 18 up and healthy; `scripts/mtmf-provision-roles.py` created the
     `mtmf_migrator`/`mtmf_runtime` roles (restricted runtime);
   - fresh Keycloak up and healthy, bootstrapping `mtmf-admin` from
     `MTMF_DEV_KC_ADMIN_PASSWORD`;
   - `dev/keycloak/setup-realm.py --realm mtmf-dev --allow-nonlocal` provisioned
     the `mtmf-dev` realm and approved clients;
   - `scripts/mtmf-dev-stack.py up` ran the privileged initializer and started
     the restricted service (exit 0).
7. **Verification** (below).

## Verification of the new environment (Step 7)

| Check | Result |
| --- | --- |
| Discovery `issuer` | exactly `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| Discovery `jwks_uri` | exactly `.../realms/mtmf-dev/protocol/openid-connect/certs` |
| Token `iss` | exactly `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| Old realm `mtmf-pr14-dev` | **HTTP 404** (absent) |
| Master admins | only `mtmf-admin` (enabled); `mtmf-pr14-admin` / `mtmf-pr14-admin2` **absent** |
| Realms | `mtmf-dev`, `master` |
| New development user `sub` | `fc5d09c1-e7be-4a61-bc0d-1b0559429fdc` (changed from `5d198663-…`) |
| Service readiness | `http://127.0.0.1:28001/health/ready` = **200** |
| MTMF identity binding | initializer completed; binding created for the new `sub` |
| TLS | development CA/SAN validated throughout |

## Stability and reliability on the reset environment

- **Three consecutive unchanged `up` cycles**: each exit 0, 0 unexpected
  `podman stop`/`rm`, identical container IDs and `State.StartedAt`.
- **Forwarder reliability**: **100/100** sequential first-attempt TLS
  discovery+JWKS (max 0.056 s), **50/50** at concurrency 10 (max 0.129 s),
  **30/30** direct-to-Keycloak control.
- **Live regressions**: PR 17-B **13/13**, PR 14 **22/22**, PR 17 **26/26**
  against the real `mtmf-dev` environment.

## Canonical gates (committed fixup tip `4d16070`, re-confirmed in the prior report)

```text
./build.sh --qa           2153 passed, coverage 90.75%
./build.sh --sec          0 findings
./build.sh --rust         PASS
./build.sh --integration  564 passed, 65 skipped
```

## Resources

| Resource | Disposition |
| --- | --- |
| `mtmf-dev-keycloak-data` | **Removed** (explicitly authorized) |
| `mtmf_mtmf-postgres-data` | **Removed** (explicitly authorized) |
| `mtmf-pr14-keycloak-data` | **Preserved** (independent PR 14 fixture) |
| `/tmp/mtmf-dev-ca` CA/leaf material | **Preserved** |
| Other projects' resources | **Untouched** |

## Post-reset state

The standard MTMF development stack is running the canonical `mtmf-dev` realm
with `mtmf-admin` as the sole master administrator, a fresh development-user
`sub`, and a matching MTMF identity binding. The independent PR 14 evidence
fixture is unchanged and remains on `mtmf-pr14-dev`. PR 17-C remains
**AWAITING HUMAN REVIEW — NOT DONE**; the Windows N17/N18 gate classification
and merge approval remain human decisions.
