# PR 18 Fixup 1 — STOP / Deviations Register

No unresolved mandatory STOP condition. This register distinguishes
approved deviations from environment limitations.

## 1. Approved deferrals (unchanged by this fixup)

### 1.1 Controlled service-token-expiry `401` retry
- **Status:** deferred by contract (approved prior to fixup).
- **Reason:** PR 17 exposes no machine-readable service-token-expiry signal;
  a retry would retry arbitrary 401s. No retry path exists.
- **Unchanged by fixup.**

### 1.2 Universal 15-second snapshot cap
- **Status:** preserved conservative deviation (approved prior to fixup).
- **Reason:** the authoritative Action sensitivity classifier is not a public
  contract. `_build_snapshot` was intentionally not modified.
- **Unchanged by fixup.**

## 2. Environment / harness notes

### 2.1 Ephemeral development credentials (previously reported, resolved)
The earlier interruption cleared `/tmp` development secret files and stopped
the containers. The stack was restored non-destructively and the live slice
continues to use one **additive, disposable** Keycloak user that is deleted
after the run. No existing fixture user/client, volume, or PR 14 evidence was
mutated or reset. No `podman` destroy/prune/reset was executed.

### 2.2 Keycloak restart is NOT TESTED
The fixup plan authorizes only an owned-Uvicorn restart. Restarting the
shared development Keycloak would disrupt the operator environment, so it is
explicitly **NOT TESTED**; a human reviewer decides whether a separate,
fully isolated disposable Keycloak restart gate is required. This is not
waived by the coding agent.

## 3. Breaking API change (intentional, non-deviating)

`is_allowed`/`require` now require `action` and `resource`. This is a
deliberate pre-merge hardening, recorded as a compatibility break in
`PR18_FIXUP1_API_CONTRACT_AND_TEST_MATRIX.md`. No external consumer depends
on the old signature within this repository.

## 4. Migration completeness

All in-repository call sites were migrated: unit tests, live tests, and the
README example. No `is_allowed`-style assertion was deleted, weakened, or
changed from DENY to ALLOW. `mtmf-api`, PR 17, Keycloak realm, PostgreSQL
schema, and the Rust engine were not modified.

## 5. Unresolved issues

None. All required gates and the three live runs passed; no mandatory
failure or unexecuted required gate remains other than the explicitly
out-of-scope Keycloak restart.
