# PR 23 — Baseline and Scope Reconciliation

**Roadmap item:** PR 23 — Identity, Principal, and Tenant membership provisioning
**Branch:** `dev/pr23-verified-subject-stewardship`
**Verified base:** `main` @ `1bb46af8a8fe780be23521954e130ef895906ab9` (merged PR #74, 2026-11-03)
**Base migration head:** `0014` / `0014_pr22_onboarding_entitlement`
**New migration head:** `0015` / `0015_pr23_initial_stewardship`
**PostgreSQL:** 18.6 (Debian 18.6-1.pgdg13+2), `127.0.0.1:25432/mtmf`
**Date:** 2026-11-11

## Source reconciliation

`git fetch`/branch creation was not required: the working checkout was already
at the plan's verified baseline SHA. A clean branch was created from it.

```text
HEAD   = 1bb46af8a8fe780be23521954e130ef895906ab9
main   = 1bb46af8a8fe780be23521954e130ef895906ab9
origin = 1bb46af8a8fe780be23521954e130ef895906ab9
git status --porcelain=v1  -> clean before edits
git fsck --full            -> clean
git diff --check           -> clean
```

`git grep -n -E 'PreTenant|pre_tenant|onboarding_subject|INITIAL_ONBOARDING|initial_steward|stewardship_audit_operation_check'`
found only the v008 `stewardship_audit_operation_check` definition and no
pre-existing PR 23 implementation. No PR 24P topology or privileged executor
was present.

## Capability matrix at baseline

| # | §4 capability | Baseline classification | After PR 23 |
| --- | --- | --- | --- |
| 1 | Provider-neutral immutable pre-Tenant verified-subject result | NOT-STARTED | DONE+VERIFIED (unit, real PostgreSQL, and live genuine-token proof) |
| 2 | Shared PR 14 token-pair verification reuse | DONE+VERIFIED (inline in `AuthenticatedActorContextService`) | DONE+VERIFIED (extracted `_verify_token_pair`; old tests unchanged) |
| 3 | Read-only Application + optional global Identity/Principal resolution | NOT-STARTED | DONE+VERIFIED |
| 4 | Owner-only global subject resolution/creation SQL participant | NOT-STARTED | DONE+VERIFIED |
| 5 | Owner-only strict initial-stewardship SQL participant | NOT-STARTED | DONE+VERIFIED |
| 6 | Additive migration `0015` with audit operation extension | NOT-STARTED | DONE+VERIFIED |
| 7 | Test-only single-transaction owner harness | NOT-STARTED | DONE+VERIFIED |
| 8 | Unit acceptance A-U01…A-U18 | NOT-STARTED | DONE+VERIFIED |
| 9 | Real-PostgreSQL acceptance P23-I01…P23-I22 | NOT-STARTED | DONE+VERIFIED |
| 10 | Genuine Keycloak L01…L04 | NOT-STARTED | DONE+VERIFIED (4 passed; approved `mtmf-dev` fixture selection) |
| 11 | Rust native gate | DONE on prior PRs | DONE+VERIFIED (rustup stable 1.99.1; `./build.sh --rust` passed) |

## Existing assets reused (not recreated)

- `Principal`, `Identity`, typed memberships, `Tenant`, `IdentityRoleAssignment`,
  `ExternalSubjectBinding`, `RootRegistryRecord`.
- `AuthenticatedActorContextService` and its attestor/verifier seams.
- v004 membership, v005 role-assignment, v008 root/stewardship, v011
  authentication-binding, and v014 entitlement SQL.
- `PostgresMtmfSpi` runtime-only provider (constructor/role restriction
  untouched).
- Integration fixtures `db`, `migrator_config`, `runtime_connection`,
  `postgres_spi`, and the real `mtmf_owner`/`mtmf_migrator`/`mtmf_runtime`
  topology.

## Explicit non-delivery

No Tenant creation/activation, quota consumption, replay ledger, registration/
subscription mutation, onboarding HTTP, CLI, privileged PR 24P executor, new
Role/Action seed, new runtime grant, or `SECURITY DEFINER` privilege proxy was
added. PR 22B/24P/24–26 remain unimplemented.
