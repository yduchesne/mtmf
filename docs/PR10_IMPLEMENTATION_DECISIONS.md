# PR 10 implementation decisions, STOP record, and reconciliation

**Status:** Branch reconciled onto current `main`; the six original STOP gates are
**design-resolved** by merged PRs #35 and #36. The exact built-in
Action/Permission seed manifest (**Gate M**) still requires explicit human
approval, so bootstrap/seed/persistence are **BLOCKED and not implemented**. The
approved, non-gated structural domain vocabulary is implemented.

## Refs and baseline

- Branch: `dev/pr10-bootstrap`
- Rebased onto `main` `26468b021ceb4f4fc5041dfc9d23e90145401700` (merge of PR #36)
- Prior base: `73f965caac8294f93a45334a35f919f7c9486321` (merge of PR #34)
- Working tree clean after the reconciliation rebase

## Historical STOP record (preserved)

The original PR 10 execution plan defined six STOP gates and instructed a STOP
rather than a permissive guess. On the original base, none of them had an
approved decision:

| Gate | Original subject |
|---|---|
| STOP-01 | Trusted end-user identity boundary for privileged SQL |
| STOP-02 | Built-in Role/Permission catalog and Tenant Administrator composition |
| STOP-03 | Local vs federated Identity representation |
| STOP-04 | Explicit Tenant provisioning/activation state |
| STOP-05 | Transactional trusted authorization + write boundary |
| STOP-06 | Root recovery runbook and credential custody |

That STOP was recorded in the first version of this document; the structural
domain slice (`domain/stewardship.py`, errors, exports, tests) was delivered
without privileged persistence. That history is retained below as the reason the
migration/seed was not written at that time.

## Reconciliation with PRs #35 and #36

- **PR #35** merged `docs/PR10_ARCHITECTURE_DECISIONS.md`, which **design-resolves
  all six STOP gates** (design resolved; implementation still pending):
  separate installation/actor/database trust boundaries; explicit SYSTEM-owned
  built-in Roles with narrow exact-action grants; immutable `IdentityOrigin`
  (`LOCAL`/`FEDERATED`); ordinary Tenant lifecycle
  `PROVISIONING`/`ACTIVE`/`SUSPENDED`; DB guards across all write paths under a
  deterministic lock order; SYSTEM recovery for ordinary Tenants plus separate
  operator-only root recovery.
- **PR #36** merged `docs/PR10_BUILTIN_ACCESS_AND_INSTALLATION.md`, which fixes
  the human-readable built-in Role allocation, contributor/reader boundaries,
  exact-action seeding policy, and the **fresh empty-database v0.1 installation
  baseline** (no legacy-data migration; explicit `LOCAL`/`FEDERATED`; no
  `UNKNOWN`).

After reconciliation the STOP table above is superseded. The authoritative
status of each gate is now:

| Gate | Design | Structural implementation | Trusted invocation | Runtime-exposed |
|---|---|---|---|---|
| STOP-01 | Resolved (PR #35) | Not started | Not available | No (correct) |
| STOP-02 | Policy allocation resolved (PR #36); exact manifest **not approved** | Blocked (Gate M) | n/a | No |
| STOP-03 | Resolved: `IdentityOrigin` `LOCAL`/`FEDERATED` | Vocabulary delivered; entity/schema wiring not started | n/a | n/a |
| STOP-04 | Resolved: `TenantLifecycle` | Vocabulary/transition validator delivered; entity/schema wiring not started | n/a | n/a |
| STOP-05 | Resolved (PR #35) | Not started | n/a | No |
| STOP-06 | Resolved (PR #35) | Not started | n/a | No |

## Gate M — the remaining blocker

`PR10_BUILTIN_ACCESS_AND_INSTALLATION.md` and `PR10_ARCHITECTURE_DECISIONS.md`
both state that the **exact executable seed manifest** (Role URN →
PermissionSet identity → Permission identity → exact Action URN/effect →
enforcement point) must be reviewed and approved before any migration seeds it,
and that unsupported operations must be omitted rather than guessed. No such
approval exists in this execution environment. Consequently:

- No `docs/PR10_EXACT_PERMISSION_MANIFEST.md` inventory was approved.
- No built-in Role/PermissionSet/Permission/Action was seeded.
- No bootstrap/installer, activation, transfer, or recovery function was
  written or granted.
- No Alembic `0006` / packaged `sql/v006` was written, because the manifest and
  the root/steward schema shape depend on that approval.

This is the amendment's own STOP condition #2 ("Gate M exact Role/Permission
manifest has not received explicit human approval before seed SQL is written")
and the final rule "STOP when the trust boundary or exact seed manifest is
unresolved."

## Implemented in this session (approved, non-gated, additive)

The following approved domain vocabulary and pure structural validation were
added without touching persistence, privileges, or the built-in policy:

- `mtmf_core.domain.lifecycle.IdentityOrigin` — exact `LOCAL = 1`,
  `FEDERATED = 2`; no `UNKNOWN`.
- `mtmf_core.domain.lifecycle.TenantLifecycle` — exact `PROVISIONING = 0`,
  `ACTIVE = 1`, `SUSPENDED = 2`.
- `mtmf_core.domain.errors.TenantLifecycleError`.
- `mtmf_core.domain.stewardship.validate_tenant_lifecycle_transition(...)` —
  pure structural transition rules: root must remain `ACTIVE`; ordinary
  transitions limited to `PROVISIONING→ACTIVE`, `ACTIVE→SUSPENDED`,
  `SUSPENDED→ACTIVE` (same-state no-op allowed).
- `validate_root_bootstrap_record(...)` accepts optional
  `root_identity_origin` (must be `LOCAL`) and `root_tenant_lifecycle` (must be
  `ACTIVE`).
- `validate_stewardship_designation(...)` accepts optional `tenant_lifecycle`
  (must be `ACTIVE`).
- Public exports from `mtmf_core.domain` / `mtmf_core`.
- Tests in `tests/unit/core/test_stewardship.py` (37 tests total).

These are **structural only**: they do not authenticate a caller, authorize an
Action, resolve/assign Roles, grant dominance, read a session, persist state,
touch PostgreSQL, or define a privileged boundary. Providing the origin/lifecycle
facts to the validators remains the trusted caller's responsibility.

## Blocked / not implemented (requires Gate M or the trusted actor boundary)

- Alembic revision `0006`, packaged `sql/v006/*`, schema/constraints/triggers.
- `Identity.origin` / `Tenant.lifecycle` entity and persistence wiring
  (round-trip, immutability, repository/DTO propagation).
- Effective-Role/session enforcement of `TenantLifecycle`.
- Root registry, bootstrap completion marker, stewardship designation
  persistence and append-only audit.
- Deterministic built-in Role/Permission/Action seed.
- Protected bootstrap/activation/transfer/recovery primitives and DB guards on
  existing v002/v004/v005 write paths.
- Runtime privilege-manifest update and postflight verification for `0006`.
- Real-PostgreSQL and concurrency tests for the above.

## Required decisions to proceed

1. **Gate M:** approve the complete, explicit built-in Action/Permission seed
   manifest (or explicitly split a prerequisite manifest PR).
2. Confirm the root/steward schema shape and lock ordering for migration `0006`.
3. Confirm the trusted actor/installation boundary so privileged operations can
   be implemented without runtime grants. Until then they stay inaccessible.

## Evidence

- Branch reconciliation: rebase onto `26468b0`; clean tree; no force-reset; the
  original branch commit content was preserved.
- `./build.sh --qa` (run on the final tree; see the implementation report):
  Ruff format/lint, strict Mypy, unit suite, coverage gate.
- No migration/privileged/seed feature evidence exists because none was
  implemented.

## Merge recommendation

The additive approved domain vocabulary is safe to review. **PR 10
Amendment #1 as a whole is do-not-merge / incomplete:** Gate M is unresolved, so
bootstrap, built-in policy, persistence, and all privileged operations remain
unimplemented and runtime-inaccessible. The roadmap must not mark PR 10 `[DONE]`.
