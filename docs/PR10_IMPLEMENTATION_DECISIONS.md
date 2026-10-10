# PR 10 implementation decisions, STOP record, and reconciliation

**Status:** Branch reconciled onto current `main`. The six original STOP gates are
**design-resolved** (PR #35/#36). **Gate M is now policy-approved by PR #38 and
its exact minimum seed is implemented** in additive Alembic revision `0006`,
with database-enforced protection of the built-in SYSTEM Role definitions.

The remaining PR 10 structural foundation is **not implemented**: explicit
`IdentityOrigin`/`TenantLifecycle` entity persistence, the canonical root
registry and bootstrap, ordinary-Tenant stewardship designation/activation, and
DB guards across the legacy mutation paths. Trusted end-user (HTTP/service)
identity and any runtime-callable privileged operation remain deliberately
deferred.

## Refs and baseline

- Branch: `dev/pr10-bootstrap`
- Current base: `origin/main` `35b770a951fc455c8152e25bf90172b8fb36e13a`
  (merge of PR #38)
- Prior bases: `26468b0` (PR #36), `73f965c` (PR #34)
- Working tree clean after the reconciliation rebase

## Historical STOP record (preserved)

The original PR 10 execution plan defined six STOP gates and instructed a STOP
rather than a permissive guess. On the original base none had an approved
decision: STOP-01 trusted identity boundary, STOP-02 built-in Role catalog,
STOP-03 local Identity representation, STOP-04 Tenant activation, STOP-05
transactional trusted boundary, STOP-06 root recovery.

## Reconciliation with PRs #35–#38

- **PR #35** (`PR10_ARCHITECTURE_DECISIONS.md`) design-resolved all six STOP
  gates: separate installation/actor/database trust boundaries; explicit
  SYSTEM-owned built-in Roles with narrow exact-action grants; immutable
  `IdentityOrigin` (`LOCAL`/`FEDERATED`); ordinary Tenant lifecycle
  (`PROVISIONING`/`ACTIVE`/`SUSPENDED`); DB guards across all write paths under
  a deterministic lock order; SYSTEM recovery for ordinary Tenants plus
  operator-only root recovery.
- **PR #36** (`PR10_BUILTIN_ACCESS_AND_INSTALLATION.md`) fixed the
  human-readable built-in Role allocation and the fresh empty-database v0.1
  baseline.
- **PR #37** (`PR10_EXACT_PERMISSION_MANIFEST.md`) enumerated a 34-Action
  candidate catalog. It remains **PROPOSED / candidate-only and unseeded**.
- **PR #38** (`PR10_GATE_M_SEED_POLICY.md`) approved the exact minimum seed:
  **11 SYSTEM Roles / 11 ALLOW PermissionSets / 11 exact Permissions / 3 Action
  definitions / 22 fixed UUIDs**. This is the only authorized seed.

## Gate M — resolved and implemented

The approved PR #38 seed is installed by additive Alembic revision `0006`
(no shipped revision or `v001`–`v005` resource is modified):

- `sql/v006/01_builtin_seed_schema.sql` — the `mtmf.builtin_role` protection
  registry (FK to `mtmf.role`).
- `sql/v006/02_builtin_seed_function.sql` — `mtmf.install_builtin_policy()`
  (owner-owned, `SECURITY INVOKER`, fixed `search_path = ''`) installing the
  literal URNs and 22 UUIDs; identical replay is a no-op and any conflicting
  existing definition raises `MT010` (no silent overwrite/repair).
- `sql/v006/03_builtin_role_protection.sql` — replaces `role_save` so an
  ordinary runtime caller cannot rewrite a registered built-in definition
  (`MT010`); the unchanged signature keeps its reviewed runtime grant and
  `role_add`'s `ON CONFLICT DO NOTHING` cannot replace an existing Role. The
  installer is explicitly **not** granted to `mtmf_runtime`.
- `sql/v006/04_builtin_privilege_assertions.sql` — in-transaction assertions
  (11 Roles / 3 Actions / 11 sets / 11 Permissions / no wildcard / installer not
  runtime- or PUBLIC-executable).
- `migrations/versions/0006_pr10_builtin_policy.py`; `HEAD_REVISION = "0006"`.

Runtime privilege posture is unchanged: the mandatory post-upgrade verifier
still requires the exact 58-signature runtime `EXECUTE` allowlist, no `PUBLIC`
EXECUTE, and no direct table access. The installer is `SECURITY INVOKER` and
absent from the SECURITY DEFINER entry-point inventory.

## Implemented before (approved, non-gated domain vocabulary)

`IdentityOrigin` (`LOCAL=1`,`FEDERATED=2`), `TenantLifecycle`
(`PROVISIONING=0`,`ACTIVE=1`,`SUSPENDED=2`), `TenantLifecycleError`,
`validate_tenant_lifecycle_transition`, and the root/stewardship structural
validators that accept origin/lifecycle, plus tests.

## Not implemented (remaining PR 10 structural work)

- `Identity.origin` / `Tenant.lifecycle` entity, mapper, repository and SQL
  round-trip; lifecycle enforcement in the effective-Role/session path.
- Canonical root registry, bootstrap completion marker, protected bootstrap.
- Ordinary-Tenant stewardship designation persistence, activation/suspension
  primitives, and append-only stewardship audit.
- DB guards across the legacy mutation paths (`tenant_save`, `identity_save`,
  membership-removal functions, Role-assignment removal) for root/steward
  invariants.
- Runtime privilege-manifest changes for those new functions (they must remain
  non-runtime-granted) and the corresponding concurrency tests.
- Trusted end-user/service identity propagation and any user-facing
  transfer/recovery endpoint (explicitly out of scope).

## Evidence (this session)

- `./build.sh --qa` — PASS (Ruff format/lint, strict Mypy, 1192 unit tests,
  coverage ≥ 85%).
- `./build.sh --integration` (real PostgreSQL, configured `MTMF_*`) — PASS,
  443 tests including the new `test_postgres_builtin_policy.py` (exact seed,
  UUIDv5 cross-check, idempotent replay, conflicting-definition fail-closed,
  runtime Role-save denial, installer/PUBLIC denial, registry denial).
- Seed UUIDs independently matched their documented UUIDv5 derivation.

## Merge recommendation

The domain vocabulary and the approved Gate M seed + protection are safe to
review and are covered by QA/integration evidence. **PR 10 as a whole is not
complete**: the root/steward structural foundation and the origin/lifecycle
persistence remain unimplemented, and no privileged capability is
runtime-exposed. The roadmap must not mark PR 10 `[DONE]`.
