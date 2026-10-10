# PR 10 implementation decisions, STOP record, and reconciliation

**Status:** The six original STOP gates are design-resolved (PR #35/#36). Gate M
is approved (PR #38) and its exact minimum seed is installed (revision `0006`).
The explicit Identity `origin` / Tenant `lifecycle` persistence (`0007`) and the
protected root bootstrap + ordinary-Tenant stewardship designation, audit, and
legacy-write guards (`0008`) are implemented and verified on real PostgreSQL.

**Not complete:** the full Amendment #2 concurrency matrix is only partially
covered, and trusted end-user (HTTP/service) identity — and therefore any
runtime-callable transfer/recovery — remains deliberately deferred. PR 10 is
**not** `[DONE]`.

## Refs and baseline

- Branch: `dev/pr10-bootstrap`
- Base: `origin/main` `35b770a` (PR #38)
- Delivered additive revisions: `0006` (built-in seed), `0007`
  (origin/lifecycle), `0008` (root/stewardship)

## Historical STOP record (preserved)

The original plan defined six STOP gates (trusted identity, built-in catalog,
local Identity, Tenant activation, transactional trusted boundary, recovery).
The PR #35/#36/#38 decision documents resolved them: separate
installation/actor/database trust boundaries; explicit SYSTEM-owned built-in
Roles with exact-action grants; immutable `IdentityOrigin`; explicit
`TenantLifecycle`; a deterministic lock order; and operator-only root recovery.

## Delivered

### Revision `0006` — approved Gate M built-in policy
Exactly 11 SYSTEM Roles / 11 ALLOW PermissionSets / 11 exact Permissions / 3
Actions / 22 fixed UUIDs, installed idempotently; conflicting definitions fail
closed; SYSTEM Role definitions are protected from ordinary `role_save`; the
installer is not runtime- or PUBLIC-executable.

### Revision `0007` — Identity origin and Tenant lifecycle
- Immutable `identity.origin` (`LOCAL=1`/`FEDERATED=2`), with conservative
  backfill (`FEDERATED`) for any pre-existing row and an immutability guard.
- `tenant.lifecycle` (`PROVISIONING=0`/`ACTIVE=1`/`SUSPENDED=2`), independent
  of soft deletion, with a root-must-be-ACTIVE check and a conservative
  `PROVISIONING` backfill.
- Updated entity read/write functions and the exact 58-signature runtime
  `EXECUTE` allowlist.
- `EffectiveRoleResolver` fails closed for PROVISIONING/SUSPENDED Tenants
  before Role evaluation.

### Revision `0008` — protected root and Tenant stewardship
- `root_registry` singleton (canonical root Tenant/Principal + designated LOCAL
  root Identity), `stewardship_designation` (`PK(tenant_id)`), and append-only
  `stewardship_audit`.
- Installation-only `SECURITY INVOKER` primitives, **never** runtime-granted:
  `bootstrap_root` (serialized, idempotent, fail-closed), `designate_steward`
  (version CAS + eligibility + audit), `activate_tenant`/`suspend_tenant`,
  `recover_root_identity`.
- Structural eligibility predicate `stewardship_is_eligible` (ordinary active
  Tenant, active Principal/Identity, explicit memberships, direct or
  group-derived Tenant Administrator Role).
- Database guards: root Tenant/Principal/Identity cannot be deleted,
  suspended, deactivated, reclassified, or reassigned; root and current-steward
  prerequisite memberships cannot be removed; the steward's final Tenant
  Administrator assignment cannot be revoked; an ordinary Tenant cannot become
  ACTIVE without a designation; runtime `tenant_add` must create ordinary
  Tenants PROVISIONING.
- All privileged functions are owner-owned `SECURITY INVOKER`, PUBLIC-revoked,
  and absent from the runtime allowlist; the mandatory post-upgrade verifier
  remains the exact 58-signature contract.

## Not implemented / deferred

- The Amendment #2 concurrency matrix is partially covered: deterministic
  two-connection bootstrap and designation races exist, but the full
  minimum-10-cycle protocol across every race (transfer vs deactivation,
  activation vs setup, root recovery vs deletion) is not complete.
- Trusted end-user/service identity propagation; user-facing
  transfer/recovery endpoints. Privileged operations remain inaccessible to
  ordinary runtime callers by design.

## Evidence

- `./build.sh --qa` — PASS (Ruff format/lint, strict Mypy, 1196 unit tests,
  coverage ≥ 85%).
- `./build.sh --sec` — PASS (Bandit Medium/High 0; Semgrep 0 findings).
- `./build.sh --integration` (real PostgreSQL, configured `MTMF_*`) — PASS,
  471 tests, including `test_postgres_origin_lifecycle.py`,
  `test_postgres_root_stewardship.py`, and `test_postgres_builtin_policy.py`.

## Merge recommendation

The seed, origin/lifecycle persistence, and protected root/stewardship
foundation are implemented and verified. PR 10 Amendment #2 is **not complete**
(full concurrency matrix and deferred trusted-user exposure), so the roadmap
must not mark PR 10 `[DONE]`.
