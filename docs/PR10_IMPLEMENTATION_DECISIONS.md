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

## Concurrency and lock ordering

The privileged mutation paths share one documented lock order:
**Tenant row → subject Principal/Identity rows → designation row** (the root
path adds the fixed bootstrap advisory lock first). `bootstrap_root` serializes
on `pg_advisory_xact_lock('mtmf.bootroot')`; `designate_steward` and
`activate_tenant` lock the successor/bound Principal and Identity rows `FOR
UPDATE` before the eligibility read, which closes the read-then-write
write-skew where a concurrent deactivation could otherwise commit after
eligibility was read.

`tests/integration/postgres/test_postgres_stewardship_concurrency.py` runs
**13 race scenarios with 10 cycles each** (130 race cycles), two-plus
independent connections, a `threading.Barrier`, bounded
`statement_timeout`/`lock_timeout`, and explicit SQLSTATE + committed-state
assertions:

- concurrent bootstrap (one canonical root, one audit event);
- concurrent transfer vs transfer (one winner, one `MT012`);
- transfer vs incumbent Principal / Identity deactivation;
- transfer vs final Tenant Administrator revocation;
- transfer vs successor Principal / Identity deactivation (`MT013` vs `MT032`);
- designation vs successor direct-assignment revocation (`MT013` vs `MT032`);
- designation vs successor group-assignment revocation (`MT013` vs `MT032`);
- activation vs incomplete setup (`MT014`);
- activation vs designated-Identity deactivation (`MT013`);
- root recovery vs replacement-candidate deactivation (`MT026` vs `MT030`);
- concurrent built-in seed install (idempotent, no duplicates).

A hang or split state fails a test; none was observed. Two additional locking
defects were found by this matrix and fixed: (1) the authority-revocation
paths (`identity_role_assignment`, `group_role_assignment`,
`identity_group_membership`, group deactivation) now lock the affected subject
Identity row(s) `FOR UPDATE` — in deterministic `id` order — *before* the
eligibility check, so they serialize with `designate_steward`/`activate_tenant`
(which already lock the subject Identity); and (2) group-derived eligibility
now requires the authorizing Group to be non-deleted, matching the effective
Role resolver, and the Group/membership may not be removed while it is the
designated steward's final Tenant Administrator source (`MT032`).

## Coverage of the Amendment #2 matrix

Additional acceptance coverage added: group-derived Tenant Administrator
stewardship eligibility (`rs17`), Organization-refined assignments being
Organization-scoped authority rather than Tenant-level stewardship eligibility
(`rs18`, `ol10`), ineligible-prerequisite rejection and no-audit-on-failure
(`rs19`, `rs20`), root/stewardship `SECURITY INVOKER` + owner ownership
(`rs21`), the exact 58-signature runtime allowlist after all migrations
(`rs22`), `role_add` collision protection (`bp08`), post-suspension
fail-closed re-resolution (`ol09`), and group-derived invalidation guards
(`rs23` membership removal rejected, `rs24` group deactivation rejected,
`rs25` removal allowed when another authority source remains).

## Deferred (explicitly out of Amendment #2 scope)

Per Amendment #2 section 1, HTTP API, OAuth/OIDC, service-to-service tokens,
propagation/authentication of an acting Identity, runtime-callable
stewardship transfer/recovery/activation, and end-user self-service are
**out of scope**. Their dependencies are: a trusted service identity boundary
(PR 14) that authenticates the caller and propagates the verified acting
Identity. Until then the privileged structural primitives remain
installation/operator-only and non-runtime-granted; no caller-supplied actor
UUID, GUC, or shared runtime credential is treated as authentication.

## Evidence

- `./build.sh --qa` — PASS (Ruff format/lint, strict Mypy, 1196 unit tests,
  coverage 91.47%).
- `./build.sh --sec` — PASS (Bandit Medium/High 0; Semgrep 0 findings).
- `./build.sh --integration` (real PostgreSQL, configured `MTMF_*`) — PASS,
  **501 tests**, including `test_postgres_origin_lifecycle.py`,
  `test_postgres_root_stewardship.py`, `test_postgres_builtin_policy.py`, and
  `test_postgres_stewardship_concurrency.py` (13 scenarios × 10 cycles).
- `scripts/mtmf-provision-roles.py --verify` — PASS (`mtmf_runtime` restricted;
  exact 58-signature allowlist).

## Merge recommendation

The seed, origin/lifecycle persistence, protected root/stewardship foundation,
the full prescribed concurrency matrix, and the previously identified coverage
gaps are implemented and verified. Trusted end-user identity propagation and
runtime-callable privileged operations remain out of scope and deferred with
documented dependencies. The roadmap may record PR 10 implementation progress
but must not claim verified user-facing transfer/recovery, which is deferred.
