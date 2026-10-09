# PR 10 implementation decisions and STOP record

**Status:** Partial, non-deployable structural slice implemented; production
bootstrap/stewardship persistence and privileged operations are **BLOCKED and
NOT implemented**.

**Baseline:** branch `dev/pr10-bootstrap`, base/merge-base commit
`73f965caac8294f93a45334a35f919f7c9486321` (current `main`, Alembic head
`0005`). Working tree clean before implementation.

**Authority:** [`docs/SECURITY_MODEL.md`](SECURITY_MODEL.md) governs security
semantics; this record does not override it. It records how the STOP gates in
the PR 10 execution plan were resolved against the current repository and the
authoritative documents.

## 1. Why PR 10 is not complete

The PR 10 execution plan defines six STOP gates that must be resolved by an
explicit, reviewed decision before any production migration or privileged
function is written. Each gate maps to a decision that the authoritative
documents still mark unresolved:

| Gate | Subject | Authoritative unresolved status |
|---|---|---|
| STOP-01 | Trusted end-user identity boundary for privileged SQL | `SECURITY_MODEL.md` §24, `DATABASE.md` §12, `ROOT_AND_STEWARDSHIP.md` "Enforcement" |
| STOP-02 | Built-in Role/Permission catalog and Tenant Administrator composition | `SECURITY_MODEL.md` §25.2, `AUTHORIZATION.md` §11 |
| STOP-03 | Local vs federated Identity representation | `DOMAIN_MODEL.md` §19.10, `SECURITY_MODEL.md` §25.7 |
| STOP-04 | Explicit Tenant provisioning/activation state | `DOMAIN_MODEL.md` §2.3, §19.11 and `SECURITY_MODEL.md` §25 |
| STOP-05 | Transactional trusted authorization + write boundary | `ROOT_AND_STEWARDSHIP.md` "Enforcement", `DATABASE.md` §12 |
| STOP-06 | Root recovery runbook and credential custody | `ROOT_AND_STEWARDSHIP.md` "Recovery without silent escalation" |

No approval channel for these decisions exists in the current execution
environment, and the plan itself instructs a STOP rather than a permissive
guess:
> "Any unresolved privileged-authentication boundary, built-in Permission
> catalog, or lifecycle representation must trigger a **STOP** under §2, not a
> permissive guess."

Consequently **no Alembic revision `0006`, no packaged `sql/v006`, no stored
function, no runtime grant, no SPI/repository extension, no privileged
application coordinator, and no built-in Role seed were written.** Adding them
would have required inventing the very representations the documents forbid
inferring.

## 2. STOP resolutions

### STOP-01 — Privileged operation identity

- **Current state:** the shared `mtmf_runtime` login is not an end-user
  authentication boundary; a caller-supplied UUID/GUC is not authentication
  (`DATABASE.md` §7, §12; `SECURITY_MODEL.md` §24).
- **Decision:** no trusted boundary exists and none may be assumed.
- **Resolution taken:** blocked. No bootstrap, transfer, recovery, or
  privileged designation-change function was created or granted. The plan's
  allowed fallback ("implement its isolated structural/database core and tests,
  but leave the privileged entry point inaccessible to runtime") was itself
  constrained by STOP-02/03/04, which block the database core (see §3).
- **Not implemented:** end-to-end transfer/recovery authorization.

### STOP-02 — Built-in Roles/Permissions

- **Current state:** `SECURITY_MODEL.md` §16 names eleven built-in Roles, but
  §25.2 states the complete Permission catalog and the exact composition of
  each built-in Role remain unresolved.
- **Decision required:** a reviewed, narrowly scoped initial catalog (exact
  Role/Action URNs, PermissionSets, effects).
- **Resolution taken:** blocked. No Role, PermissionSet, Permission, Action,
  or built-in Role assignment was seeded, and no wildcard/root ALLOW was
  invented.
- **Consequence:** steward eligibility ("holds the built-in Tenant
  Administrator Role") cannot yet be enforced end-to-end.

### STOP-03 — Identity locality

- **Current state:** `Principal`/`Identity` deliberately do not encode a
  local-vs-federated representation (`identity_entity.py`, `principal.py`);
  `DOMAIN_MODEL.md` §19.10 keeps it unresolved, and locality must not be
  inferred from names, UUIDs, or IdP absence.
- **Decision required:** an authoritative field or approved minimal
  backward-compatible representation for a local MTMF Identity.
- **Resolution taken:** blocked. No `is_local`/federation field was invented,
  and no claim of root local-Identity continuity is made.
- **Consequence:** the "designated active **local** root Identity" guarantee is
  not asserted as implemented.

### STOP-04 — Tenant activation

- **Current state:** `Tenant` exposes `scope` + `deletion_status` only; there
  is no explicit ACTIVE/INACTIVE Tenant state, and `DOMAIN_MODEL.md` §2.3/§19.11
  leaves lifecycle applicability unresolved. "Not deleted" must not be equated
  with "active".
- **Decision required:** an approved minimal provisioning/activation state, or
  a single atomic create-and-designate operation with no visible intermediate
  active Tenant.
- **Resolution taken:** blocked. No activation column/state was invented, and
  because STOP-02 blocks the required Tenant Administrator Role prerequisite,
  the atomic create-and-designate operation cannot be completed. No stewardless
  authorizing Tenant can be created because no Tenant-authorizing operation was
  added.

### STOP-05 — Transactional trusted boundary

- **Current state:** no trusted path binds an authorized actor to a write in
  one serialized transaction.
- **Decision required:** an approved revalidation/locking protocol for the
  trusted operator path.
- **Resolution taken:** blocked with STOP-01; no privileged write path exists
  to introduce a TOCTOU gap.

### STOP-06 — Recovery

- **Current state:** operator approval, dual control, and credential custody
  are deployment policy and are not implemented (`ROOT_AND_STEWARDSHIP.md`).
- **Resolution taken:** blocked. No recovery endpoint, automatic credential
  minting, canonical-ID change, or authorization bypass was created.

## 3. Implemented slice (non-deployable, structural only)

The plan permits settled structural work in a separately identified
non-deployable slice. The following was implemented and unit-tested:

- `packages/mtmf-core/src/mtmf_core/domain/stewardship.py`
  - `RootBootstrapRecord` — immutable canonical root Tenant/Principal/Identity
    IDs (stable IDs, never names).
  - `TenantStewardshipDesignation` — immutable `(tenant, steward Principal,
    designated Identity, version)` structural fact.
  - `validate_root_bootstrap_record(...)` — checks the settled root structure:
    canonical-ID agreement, ROOT scope on the root Tenant, root Identity
    belongs to the root Principal, distinct canonical IDs, and no soft
    deletion.
  - `validate_stewardship_designation(...)` — checks ordinary-Tenant scope,
    Identity-belongs-to-steward-Principal, explicit Principal/Identity Tenant
    memberships, and no soft deletion.
- New narrow errors `RootInvariantError` and `StewardshipInvariantError`.
- Public exports from `mtmf_core.domain` / `mtmf_core`.
- `tests/unit/core/test_stewardship.py` — 23 deterministic structural tests.

**Hard boundaries of this slice:** it does not authenticate, authorize,
resolve/assign Roles, grant dominance, validate locality or ACTIVE/INACTIVE
admission, read a session, persist anything, touch PostgreSQL, or define a
privileged boundary. The validators must **not** be used as a grant of
authority. They are not wired into any production operation.

## 4. Explicitly not implemented (blocked)

- Alembic revision `0006`, packaged `sql/v006/*`, schema/constraints/triggers.
- Bootstrap/root-recovery function or any `mtmf_runtime` grant.
- Stewardship transfer/recovery function or coordinator.
- Built-in Role/Permission seed and mandatory Tenant Administrator assignment.
- Local Identity representation and root-Identity continuity enforcement.
- Tenant activation state and atomic create-and-designate operation.
- SPI/repository/in-memory persistence parity for bootstrap/stewardship.
- Authorization-context stewardship dominance integration.
- Guards on existing v002/v004/v005 mutation paths for protected root/steward
  state.
- Real-PostgreSQL adversarial, concurrency, migration (`0005→0006`), and
  privilege-manifest tests for PR 10.

## 5. Required decisions to proceed

1. Approve a trusted privileged orchestration boundary and its actor
   verification (STOP-01/STOP-05).
2. Approve the exact built-in Role/Permission catalog and Tenant Administrator
   composition (STOP-02).
3. Approve the local MTMF Identity representation (STOP-03).
4. Approve Tenant activation representation or the atomic create-and-designate
   operation (STOP-04).
5. Approve the root-recovery runbook, dual control, and credential custody
   (STOP-06).

Until then, the restrictive posture is preserved: no privileged capability is
runtime-reachable, and no unresolved security behavior is inferred.

## 6. Operator guidance (no secrets)

- Do **not** expect a bootstrap/transfer/recovery command in this revision:
  none is exposed.
- Provisioning and migration remain exactly as documented in `DATABASE.md`
  (administrator `MTMF_POSTGRES_*`, migrator `MTMF_MIGRATOR_*`, runtime
  `MTMF_RUNTIME_*`).
- Root/stewardship state does not yet exist, so no operator runbook can act on
  it. When the STOP decisions are approved, the runbook must be added before
  any production rollout.

## 7. Evidence and merge recommendation

- Baseline: clean `dev/pr10-bootstrap` at `73f965caac...`; unit suite green.
- Feature evidence: `tests/unit/core/test_stewardship.py` (structural only).
- No migration/privileged/integration feature evidence exists, because no such
  feature was implemented.
- **Recommendation:** the structural slice is safe to review, but **PR 10 as a
  whole is do-not-merge**: the mandatory root/stewardship bootstrap,
  persistence, and privileges are not implemented and are blocked on the STOP
  decisions above. The roadmap must not mark PR 10 `[DONE]`.
