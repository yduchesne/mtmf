# PR19C_BASELINE_RECONCILIATION

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation (add an existing Identity to an existing Group in one ACTIVE Tenant).
**Date:** 2026-10-14.
**Phase:** Phase 0 (mandatory gate) — baseline reconciliation.
**Base commit:** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db` (branch `dev/mgmt-mutation`; equals `main` and `origin/main`).
**Outcome:** **STOP applies — no approved exact Action exists for identity-to-group membership addition.** No production edit was made. See [PR19C_STOP_REPORT.md](PR19C_STOP_REPORT.md).

## 1. Scope and method

Per §11 Phase 0 of the PR 19C execution plan, this reconciliation:

1. recorded the base commit and migration head;
2. read `AGENTS.md`, the PR 19/19A artifacts, `docs/SECURITY_MODEL.md`, `docs/AUTHORIZATION.md`, `docs/DATABASE.md`, `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md`, and the PR 10 built-in-policy manifest/decisions;
3. enumerated every `urn:mtmf:iam:actions:...` value present anywhere in the repository (Python, SQL, docs, JSON);
4. enumerated the Actions actually installed by the built-in policy seed and its in-transaction assertion;
5. re-confirmed the authenticated/authorization seams, the runtime EXECUTE manifest, the legacy membership-add function, and the mutation-provenance registration map;
6. ran the baseline canonical gates.

No production code, SQL, migration, DTO, route, or test was changed.

## 2. Base and migration head

| Fact | Value |
| --- | --- |
| Base commit | `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db` |
| Branch | `dev/mgmt-mutation` (points at `main`/`origin/main`; no commits yet) |
| Alembic head | `0011` (`0011_authentication_bindings`, `down_revision = "0010"`) |
| PR 19A evidence head | `0011_authentication_bindings` — matches |

The plan's Step 6 assumption (`0011` is head) is confirmed. No migration was created, so no head conflict exists.

## 3. Exact Action manifest evidence (the blocking gate)

### 3.1 Actions actually installed by the built-in policy (authoritative enforcement set)

`packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v006/02_builtin_seed_function.sql` seeds exactly eleven SYSTEM Roles, each owning exactly one ALLOW PermissionSet with one exact Permission. The `permission_suffix` values reduce to exactly **three** distinct Action definitions:

```text
urn:mtmf:iam:actions:system:tenant:get-object
urn:mtmf:iam:actions:system:role:get-object
urn:mtmf:iam:actions:system:organization:get-object
```

`packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v006/04_builtin_privilege_assertions.sql` enforces this at migration time:

> `Gate M assertion failed: exactly 3 approved Action definitions must exist`

So the only Actions with an approved built-in Role/Permission grant are the three above. There is **no** membership-add Action.

### 3.2 Repository-wide Action search

A repository-wide scan for `urn:mtmf:iam:actions:...` (Python, SQL, Markdown, JSON) returns no Action naming any typed-membership operation. The only non-baseline, non-test Actions are the three seeded `*-get-object` reads above. No `identity-group-membership`/`group:add-object`/`membership:*`/`*:add-object` Action exists.

### 3.3 `BASELINE_ACTIONS` is not an approved catalog

`packages/mtmf-core/src/mtmf_core/domain/action.py` lists 17 example Actions for `principal`, `role`, and `tenant`. Its own docstring states these are examples and that the complete Action catalog is **unresolved**; it contains no membership Action. Example URNs are not authorization grants.

### 3.4 The authoritative design documents explicitly defer typed-membership Actions

- `docs/pr-artifacts/pr-10/PR10_EXACT_PERMISSION_MANIFEST.md` §3: "Typed membership Actions, PermissionSet/Permission administration, sensitive IAM reads, ordinary non-container business resources, and Organization-scoped assignment semantics require their own reviewed Action inventory. **Do not replace missing operations with generic container CRUD.** This table is an explicit **incomplete candidate catalog**, not an approved executable manifest." Its checklist item requires the human to "Approve every exact Action URN … including any missing typed membership and assignment Actions."
- `docs/pr-artifacts/pr-10/PR10_BUILTIN_ACCESS_AND_INSTALLATION.md`: typed membership create/remove Actions are merely "Proposed … Not generic CRUD; cascading removal and audit still required."
- The installed Gate M policy therefore intentionally excludes every typed-membership write Action.

### 3.5 Constitutional rule forbids substituting a broad CRUD Action

`docs/SECURITY_MODEL.md` §15.1 states: "Security-sensitive operations with distinct semantics MUST use distinct Actions rather than being silently implied by `update-object` or another broad CRUD Action." §15.2 repeats the granularity requirement and gives Role assignment as an explicit example of a distinct security operation. §18 lists Role assignment and membership operations as security-sensitive. Plan §0 and §10 additionally forbid reusing an unrelated Action or substituting a wildcard.

**Conclusion:** there is no existing approved exact Action URN for adding an Identity to a Group; and the plan forbids inventing one, reusing an unrelated Action, or substituting a broad CRUD Action. The plan's mandatory early STOP condition is met exactly:

> `BLOCKED: no approved exact Action for identity-to-group membership addition`

## 4. Operation-specific guards are equally unsettled

The plan requires "the **existing exact Action URN and settled operation-specific guards**". No approved operation-specific guard or dominance rule exists for this operation:

- `docs/pr-artifacts/pr-10/PR10_ARCHITECTURE_DECISIONS.md` scopes Tenant Administrator / Tenant Security Administrator IAM administration to Actions "**only when separately specified in the existing Action catalog and permitted by dominance rules**". The applicable catalog entry does not exist, so the guard is unspecified.
- The PR 10 candidate allocation rates every membership/assignment row `BLOCKED` and refuses to treat broad CRUD as the enforcement point.

So even if a human approved an Action name, the operation-specific scope/dominance/anti-escalation guard for "add Identity to Group" has not been settled by an authoritative document.

## 5. Verified seams (available and unchanged)

| Seam | Location | Status |
| --- | --- | --- |
| Two-token verified actor | `mtmf_core/application/authentication.py::AuthenticatedActorContextService.resolve(service_token, user_token, tenant_id)` | Present; read-only; no Action evaluation |
| Effective roles | `mtmf_core/application/effective_roles.py::EffectiveRoleResolver.resolve` + `build_authorization_context` | Present; Tenant-filtered; no decision |
| Authoritative decision | `mtmf_core/authorization/authorizer.py::Authorizer.authorize(AuthorizationRequest)` | Present; exact-Action evaluation |
| Cross-Tenant delegation | `mtmf_core/application/management_authorization.py::ManagementAuthorizationResolver` | Present, but explicitly for delegated **cross-Tenant** authority; must not be used for this same-Tenant operation |
| Provenance contract | `mtmf_core/application/mutation_provenance.py::VerifiedMutationProvenance` | Present; `_MIGRATED_MUTATIONS` is **empty** (PR 19A scaffold) |
| HTTP surface | `mtmf_service/app.py` | Only `POST /v1/authorization/evaluate`, `GET /health/live`, `GET /health/ready` |
| Runtime privilege manifest | `mtmf_core/persistence/postgres/roles.py::expected_runtime_signatures` | 75 reviewed signatures through v011 |

None of these provides an approved membership-add Action.

## 6. Legacy runtime bypass (a prerequisite, not the blocking gate)

`mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid)` is a `SECURITY DEFINER` function (`sql/v004/03_membership_functions.sql`) with no actor argument and no audit row. It is currently granted to `mtmf_runtime` via `_REPOSITORY_FUNCTION_ARGUMENTS` in `roles.py` (line 143). Closing it is a mandatory part of any PR 19C implementation (Step 8) and is not itself the reason for this STOP. Per the plan, "Never call a mutation audited while a runtime-executable unaudited bypass remains."

## 7. Concurrency/lock discipline (second unresolved prerequisite)

The plan's Step 3 prescribes a single transaction-level advisory lock for the Tenant management authorization/mutation lane, and states it is only sufficient "if **all relevant role/permission/membership/tenant-state mutators that could invalidate authorization participate in the same lock discipline**." Phase 0 observed that current mutators (role-assignment add/remove, typed-membership add/remove, Tenant lifecycle, Group deactivation) use row-level `FOR UPDATE` / `FOR KEY SHARE` locking plus trigger guards (`docs/DATABASE.md` §181), and there is no shared per-Tenant advisory lock lane. Proving or establishing the prescribed lock discipline for every relevant policy writer would itself require a reviewer-approved bounded design. This is a second unresolved prerequisite; it was not pursued because the primary Action STOP fires first and the plan forbids designing alternatives.

## 8. Baseline gate results (recorded for failure classification)

Run on base `0f6d3fe` with the repository's canonical commands:

| Command | Result |
| --- | --- |
| `./build.sh --qa` | PASS — Ruff format check, Ruff lint, strict Mypy, unit tests: **2394 passed**, coverage **90.89%** (≥ 85% gate) |
| `./build.sh --sec` | PASS — Bandit + Semgrep: **0 findings** |
| `./build.sh --rust` | Not run — would not change the STOP decision (no native code is in scope) |
| `./build.sh --integration` | Not run — would not change the STOP decision; requires the live MTMF PostgreSQL/role topology |

Baseline is green, so this STOP is a genuine architectural prerequisite STOP, not a pre-existing failure.

## 9. Reconciliation with PR 19A

| PR 19A finding | Re-check at base `0f6d3fe` |
| --- | --- |
| No category-A (verified actor + exact Action ALLOW + target-bound mutation) application path | Confirmed; the only route remains the decision endpoint |
| Provenance map empty | Confirmed (`_MIGRATED_MUTATIONS = {}`) |
| Legacy membership-add runtime-granted | Confirmed |
| Migration head `0011` | Confirmed |
| 29 runtime-granted mutators, no audited additions | Unchanged |

PR 19C was authorized to create the entry point (unlike PR 19A), but it is not authorized to invent the exact Action, Permission, or built-in Role grant that the entry point must request. That single decision is the required human input.

## 10. STOP decision

The plan's §0 early STOP and §10 STOP rule ("STOP before edits if exact membership-add Action/guard is not approved") both apply.

**Disposition: `BLOCKED: no approved exact Action for identity-to-group membership addition`.** No production edits were made. The required decision and evidence are in [PR19C_STOP_REPORT.md](PR19C_STOP_REPORT.md).
