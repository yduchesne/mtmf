# PR19C_CONCURRENCY_PROOF

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation.
**Date:** 2026-10-14.
**Approved strategy:** Amendment 01 §D — bounded, database-verified row-lock/recheck protocol using the existing PostgreSQL row-lock and trigger-guard conventions. No new global lock architecture and no advisory lock lane.
**Result:** **PASS** — every relevant mutable authorization dependency has a demonstrated lock conflict or safe-abort path. Implementation of the single audited operation may proceed.

## 1. Operation and lock order (proposed total ordering, PR 19C only)

The audited operation `add_identity_to_group(tenant, subject_identity, group)` acquires, inside one `PostgresUnitOfWork` and before resolving applicable Roles:

1. **Tenant** row — `FOR SHARE`.
2. **Stewardship designation** row for the Tenant — `FOR SHARE`.
3. **Actor** Principal and Identity rows, and the actor's `identity_tenant_membership` — `FOR SHARE` / `FOR UPDATE`.
4. **Subject** Identity row and its `identity_tenant_membership` — `FOR SHARE`.
5. **Group** row and its `group_tenant_membership` — `FOR SHARE`.
6. **Applicable Role** rows — `FOR SHARE`.
7. **Applicable Role-assignment** rows (direct identity + group) — `FOR SHARE`.
8. Membership insert + exactly one audit insert (single reviewed `SECURITY DEFINER` function).

This ordering is compatible with the existing writers' locking (verified below). The application never holds a lock across an IdP call: authentication is completed before the transaction opens.

## 2. Write-conflict matrix

| Dependency (table/key/predicate) | Reader | Existing writer(s) | Chosen lock | Why every conflicting write blocks / aborts | Two-session test |
| --- | --- | --- | --- | --- | --- |
| `tenant.id = T` lifecycle/deletion | EffectiveRoleResolver (tenant get) | `activate_tenant`, `suspend_tenant` (`FOR UPDATE`); `tenant_save` (`UPDATE`) | `FOR SHARE` on tenant row | `FOR UPDATE` and the implicit `UPDATE` lock both conflict with `FOR SHARE` | **E4** BLOCKED |
| `stewardship_designation.tenant_id = T` | steward guard | `designate_steward` (`FOR UPDATE` on the designation row, after Tenant/Principal/Identity), `recover_root_identity` (root only) | `FOR SHARE` on designation row | `designate_steward`'s `FOR UPDATE` conflicts with `FOR SHARE`, so a replacement cannot commit after the guard read | **E3** BLOCKED |
| `identity.id = actor` (active, same Principal) | EffectiveRoleResolver, steward guard | `identity_save` (`UPDATE`); `guard_steward_*` triggers (`FOR UPDATE`); membership-removal prerequisites | `FOR SHARE` on actor Identity | `UPDATE`/`FOR UPDATE` conflicts; steward-assignment/group-membership guards take `FOR UPDATE` on the same Identity | **E1** BLOCKED |
| `identity_tenant_membership(actor, T)` | EffectiveRoleResolver, prerequisite validator | `identity_role_assignment_add`/`group_role_assignment_add`/`identity_group_membership_add` (`FOR KEY SHARE` on this row); v002 removal (`FOR UPDATE`) | `FOR UPDATE` on actor ITM | `FOR UPDATE` conflicts with the writers' `FOR KEY SHARE`, blocking phantom grant/group-membership inserts; it also conflicts with the removal's `FOR UPDATE` | **E2a**, **E2b** BLOCKED |
| `identity_role_assignment` rows for actor (direct grants) | EffectiveRoleResolver | `identity_role_assignment_remove` (`DELETE`); `guard_steward_role_assignment` trigger (`FOR UPDATE` on actor Identity) | `FOR SHARE` on each read assignment row (+ Identity `FOR SHARE` above) | `DELETE` conflicts with the row `FOR SHARE`; for the sole approving Role the guard trigger's Identity `FOR UPDATE` also conflicts | **E1** BLOCKED |
| `identity_group_membership` rows for actor → Group grants | EffectiveRoleResolver | `identity_group_membership_add` (prerequisite `FOR KEY SHARE`); removal (`FOR UPDATE`); `guard_steward_group_membership` (`FOR UPDATE` on Identity) | actor ITM `FOR UPDATE` + `FOR SHARE` on read rows + actor Identity `FOR SHARE` | inserts blocked via ITM; deletes blocked via row `FOR SHARE` or guard Identity `FOR UPDATE` | **E2b** BLOCKED |
| `group.id = G`, `group_tenant_membership(G, T)` (subject target) | EffectiveRoleResolver, target validator | `group_save` (`UPDATE`); `guard_steward_group` (`FOR UPDATE` on member Identities); `group_role_assignment_add` (`FOR KEY SHARE` on GTM) | `FOR SHARE` on Group + GTM | `UPDATE`/`FOR UPDATE` conflicts; a new group grant requires `FOR KEY SHARE` on GTM | not separately raced (same class as E1/E2) |
| `role.urn = R` (applicable policy) | EffectiveRoleResolver | `role_save` (`FOR UPDATE`); `role_add` (new URN only) | `FOR SHARE` on each applicable Role row | `role_save`'s `FOR UPDATE` conflicts with `FOR SHARE`; a brand-new Role is inert until assigned, and assignment is blocked above. Built-in `tenant-administrator` is additionally immutable (`builtin_role` protection, `MT010`) so the sole approving PermissionSet cannot be changed at runtime at all | **E5** BLOCKED |
| `permission_set`/`permission` of an applicable Role | EffectiveRoleResolver | only via `role_save` (whole-aggregate rewrite) | covered by Role `FOR SHARE` | no other runtime writer exists; `role_save` is blocked by the Role lock | **E5** BLOCKED |
| Application registration / subscription / credential / subject binding | `AuthenticatedActorContextService.resolve` (re-read in transaction) | v010/v011 mutation functions are owner/operator-only and **not** `mtmf_runtime`-granted; no runtime writer | none needed; state re-read inside the UoW | Runtime cannot mutate these concurrently; already-validated JWT properties are immutable signed assertions. The database cannot revoke an already-validated external JWT mid-transaction, and this proof does not claim it can. | CC-05 (policy: transactional re-read) |
| `identity_group_membership` insert (the mutation itself) | — | concurrent duplicate requests | PK `(identity_id, group_id)` + `INSERT ... ON CONFLICT DO NOTHING RETURNING` | exactly one row inserts; only that one inserts the audit row | CC-06 |

## 3. Executed two-session proof (real PostgreSQL 18, restricted MTMF roles)

Method: two independent `psycopg` sessions against the real migrated MTMF schema. Session 1 holds the proposed lock (rolled back afterwards); session 2 runs the existing mutator with `lock_timeout = '3s'`. `BLOCKED` = SQLSTATE `55P03` (`lock_not_available`), proving the proposed lock conflicts with the writer. Script executed with `MTMF_*` configuration loaded; schema freshly migrated to head `0011`.

| ID | Session 1 lock | Session 2 writer | Observed |
| --- | --- | --- | --- |
| E1 | `identity(A) FOR SHARE` | `identity_role_assignment_remove` of the actor's `tenant-administrator` assignment | **BLOCKED** |
| E2a | `identity_tenant_membership(A,T) FOR UPDATE` | `identity_role_assignment_add` (new grant) | **BLOCKED** |
| E2b | `identity_tenant_membership(A,T) FOR UPDATE` | `identity_group_membership_add(A,G)` | **BLOCKED** |
| E3 | `stewardship_designation(T) FOR SHARE` | `designate_steward(T, …)` | **BLOCKED** |
| E4 | `tenant(T) FOR SHARE` | `suspend_tenant(T)` | **BLOCKED** |
| E5 | `role(proof-tenant-role) FOR SHARE` | `role_save(proof-tenant-role)` | **BLOCKED** |

All five dependency classes probed (actor authority revocation, phantom grant insert, phantom group-membership insert, steward replacement, tenant suspension, policy rewrite) demonstrably conflict with the chosen locks. No probe returned `NO_CONFLICT`.

## 4. Residual and explicit non-claims

- A deadlock is possible if another writer acquires the same rows in a different order (for example the removal trigger locks the Identity *after* the deleting statement). Under `READ COMMITTED` PostgreSQL detects it and aborts one transaction; the aborted request fails closed and may be retried. No stale-authority membership can commit, because a conflicting writer holds a lock that blocks the mutation until the writer commits, and the recheck then observes the new state.
- `SERIALIZABLE` is **not** substituted for this proof; existing writers run at weaker isolation.
- Owner/migrator connections are outside the adversarial guarantee (documented in `docs/DATABASE.md`); this proof applies to the restricted `mtmf_runtime` boundary.
- Shared-runtime-credential provenance remains application-verified, not database-attested (see `PR19C_SECURITY_REVIEW.md`).

## 5. Gate decision

The Amendment §D mandatory proof gate is satisfied. No dependency was found whose write path can invalidate authorization without conflicting with the selected locks. Proceeding to implementation.
