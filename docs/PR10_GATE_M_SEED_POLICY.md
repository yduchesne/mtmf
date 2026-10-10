# PR 10 — Gate M resolution: protected seed and deferred enforcement

> **Status: proposed decision for explicit human approval.** This is an additive decision proposal to [PR10_EXACT_PERMISSION_MANIFEST.md](PR10_EXACT_PERMISSION_MANIFEST.md), which remains the candidate catalog. Merging this document does **not** authorize migration 0006 until the concrete seed identities and privilege review are approved.

## Decision: Option B

PR 10 owns protected, operator-controlled installation, root bootstrap, Tenant lifecycle and stewardship **structural** invariants, and installation of built-in IAM definitions. PR 10 does **not** expose end-user administrative operations or stewardship transfer/recovery via the shared runtime credential. A later versioned HTTP service/API boundary must authenticate the calling service, propagate and verify the acting Identity, enforce Action/target/scope/dominance checks, and coordinate database writes.

**An Action being defined or a Permission being seeded never makes an operation callable.** All PR 10 built-in policy grants are dormant with respect to end-user administrative execution until the verified-actor enforcement boundary is delivered. Existing PostgreSQL runtime repository entry points must not be treated as that boundary.

## Recommended minimum exact seed — 11 Roles, 11 Permissions, 3 distinct Actions

This is a deliberately minimal **bootstrap policy**, not the final feature-complete administrative policy. All rows are SYSTEM-defined and each Role owns exactly one ALLOW PermissionSet containing exactly one exact Permission. Each listed Action is a real domain read concept, not a made-up placeholder; none is claimed to be end-user enforceable yet.

Abbreviations: `R(x)` = `urn:mtmf:iam:roles:system:x`; `A(r:o)` = `urn:mtmf:iam:actions:system:r:o`; `P(r:o)` = `urn:mtmf:iam:permissions:system:r:o`. Expand these strings exactly when implementing; do not persist abbreviations.

| Built-in Role | Exact Role URN | Exact ALLOW Permission matcher | Exact Action definition | End-user execution |
| --- | --- | --- | --- | --- |
| System Administrator | `R(system-administrator)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| System Security Administrator | `R(system-security-administrator)` | `P(role:get-object)` | `A(role:get-object)` | Deferred |
| System Reader | `R(system-reader)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Tenant Administrator | `R(tenant-administrator)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Tenant Security Administrator | `R(tenant-security-administrator)` | `P(role:get-object)` | `A(role:get-object)` | Deferred |
| Tenant Contributor | `R(tenant-contributor)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Tenant Reader | `R(tenant-reader)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Organization Administrator | `R(organization-administrator)` | `P(organization:get-object)` | `A(organization:get-object)` | Deferred |
| Organization Security Administrator | `R(organization-security-administrator)` | `P(role:get-object)` | `A(role:get-object)` | Deferred |
| Organization Contributor | `R(organization-contributor)` | `P(organization:get-object)` | `A(organization:get-object)` | Deferred |
| Organization Reader | `R(organization-reader)` | `P(organization:get-object)` | `A(organization:get-object)` | Deferred |

**Scope rule:** Organization Administrator, Contributor, and Reader receive only `organization:get-object`, never a Tenant-wide read as a substitute. Organization Security Administrator receives `role:get-object` only for Role definitions visible in the assigned Organization context. These are dormant grants: target scoping and sensitive-read filtering remain mandatory before any user-facing endpoint can execute them.

## Why not seed the full 34-Action candidate matrix now?

| Concern | Decision |
| --- | --- |
| Incomplete exact catalog | Do not guess membership, IAM, sensitive-read, or ordinary-resource Action names |
| Unimplemented trusted actor path | Keep administrative operations inaccessible |
| Existing nonempty aggregate contract | Seed a real, narrow read Permission per Role, not an invented `noop` |
| Role semantics | Built-in Roles are **installed but not feature-complete**; no claim that Administrators can already administer |
| Stewardship | The installed Tenant Administrator Role can serve as an eligibility marker, but cannot by itself transfer stewardship |
| Future policy | Add reviewed exact Actions through a later controlled migration with matching enforcement; never auto-expand grants when a new Action is registered |
| System-owned policy | Protected from ordinary Role CRUD and SQL runtime writes |
| Principal vs Identity | No Role assignment or shared Principal ownership grants designated-steward authority |

## Proposed exact UUID seed rows (requires human approval)

UUID version 5 namespace: `df87448f-4a54-5c73-bf35-c61c85406363`, derived as `uuid.uuid5(uuid.NAMESPACE_URL, 'https://github.com/yduchesne/mtmf/pr10/builtin-policy/v1')`. PermissionSet ID = `uuid.uuid5(namespace, 'permission-set:' + full_role_urn)`. Permission ID = `uuid.uuid5(namespace, 'permission:' + full_role_urn + ':' + full_permission_urn)`. These UUIDs are **proposed immutable installation constants**, not yet approved.

| Role suffix | Permission suffix | PermissionSet UUID | Permission UUID |
| --- | --- | --- | --- |
| `system-administrator` | `tenant:get-object` | `b04f0a3d-5d52-5c14-bb45-6ee07169eec0` | `fa32a700-21d8-55fb-8e50-46f6d236d731` |
| `system-security-administrator` | `role:get-object` | `b72dfbeb-59b4-5e36-bcd1-d707bc80571a` | `747273b4-90b8-53da-b67b-029b3b336ac1` |
| `system-reader` | `tenant:get-object` | `1f9a65c9-cf69-516b-86f3-6cb459ae0b5e` | `894a1b10-2e42-51d0-a21b-cd9b15676a69` |
| `tenant-administrator` | `tenant:get-object` | `187bc3cd-993d-5660-a226-113411121fed` | `e7943319-187f-55b4-835a-059bf4ab7206` |
| `tenant-security-administrator` | `role:get-object` | `1526c205-21da-551f-8048-493467be2e19` | `ac9ee2ad-87f0-5fe8-a273-fe3b70a3edc2` |
| `tenant-contributor` | `tenant:get-object` | `aded7e13-b6de-54fd-8ddd-de1009611179` | `713c550d-b88c-5ec8-882e-7c592884bebd` |
| `tenant-reader` | `tenant:get-object` | `babc80ad-448a-5533-81c0-a558b43f2434` | `8260fdea-7bb7-5b4c-9433-44006e39fdf3` |
| `organization-administrator` | `organization:get-object` | `ea4c7027-67f1-52f5-b249-3006c41b122b` | `9e6153ad-0071-5a89-a322-a69185b9e32a` |
| `organization-security-administrator` | `role:get-object` | `3d7d1473-bdba-53fa-a841-8ec02ce326db` | `92ca8929-3563-5387-92a7-bf0679a10132` |
| `organization-contributor` | `organization:get-object` | `2cab5378-81e9-53e6-966e-9aa7813e96d9` | `40fcf83f-37d6-5a50-aa60-d371dc739aad` |
| `organization-reader` | `organization:get-object` | `2d937b29-264e-578a-83d1-21cd13c6923e` | `d18a1bd3-dc89-5e64-a019-64a419dd3f75` |

All Role URNs expand to `urn:mtmf:iam:roles:system:<role suffix>` and all Permission URNs to `urn:mtmf:iam:permissions:system:<permission suffix>`. PermissionSet effect is `ALLOW` in every row. Action URNs use `urn:mtmf:iam:actions:system:<permission suffix>` and contain no wildcard.

## Protected installation acceptance

1. Seed exactly eleven SYSTEM-owned Role aggregates, each with one ALLOW PermissionSet and one exact Permission. Seed exactly three distinct Action definitions: `tenant:get-object`, `role:get-object`, and `organization:get-object`.
2. Use explicit, immutable, stable UUIDs for each PermissionSet and Permission. Use the 22 explicit UUID literals in the proposed table below; no random UUID generation at each install, no silent overwrite, and no implicit namespace selection.
3. Replay with identical definitions is idempotent; a conflicting existing Role/PermissionSet/Permission/Action fails closed and reports the conflicting semantic key.
4. Install via authenticated migrator/owner-controlled migration only. Verify SYSTEM Role definitions cannot be mutated via ordinary runtime Role entry points, including `role_save`; a mere documentation statement is insufficient.
5. Do not add bootstrap, transfer, recovery, or privileged IAM runtime EXECUTE grants. Existing runtime signatures must be checked for bypasses of new invariants and SYSTEM definition protection.
6. Root bootstrap and ordinary Tenant activation may establish required membership/Role-assignment state only through protected, auditable installation/provisioning paths; no caller-supplied actor UUID is proof of identity.
7. Deny all out-of-scope requests and all unimplemented administrative Actions; Role possession alone does not make a dormant operation executable.
8. Prove fresh installation, re-install/idempotency, tampering/replay failure, protected Role write denial, runtime privilege inventory, root/steward invariant preservation, and concurrent operation behavior on real PostgreSQL with actual `mtmf_runtime` credentials.
9. Report any mismatch between the structural install-only Tenant Administrator Role and existing effective-role eligibility logic before changing authorization semantics.

## Remaining approval questions (do not silently decide)

1. **Minimum read semantics:** Confirm `organization:get-object` for Organization Administrator, Contributor, and Reader, and the scoped `role:get-object` for Organization Security Administrator.
2. **UUIDs:** Approve the 22 explicit fixed UUID literals and UUIDv5 derivation procedure shown above.
3. **Dormant grant posture:** Explicitly confirm that an installed but not yet executable Action/Permission is acceptable for v0.1 and must never be interpreted as a runtime capability.
4. **Future completeness:** Confirm that the remaining 34-Action candidate matrix stays unseeded until each relevant Action is implemented with verified-actor enforcement.
5. **Security check:** Inspect `role_add`, `role_save`, and all mutation stored functions for SYSTEM Role definition bypass before permitting the migration.

**Gate M closes only after these questions and the final literal UUID table are explicitly approved.** Until then, continue non-gated PR 10 structural work only.
