# PR 10 — Gate M resolution: protected seed and deferred enforcement

> **Status: proposed decision for explicit human approval.** This is an additive decision proposal to [PR10_EXACT_PERMISSION_MANIFEST.md](PR10_EXACT_PERMISSION_MANIFEST.md), which remains the candidate catalog. Merging this document does **not** authorize migration 0006 until the concrete seed identities and privilege review are approved.

## Decision: Option B

PR 10 owns protected, operator-controlled installation, root bootstrap, Tenant lifecycle and stewardship **structural** invariants, and installation of built-in IAM definitions. PR 10 does **not** expose end-user administrative operations or stewardship transfer/recovery via the shared runtime credential. A later versioned HTTP service/API boundary must authenticate the calling service, propagate and verify the acting Identity, enforce Action/target/scope/dominance checks, and coordinate database writes.

**An Action being defined or a Permission being seeded never makes an operation callable.** All PR 10 built-in policy grants are dormant with respect to end-user administrative execution until the verified-actor enforcement boundary is delivered. Existing PostgreSQL runtime repository entry points must not be treated as that boundary.

## Recommended minimum exact seed — 11 Roles, 11 Permissions, 2 distinct Actions

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
| Organization Administrator | `R(organization-administrator)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Organization Security Administrator | `R(organization-security-administrator)` | `P(role:get-object)` | `A(role:get-object)` | Deferred |
| Organization Contributor | `R(organization-contributor)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |
| Organization Reader | `R(organization-reader)` | `P(tenant:get-object)` | `A(tenant:get-object)` | Deferred |

**Review issue:** `tenant:get-object` is not an Organization-resource read. Its use for Organization Roles is a narrow common-context read, not a claim of Organization resource access. An alternative is to approve and seed `organization:get-object` once its exact Action definition and scoped semantics are reviewed. Do not infer broad Tenant visibility from an Organization assignment: the authorization target/scope guard must reject out-of-scope reads.

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

## Protected installation acceptance

1. Seed exactly eleven SYSTEM-owned Role aggregates, each with one ALLOW PermissionSet and one exact Permission. Seed only the two distinct exact Actions `tenant:get-object`, `role:get-object`, and (if changed during review) an explicitly approved Organization read Action.
2. Use explicit, immutable, stable UUIDs for each PermissionSet and Permission. Publish all 22 UUID literals in the **final approved seed table**; no random UUID generation at each install, no silent overwrite, no implicit UUID namespace selection.
3. Replay with identical definitions is idempotent; a conflicting existing Role/PermissionSet/Permission/Action fails closed and reports the conflicting semantic key.
4. Install via authenticated migrator/owner-controlled migration only. Verify SYSTEM Role definitions cannot be mutated via ordinary runtime Role entry points, including `role_save`; a mere documentation statement is insufficient.
5. Do not add bootstrap, transfer, recovery, or privileged IAM runtime EXECUTE grants. Existing runtime signatures must be checked for bypasses of new invariants and SYSTEM definition protection.
6. Root bootstrap and ordinary Tenant activation may establish required membership/Role-assignment state only through protected, auditable installation/provisioning paths; no caller-supplied actor UUID is proof of identity.
7. Deny all out-of-scope requests and all unimplemented administrative Actions; Role possession alone does not make a dormant operation executable.
8. Prove fresh installation, re-install/idempotency, tampering/replay failure, protected Role write denial, runtime privilege inventory, root/steward invariant preservation, and concurrent operation behavior on real PostgreSQL with actual `mtmf_runtime` credentials.
9. Report any mismatch between the structural install-only Tenant Administrator Role and existing effective-role eligibility logic before changing authorization semantics.

## Remaining approval questions (do not silently decide)

1. **Minimum read semantics:** Approve `tenant:get-object` as the common-context minimum for Organization Roles, or replace those four rows with a reviewed `organization:get-object` exact Action.
2. **UUIDs:** Approve the final table of 22 fixed UUID literals (one PermissionSet and one Permission per Role), and a reproducible source-generation procedure if desired.
3. **Dormant grant posture:** Explicitly confirm that an installed but not yet executable Action/Permission is acceptable for v0.1 and must never be interpreted as a runtime capability.
4. **Future completeness:** Confirm that the remaining 34-Action candidate matrix stays unseeded until each relevant Action is implemented with verified-actor enforcement.
5. **Security check:** Inspect `role_add`, `role_save`, and all mutation stored functions for SYSTEM Role definition bypass before permitting the migration.

**Gate M closes only after these questions and the final literal UUID table are explicitly approved.** Until then, continue non-gated PR 10 structural work only.
