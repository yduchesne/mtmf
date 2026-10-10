# PR 10 — Exact built-in Permission manifest (review candidate)

**Status: PROPOSED / NOT APPROVED. Gate M remains CLOSED.** This document is a review artifact, **not** permission to execute a seed migration. Human approval must cover the exact rows and enforcement classifications below. Approval of the earlier *capability-level* tables in PR #36 is not approval of these executable rows.

**Sources:** [Security Model](SECURITY_MODEL.md), [Built-in Access and Installation](PR10_BUILTIN_ACCESS_AND_INSTALLATION.md), [PR 10 Architecture Decisions](PR10_ARCHITECTURE_DECISIONS.md). This proposal was reconciled against current `main`'s `domain/action.py`, `domain/iam_urn.py`, `domain/role.py`, `domain/permission_set.py`, `domain/permission.py`, `application/effective_roles.py`, and `persistence/postgres/roles.py`.

## 1. Critical distinction: defined is not enforced

| Layer | What exists on main | What this means for the seed |
| --- | --- | --- |
| Action URN grammar | Typed exact `ActionUrn` and exact `PermissionUrn` grammar | A syntactically valid Action is **not** an authorized operation |
| Example catalog | `BASELINE_ACTIONS` lists 17 examples for `principal`, `role`, `tenant` | These are **examples**, not a complete approved catalog or proof of an enforcement path |
| IAM aggregate | Role → nonempty PermissionSets → nonempty Permissions; IDs are UUIDs | A Role **cannot be seeded with an empty PermissionSet** using the current domain contract |
| Authorization | `Authorizer` and effective-Role resolver, using verified session facts | Permission matching is real, but ordinary repository stored functions are **not** per-end-user authenticated authorization entry points |
| PostgreSQL | Shared restricted `mtmf_runtime` credential; existing stored functions, signature allowlist and privilege verifier | A runtime `EXECUTE` grant is **not** evidence of verified actor identity or an Action-specific policy check |
| Stewardship | Architectural policy agreed; structural domain slice on `dev/pr10-bootstrap` | Privileged transfer/recovery is **not** a callable trusted user operation |

**Gate M decision rule:** Do not seed a Role/Permission merely because its URN parses, a repository function exists, or a Role description says it should be able to perform that operation. The operation must have a documented **verified-actor → authorization → transaction/write** enforcement path. Otherwise classify it `BLOCKED`.

## 2. Canonical Role identities

The exact proposed SYSTEM Role URNs (names require explicit approval; current Security Model specifies human-readable Role names, not these kebab-case spellings):

| Role | Proposed exact Role URN |
| --- | --- |
| System Administrator | `urn:mtmf:iam:roles:system:system-administrator` |
| System Security Administrator | `urn:mtmf:iam:roles:system:system-security-administrator` |
| System Reader | `urn:mtmf:iam:roles:system:system-reader` |
| Tenant Administrator | `urn:mtmf:iam:roles:system:tenant-administrator` |
| Tenant Security Administrator | `urn:mtmf:iam:roles:system:tenant-security-administrator` |
| Tenant Contributor | `urn:mtmf:iam:roles:system:tenant-contributor` |
| Tenant Reader | `urn:mtmf:iam:roles:system:tenant-reader` |
| Organization Administrator | `urn:mtmf:iam:roles:system:organization-administrator` |
| Organization Security Administrator | `urn:mtmf:iam:roles:system:organization-security-administrator` |
| Organization Contributor | `urn:mtmf:iam:roles:system:organization-contributor` |
| Organization Reader | `urn:mtmf:iam:roles:system:organization-reader` |

All definitions are SYSTEM-owned. Assignment scope, acting Identity, membership, dominance, and resource target are evaluated independently. A Role's label does not create an implicit scope.

## 3. Exact candidate Actions and enforcement inventory

Use `A(<resource>:<operation>)` as an abbreviation **only in the review tables below** for the full exact Action URN `urn:mtmf:iam:actions:system:<resource>:<operation>`. Every proposed Permission matcher corresponding to `A(r:o)` is exactly `urn:mtmf:iam:permissions:system:r:o`. No wildcard is permitted in the built-in seed.

| ID | Exact Action suffix (prefix `urn:mtmf:iam:actions:system:`) | Source | Verified end-user enforcement on current main | Seed decision |
| --- | --- | --- | --- | --- |
| A01 | `tenant:create-object` | BASELINE_ACTIONS | Not demonstrated; `tenant_add` is a repository stored function | BLOCKED |
| A02 | `tenant:get-object` | BASELINE_ACTIONS | Not demonstrated; `tenant_get` exists | BLOCKED |
| A03 | `tenant:update-object` | BASELINE_ACTIONS | Not demonstrated; `tenant_save` exists | BLOCKED |
| A04 | `tenant:delete-object` | BASELINE_ACTIONS | Not demonstrated | BLOCKED |
| A05 | `tenant:set-active` | BASELINE_ACTIONS | No PR 10 lifecycle write path yet | BLOCKED |
| A06 | `tenant:set-inactive` | BASELINE_ACTIONS | No PR 10 lifecycle write path yet | BLOCKED |
| A07 | `tenant:transfer-stewardship` | BASELINE_ACTIONS | No trusted actor boundary or transfer procedure | BLOCKED |
| A08 | `tenant:recover-stewardship` | New explicit proposal | No trusted actor boundary or recovery procedure | BLOCKED |
| A09 | `principal:create-object` | BASELINE_ACTIONS | Not demonstrated; `principal_add` exists | BLOCKED |
| A10 | `principal:get-object` | BASELINE_ACTIONS | Not demonstrated; `principal_get` exists | BLOCKED |
| A11 | `principal:update-object` | BASELINE_ACTIONS | Not demonstrated; `principal_save` exists | BLOCKED |
| A12 | `principal:delete-object` | BASELINE_ACTIONS | Not demonstrated | BLOCKED |
| A13 | `principal:set-active` | BASELINE_ACTIONS | No separate verified lifecycle operation shown | BLOCKED |
| A14 | `principal:set-inactive` | BASELINE_ACTIONS | No separate verified lifecycle operation shown | BLOCKED |
| A15 | `role:create-object` | BASELINE_ACTIONS | `role_add` exists, but not verified actor/anti-escalation | BLOCKED |
| A16 | `role:get-object` | BASELINE_ACTIONS | `role_get` exists, but not verified actor | BLOCKED |
| A17 | `role:update-object` | BASELINE_ACTIONS | `role_save` exists, but SYSTEM definition protection not proven | BLOCKED |
| A18 | `role:delete-object` | BASELINE_ACTIONS | No verified policy-deletion path shown | BLOCKED |
| A19 | `organization:get-object` | Proposed | `organization_get` exists, no verified actor | BLOCKED |
| A20 | `organization:create-object` | Proposed | `organization_add` exists, no verified actor | BLOCKED |
| A21 | `organization:update-object` | Proposed | `organization_save` exists, no verified actor | BLOCKED |
| A22 | `organization:delete-object` | Proposed | No verified actor/path shown | BLOCKED |
| A23 | `identity:get-object` | Proposed | `identity_get` exists, no verified actor | BLOCKED |
| A24 | `identity:create-object` | Proposed | `identity_add` exists, no verified actor | BLOCKED |
| A25 | `identity:update-object` | Proposed | `identity_save` exists, no verified actor | BLOCKED |
| A26 | `identity:delete-object` | Proposed | No verified actor/path shown | BLOCKED |
| A27 | `group:get-object` | Proposed | `group_get` exists, no verified actor | BLOCKED |
| A28 | `group:create-object` | Proposed | `group_add` exists, no verified actor | BLOCKED |
| A29 | `group:update-object` | Proposed | `group_save` exists, no verified actor | BLOCKED |
| A30 | `group:delete-object` | Proposed | No verified actor/path shown | BLOCKED |
| A31 | `role-assignment:create-identity` | Proposed | `identity_role_assignment_add` exists; no verified actor/anti-escalation | BLOCKED |
| A32 | `role-assignment:remove-identity` | Proposed | `identity_role_assignment_remove` exists; no verified actor/anti-escalation | BLOCKED |
| A33 | `role-assignment:create-group` | Proposed | `group_role_assignment_add` exists; no verified actor/anti-escalation | BLOCKED |
| A34 | `role-assignment:remove-group` | Proposed | `group_role_assignment_remove` exists; no verified actor/anti-escalation | BLOCKED |

Typed membership Actions, PermissionSet/Permission administration, sensitive IAM reads, ordinary non-container business resources, and Organization-scoped assignment semantics require their own reviewed Action inventory. **Do not replace missing operations with generic container CRUD.** This table is an explicit **incomplete candidate catalog**, not an approved executable manifest.

## 4. Candidate Role → Action allocation for review

The table below describes **desired capability allocation** using IDs from §3. Every row remains `BLOCKED` for executable seeding until its exact Action and enforcement point are approved. All listed grants have `ALLOW` effect; there are no implicit grants.

| Role | Candidate Action IDs | Explicit exclusions |
| --- | --- | --- |
| System Administrator | A01–A06, A08–A11, A15–A17, A19–A25, A27–A33 | A07 steward-only transfer; ROOT recovery; unrestricted SYSTEM policy edits |
| System Security Administrator | A02, A10, A15–A17 **for TENANT-defined Roles only**, A19, A23–A25, A27–A33 | A07–A08; ordinary resource writes; SYSTEM policy edits |
| System Reader | A02, A10, A16, A19, A23, A27 | All writes and sensitive unreviewed reads |
| Tenant Administrator | A02–A03, A07, A10–A11, A15–A17 **TENANT definitions only**, A19–A25, A27–A33 | A01, A04–A06, A08, SYSTEM policy edits; stewardship without designation |
| Tenant Security Administrator | A02, A10–A11 (authorized IAM only), A15–A17 **TENANT definitions only**, A19, A23–A25, A27–A33 | A07–A08; ordinary container writes; SYSTEM policy edits |
| Tenant Contributor | A02, A19 | Tenant/Organization container writes, lifecycle, IAM; ordinary-resource Actions remain undefined |
| Tenant Reader | A02, A10, A16, A19, A23, A27 | Writes and sensitive unreviewed reads |
| Organization Administrator | A19–A21, A23, A27, A31–A34 **only if explicitly Organization-refined** | Tenant-level IAM, Tenant lifecycle, stewardship |
| Organization Security Administrator | A19, A23, A27, A31–A34 **only if explicitly Organization-refined** | Ordinary container writes, Tenant-level IAM, stewardship |
| Organization Contributor | A19 | Container writes, lifecycle, IAM; ordinary-resource Actions remain undefined |
| Organization Reader | A19, A23, A27 **only when scoped and permitted** | Writes and sensitive unreviewed reads |

**Review caution:** These allocations are *not yet fully correct as executable policy* because some Action names cannot distinguish definition ownership or resource scope on their own. The final authorization path must check the target's defining Tenant, Organization refinement, and protected SYSTEM objects; the exact Permission matcher alone cannot express those conditions. If a listed Action cannot be safely constrained, remove it from the seed.

**Another important caution:** An Organization Administrator's ability to update its Organization container remains a candidate, while the agreed Contributor exclusion is absolute. If lifecycle and ordinary object administration need finer distinctions, introduce separate reviewed Actions; do not rely on a generic update to change lifecycle.

## 5. Seed identity, repeatability, and transaction contract

| Object | Proposed deterministic seed rule |
| --- | --- |
| Role | Exact approved Role URN from §2; stable immutable semantic identity |
| PermissionSet | Exactly one ALLOW set per Role initially; deterministic UUID derived from a fixed reviewed namespace + Role URN, **only after approving namespace** |
| Permission | One Permission object per approved exact Action matcher per Role; deterministic UUID derived from namespace + Role URN + exact Permission URN |
| Action | Exact shared Action URN; no wildcard |
| Matching | Permission matcher `urn:mtmf:iam:permissions:system:r:o` matches only Action `urn:mtmf:iam:actions:system:r:o` |
| Ownership | PermissionSet points to Role; Permission points to its PermissionSet |
| Replay | Identical seed is no-op; differing existing object is a hard integrity failure, never silently overwritten |
| Atomicity | One protected installation transaction; no partial visible seed |
| Privileges | No new runtime EXECUTE on privileged bootstrap, transfer, or recovery |

**Unresolved:** A fixed UUID namespace must be specified and reviewed before generating exact UUID rows. The current domain requires **nonempty PermissionSets and nonempty Roles**. Therefore a Role with zero safely enforceable Actions **cannot be seeded as an empty placeholder**. Either implement and verify an appropriate minimum read Action, change the contract through an approved design, or defer that Role. Do not fabricate a harmless Action to satisfy the constructor.

## 6. Gate M — review and approval checklist

- [ ] Approve or amend the eleven exact Role URN spellings.
- [ ] Approve every exact Action URN intended for PR 10, including any missing typed membership and assignment Actions.
- [ ] For each Action, identify the **actual** verified-actor entry point, Authorizer check, scope/dominance/anti-escalation guard, and protected database mutation (or mark `NOT ENFORCED — EXCLUDE`).
- [ ] Resolve how ordinary repository reads/writes are safely exposed (or explicitly defer their grants).
- [ ] Confirm which subset of the candidate matrix is in PR 10 versus later service/API work.
- [ ] Resolve nonempty PermissionSet requirement for Roles without safely enforceable Actions.
- [ ] Approve a deterministic UUID namespace and exact generated PermissionSet/Permission UUID rows.
- [ ] Confirm that the final manifest is **complete and finite**: every seed row is enumerated and no range or conceptual family is left to interpret.
- [ ] Confirm runtime privilege allowlist remains unchanged for privileged functions until trusted actor verification exists.
- [ ] Approve the exact final table before coding-agent seed implementation.

**Human approval must refer to a specific commit of this document.** Editing a review candidate or merging a documentation PR alone is not equivalent to approving an executable manifest unless that approval is explicit.

## 7. Instructions to the coding agent

**STOP at Gate M.** Continue only already-approved, non-gated structural work. Do not create migration `0006`, `sql/v006`, bootstrap/transfer/recovery stored functions, built-in seed rows, or privileged runtime grants from this candidate.

Once an exact manifest has been approved, re-check current `main`, reconcile `dev/pr10-bootstrap`, implement only the approved rows and enforcement paths, and run `./build.sh --qa`, `./build.sh --sec`, `./build.sh --integration`, and the required fresh-install/privilege/concurrency acceptance matrix. Record commands, commit SHA, database role topology, and actual outcomes. A previously green regression suite is not PR 10 feature acceptance.
