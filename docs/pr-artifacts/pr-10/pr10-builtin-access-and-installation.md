# MTMF v0.1 — Built-in access policy and installation baseline

> **Status:** Agreed architectural policy for PR 10. This document explains the intended behavior; it does not claim that bootstrap, privileged operations, or the HTTP trust boundary are implemented. The exact executable seed manifest and new Action enforcement paths require review before migration 0006 is finalized.

## At a glance

| Topic | Decision | Why it matters |
| --- | --- | --- |
| Built-in Roles | Keep the 11 SYSTEM-defined Roles already listed in [Security Model](SECURITY_MODEL.md#16-built-in-roles) | One consistent vocabulary across MTMF |
| Built-in Permissions | Explicit exact-Action ALLOW grants; no wildcard grants in the initial seed | New Actions never become implicitly authorized |
| PermissionSets | Initially one ALLOW PermissionSet owned by each built-in Role | Simple, inspectable policy; unmatched requests already DENY |
| SYSTEM-owned Role definitions | Protected from ordinary edits; changed by controlled MTMF migrations | Administrators cannot rewrite global policy |
| Tenant-defined Roles | Customizable within the defining Tenant | Tenants can tailor delegated access |
| Tenant Administrator | Manages ordinary Tenant resources **and** Tenant IAM | Practical administration without a separate security administrator |
| Tenant Security Administrator | Manages Tenant IAM, not ordinary resource writes | Enables separation of duties |
| Contributors | Manage ordinary resources, not Tenant/Organization containers or lifecycle | Limits scope and administrative escalation |
| Stewardship | Separate from Roles; only the designated acting Identity can use steward dominance | A second Tenant Administrator is not automatically the steward |
| Installation | New v0.1 installations start with an empty database | No legacy-data repair or backfill required |

## Understanding the built-in Roles

All eleven Role **definitions** belong to the SYSTEM namespace. A Role assignment still has a specific Tenant context, and may be restricted to an Organization. A SYSTEM-defined Role is **not** a license to operate outside the acting Identity's valid scope.

| Role | Ordinary resources | Identity and access management (IAM) | Stewardship / exceptional authority |
| --- | --- | --- | --- |
| System Administrator | System-wide administration below ROOT | System administrative IAM, subject to protected-definition rules | May recover an ordinary Tenant's stewardship with an explicit Permission and trusted actor |
| System Security Administrator | Read ordinary resources | System-wide IAM administration below ROOT | No stewardship recovery by default |
| System Reader | Read permitted resources | Read permitted IAM information | None |
| Tenant Administrator | Administer ordinary Tenant resources and Organizations | Full Tenant IAM administration, subject to delegation constraints | May transfer stewardship **only** when acting as designated steward |
| Tenant Security Administrator | Read ordinary resources | Tenant IAM administration | None |
| Tenant Contributor | Manage ordinary resources within the Tenant | No IAM administration | None |
| Tenant Reader | Read permitted Tenant resources | Read permitted IAM information | None |
| Organization Administrator | Administer ordinary resources inside its Organization | Organization-scoped IAM | None |
| Organization Security Administrator | Read ordinary resources | Organization-scoped IAM | None |
| Organization Contributor | Manage ordinary resources inside its Organization | No IAM administration | None |
| Organization Reader | Read permitted Organization resources | Read permitted IAM information | None |

**Contributor boundary:** Tenant Contributor and Organization Contributor do **not** create, delete, activate, suspend, or otherwise administer Tenant or Organization containers. Ordinary resources are objects administered *within* the authorized scope, not the scope containers themselves. If MTMF has no applicable ordinary-resource Action yet, the Contributor Role receives no invented container-write Permission as a substitute.

**Reader boundary:** Read access is not permission to expose secrets or sensitive security material. Sensitive reads need explicit, reviewed Actions and restrictions.

## What each administrative capability means

| Capability | Who may receive it | Additional rule |
| --- | --- | --- |
| Manage Tenant/Organization containers | Relevant Administrator, not Contributor | Valid assignment scope, dominance, and protected-object checks |
| Manage ordinary resources | Relevant Administrator or Contributor | Resource-specific exact Action must exist |
| Manage Tenant IAM | Tenant Administrator or Tenant Security Administrator; authorized SYSTEM administrators | Tenant-bound, no cross-Tenant Role leakage |
| Manage Organization IAM | Organization Administrator or Organization Security Administrator; authorized superior administrators | Only the assigned Organization |
| Assign Tenant Administrator | Authorized Tenant Administrator and appropriately authorized superior administrators | No automatic stewardship; cannot delegate authority outside permitted bounds |
| Change SYSTEM-owned Role/Permission definitions | **No ordinary Role** | Controlled migration only |
| Transfer ordinary Tenant stewardship | Designated steward acting Identity with exact transfer Permission | Eligible successor, atomic transition, audit |
| Recover ordinary Tenant stewardship | Verified SYSTEM administrator with exact recovery Permission | Not ordinary Tenant self-promotion |
| Bootstrap or recover ROOT | Protected deployment/operator authority | Not a normal Role Permission or runtime API |

A Role assignment is not a blanket delegation right. Assignment of administrative Roles must pass the existing membership, dominance, scope, and anti-escalation checks. Neither a Role assignment nor common Principal ownership causes an Identity to inherit stewardship from another Identity.

## Action and Permission conventions

The [Security Model](SECURITY_MODEL.md#15-actions-and-permission-rule-grammar) defines an exact Action as `<resource>:<verb>-<qualifier>`, represented by an Action URN such as `urn:mtmf:iam:actions:system:tenant:transfer-stewardship`.

| Policy element | v0.1 rule |
| --- | --- |
| Role URN | `urn:mtmf:iam:roles:system:<role-name>` |
| Action URN | `urn:mtmf:iam:actions:<definition-namespace>:<resource>:<operation>` |
| Permission matching | Exact Action match only in the initial built-in seed |
| PermissionSet | Owned by exactly one Role, immutable UUID object identity, ALLOW effect initially |
| Permission | Owned by a PermissionSet, immutable UUID object identity, exact matcher URN |
| No match | DENY |
| Conflicting effective Permissions | Existing specificity and DENY-precedence rules continue to apply |
| PermissionSet URN | **Not introduced** merely for the seed; use existing object identity/schema |

**A missing grant is DENY.** We do not need to seed explicit DENY entries for every excluded Action. The authorization engine must still honor DENY entries and specificity if later policy definitions contain them.

### Action catalog for the implementation review

The table below distinguishes existing documented examples from **proposed** fine-grained Actions. Proposed Actions must be reconciled with the actual Action registry, stored-function behavior, and authorization checks. A proposed name is not permission to seed an unenforced operation.

| Area | Exact Action examples / proposed families | Boundary |
| --- | --- | --- |
| Tenant | `tenant:create-object`, `tenant:get-object`, `tenant:update-object`, `tenant:delete-object`, `tenant:set-active`, `tenant:set-inactive`, `tenant:transfer-stewardship` | Recovery needs a separate reviewed `tenant:recover-stewardship` Action |
| Organization | `organization:create-object`, `organization:get-object`, `organization:update-object`, `organization:delete-object` | No Contributor container mutation |
| Principal / Identity | Baseline exact CRUD; separate `set-active` and `set-inactive` where applicable | Protected root and steward prerequisites remain guarded |
| Group | Exact object CRUD where implemented | Tenant-bound |
| Memberships | Proposed typed create/remove Actions for Principal–Tenant, Identity–Tenant, Group–Tenant, Identity–Group, Identity–Organization, Group–Organization | Not generic CRUD; cascading removal and audit still required |
| Role assignments | Proposed distinct Identity-assignment and Group-assignment create/remove Actions | Separate from editing Role definitions |
| Role / PermissionSet / Permission definitions | Exact object CRUD where supported | SYSTEM-owned definitions cannot be modified by ordinary administrators |

**Important:** The Action examples above are not yet the complete executable seed. Before implementation, the PR 10 plan must provide a line-by-line Role → PermissionSet UUID/identity → Permission UUID/URN → exact Action URN/effect manifest, confirm each Action exists or is explicitly added, and verify that every granted operation has an enforcement path. Unsupported operations must be omitted, not guessed.

## Stewardship is not another administrator Role

| Situation | May transfer stewardship? | Explanation |
| --- | --- | --- |
| Designated steward Identity, valid Tenant Administrator grant and transfer Permission | Yes, after all checks | Both Permission and designated acting Identity are required |
| Different Identity belonging to the same steward Principal | No | Acting Identities do not share stewardship dominance |
| Delegated Tenant Administrator | No | Administrative Role assignment alone is not stewardship |
| Tenant Security Administrator | No | IAM specialization does not confer stewardship |
| Authorized SYSTEM administrator | Recovery only, with separate Permission | Exceptional ordinary-Tenant recovery; not ROOT recovery |

Transfer and recovery must be atomic, auditable, and concurrency-safe. Until MTMF has a trusted service-side acting-Identity boundary, ordinary runtime connections must not be granted callable transfer or recovery entry points. The shared database login does not authenticate the end user.

## Fresh installation and lifecycle

**MTMF v0.1 has no existing production installations.** We therefore choose a fresh-database baseline rather than a compatibility migration for historical development records.

| Concern | v0.1 decision |
| --- | --- |
| Identity origin | Required, immutable `LOCAL` or `FEDERATED` |
| Legacy `UNKNOWN` origin | Not introduced |
| Ordinary Tenant lifecycle | `PROVISIONING` → `ACTIVE` → `SUSPENDED`; `SUSPENDED` → `ACTIVE` permitted after revalidation |
| New ordinary Tenant | Starts `PROVISIONING`, non-authorizing |
| Activate ordinary Tenant | Requires eligible steward Principal, designated acting Identity, required memberships and Tenant Administrator assignment |
| Root Tenant | Established `ACTIVE` through protected bootstrap; cannot be suspended or deleted |
| Built-in IAM definitions | Seed deterministically during initial installation; detect inconsistent existing definitions |
| Migration sequence | Retain additive, versioned migrations `0001` through `0006` |
| Old development databases | May be dropped and reinitialized; **no automatic conversion guarantee** |
| Pre-v0.1 production migration | Not supported; no installations exist |

A fresh database is an **installation prerequisite**, not an instruction to destroy a database automatically. Resetting development data must be an explicit operator action. Once v0.1 is released, later upgrades will need their own migration compatibility policy.

### Lifecycle behavior

| Tenant state | Can authorize ordinary Tenant sessions? | Typical purpose |
| --- | --- | --- |
| `PROVISIONING` | No | Set up memberships, Roles and designated stewardship safely |
| `ACTIVE` | Yes, subject to all authorization checks | Normal operation |
| `SUSPENDED` | No | Preserve records while Tenant access is paused |

Soft deletion is separate from lifecycle state. Reactivation must revalidate all active-steward invariants. Root bootstrap and ordinary Tenant activation must never expose partially initialized active state.

## What PR 10 still has to implement

These are **design decisions**, not claims of existing implementation. PR 10 Amendment #1 must cover the exact reviewed seed manifest, protected bootstrap, origin and lifecycle schema, database guards across existing write paths, atomic stewardship operations, concurrency and audit tests, and restricted database grants.

The HTTP service and verified end-user identity propagation are separate architectural work. If they are not delivered in PR 10, privileged user-facing transfer/recovery must remain inaccessible rather than accept caller-supplied actor IDs.

See also [PR 10 Architecture Decisions](PR10_ARCHITECTURE_DECISIONS.md), [Root Administration and Tenant Stewardship](ROOT_AND_STEWARDSHIP.md), and [Authorization](AUTHORIZATION.md).
