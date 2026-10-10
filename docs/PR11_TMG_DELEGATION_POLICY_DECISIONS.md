# PR 11 — TenantManagementGroup delegation policy decisions (Gate D)

**Status: APPROVED (Gate D security semantics).** The reviewer approved the
D01-D09 decisions below. Delegated authorization is still **not enabled**:
one follow-on implementation decision remains open and is recorded at the
end of this document (the canonical management Role URNs and their
management Permission allocations). No coding agent may invent additional
Role definitions or Permission allocations.

Authoritative sources:

- [Security Model](SECURITY_MODEL.md) §20 (Tenant Management Groups),
  §20.2 (SYSTEM groups), §25 item 8.
- [Domain Model](DOMAIN_MODEL.md) §15 (TenantManagementGroup),
  §19 items 5-6.
- [Authorization](AUTHORIZATION.md) §7 (TenantManagementGroup context).
- [Roadmap](ROADMAP_V01.md) PR 11.

> **Invariant:** Cross-Tenant management authority exists only when the
> target is covered by a valid management relationship, the verified acting
> Identity is explicitly eligible under the approved rule, and the
> management Role independently authorizes the exact Action. Otherwise
> DENY.

## Approved decisions

### D01 — Manager-side actor eligibility — APPROVED

Delegated management authority requires an explicit Identity-level
eligibility designation associated with the TenantManagementGroup.

Ordinary manager-Tenant membership, Tenant Administrator status,
stewardship, or IAM Group membership does **not** automatically confer
eligibility. Designations are scoped to the management group and its
manager Tenant. Eligibility is evaluated only against a verified acting
Identity.

### D02 — Management Role binding — APPROVED

Each TenantManagementGroup references exactly one management Role. That
Role supplies contextual authorization policy only when the acting
Identity is eligible and the target Tenant is covered by the management
relationship. The management Role is **not** materialized as an ordinary
`IdentityRoleAssignment` or `GroupRoleAssignment` and never appears in
ordinary same-Tenant effective-Role resolution.

### D03 — ROOT eligibility — APPROVED

Only the canonical root Identity may exercise the ROOT
TenantManagementGroup. Root Identity recovery must replace the eligible
actor without retaining authority for the previous root Identity. No
independent, manually maintained ROOT eligibility list is created.

### D04 — Lifecycle — APPROVED

Delegated authorization requires active, valid manager and managed Tenants
and an active, valid acting Principal/Identity with the required
manager-Tenant memberships. PROVISIONING, SUSPENDED, deleted, missing, or
otherwise invalid participants cannot exercise delegated authority.

### D05 — Management Role ownership — APPROVED

ROOT and SYSTEM TenantManagementGroups may reference only approved
SYSTEM-defined management Roles. TENANT-defined Roles must never provide
cross-Tenant management authority. Management Role identity, namespace,
ownership, and policy applicability must be verified structurally. The
concrete approved Role URNs remain an open implementation decision (below).

### D06 — Delegation boundaries — APPROVED

SYSTEM TenantManagementGroups cannot manage the ROOT Tenant, cannot manage
their own manager Tenant, and cannot establish transitive delegation.
Management relationships must not create management cycles. ROOT's
implicit universal coverage is a unique bootstrap invariant, not a
capability that SYSTEM groups inherit.

### D07 — Authorized operations — APPROVED

Delegated authority is restricted to explicit Actions permitted by the
applicable management Role. It does not automatically confer Tenant
Stewardship, unrestricted administration, or permission to mutate another
Tenant's application extension data. Existing specificity, DENY
precedence, default-DENY, and strict-dominance rules are preserved.

### D08 — Revocation — APPROVED

Removal of actor eligibility, managed-Tenant membership, or applicable
management Role authority revokes delegated authorization for subsequent
decisions. A transaction-consistency contract for concurrent
authorization and revocation must be defined and implemented. Already
authorized operations are **not** retroactively revoked.

### D09 — Trusted acting Identity — APPROVED

A caller-supplied Identity UUID is not authentication. PR 11 consumes only
trusted, verified internal acting-Identity context when evaluating
delegation. Externally callable end-user identity propagation remains PR 14
scope. No actor UUID session variables, request headers, or other
unverified trust substitutes are introduced.

## Implementation status of the structural subset

Implemented and unit-verified before approval (preserved):

- typed structural `TenantManagementGroup` and
  `TenantManagementGroupMembership` domain values with pure validators
  (`packages/mtmf-core/src/mtmf_core/domain/management_group.py`);
- fail-closed structural contextual resolver
  (`packages/mtmf-core/src/mtmf_core/application/management_scope.py`),
  returning a non-elevating candidate and always reporting
  `actor_eligible=False`;
- structural unit tests.

Still to implement after the open Role decision is resolved: Identity
eligibility designations, PostgreSQL schema/stored functions, ROOT
bootstrap integration, SPI/UnitOfWork repositories, Authorizer/policy
integration, lifecycle and revocation semantics.

## OPEN DECISION (blocks schema work) — management Role catalog

The approved policy requires each TenantManagementGroup to reference an
**approved SYSTEM-defined management Role**. The approved built-in Role
catalog installed by Alembic revision `0006`
(`docs/PR10_GATE_M_SEED_POLICY.md`) contains exactly eleven SYSTEM Roles,
each carrying a single narrow read Permission:

| Role URN | Seeded Permission |
| --- | --- |
| `urn:mtmf:iam:roles:system:system-administrator` | `tenant:get-object` |
| `urn:mtmf:iam:roles:system:system-security-administrator` | `role:get-object` |
| `urn:mtmf:iam:roles:system:system-reader` | `tenant:get-object` |
| `urn:mtmf:iam:roles:system:tenant-administrator` | `tenant:get-object` |
| `urn:mtmf:iam:roles:system:tenant-security-administrator` | `role:get-object` |
| `urn:mtmf:iam:roles:system:tenant-contributor` | `tenant:get-object` |
| `urn:mtmf:iam:roles:system:tenant-reader` | `tenant:get-object` |
| `urn:mtmf:iam:roles:system:organization-administrator` | `organization:get-object` |
| `urn:mtmf:iam:roles:system:organization-security-administrator` | `role:get-object` |
| `urn:mtmf:iam:roles:system:organization-contributor` | `organization:get-object` |
| `urn:mtmf:iam:roles:system:organization-reader` | `organization:get-object` |

The broader 34-Action candidate catalog in
`docs/PR10_EXACT_PERMISSION_MANIFEST.md` remains candidate-only and
unseeded. No role in the approved catalog is a cross-Tenant management
Role, and no management-specific Permission is approved.

**Decision required.** Approve one of:

1. a new SYSTEM-defined management Role URN (for example
   `urn:mtmf:iam:roles:system:tenant-management`) with an explicitly
   reviewed management Permission allocation written through a later
   additive migration; or
2. an explicit instruction that an existing approved SYSTEM Role is
   designated as the management Role and, if so, which exact Permissions
   delegated authority may exercise.

Until this decision is recorded, no schema migration, stored function,
bootstrap integration, or Authorizer integration may be added, and no
built-in Role/Permission may be invented.

## Required negative cases

Once implemented, the following must remain DENY (or typed fail-closed
infrastructure failure) and require explicit test evidence:

- no management relationship covers the target Tenant;
- manager acting Identity is not eligible under the approved rule;
- management Role produces no matching ALLOW, or a winning DENY;
- TENANT-defined Role used for cross-Tenant management;
- extension mutation through a SYSTEM-defined management Role;
- PROVISIONING/SUSPENDED/soft-deleted manager, target, or actor;
- self-management, root target, or management cycle;
- revoked relationship/actor eligibility used concurrently with an
  authorization request;
- unverified or caller-supplied acting identity.
