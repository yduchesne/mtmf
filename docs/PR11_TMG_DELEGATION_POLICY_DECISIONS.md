# PR 11 — TenantManagementGroup delegation policy decisions (Gate D)

**Status: APPROVED (Gate D security semantics) and management Role policy approved.** The reviewer approved D01-D09 and Option 1 of STOP `PR11-STOP-01`. PR 11 is implemented on `dev/tenant-mgmt-group`: the structural schema, the two approved SYSTEM management Roles, explicit managed-Tenant and Identity eligibility relationships, atomic ROOT bootstrap integration, fail-closed delegation, and Authorizer integration. Delegated authorization requires an eligible actor, a covered target, and a matching management-Role Permission; nothing else elevates.

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

## Implementation status

Implemented:

- typed `TenantManagementGroup`, `TenantManagementGroupMembership`, and
  `TenantManagementGroupActorEligibility` domain values with pure validators
  (`packages/mtmf-core/src/mtmf_core/domain/management_group.py`);
- the fail-closed eligibility-aware contextual resolver
  (`resolve_management_scope`) and application-layer
  `ManagementAuthorizationResolver`;
- the Authorizer cross-Tenant delegation path (`NO_MANAGEMENT_SCOPE`,
  management-Role-only policy, extension-mutation denial);
- additive Alembic revision `0009` / packaged `sql/v009`: structural
  tables, database guards, the two approved management Roles, atomic ROOT
  bootstrap integration, installation-only mutation functions, and
  narrowly reviewed runtime reads;
- SPI/UnitOfWork repositories (provider-neutral, in-memory, PostgreSQL);
- unit and real-PostgreSQL integration, concurrency, and privilege tests.

## APPROVED management Role catalog

The reviewer approved Option 1 of STOP `PR11-STOP-01`. Two SYSTEM-defined
built-in Roles are installed by Alembic revision `0009`, each owning exactly
one ALLOW PermissionSet with exactly one exact Permission for
`tenant:get-object`:

| Role URN | Permission matcher |
| --- | --- |
| `urn:mtmf:iam:roles:system:root-tenant-management` | `urn:mtmf:iam:permissions:system:tenant:get-object` |
| `urn:mtmf:iam:roles:system:tenant-management` | `urn:mtmf:iam:permissions:system:tenant:get-object` |

No wildcard Permission or additional Action is approved. The deterministic
seed-identity convention and UUIDv5 namespace from PR 10 are reused.

- A ROOT TenantManagementGroup references `root-tenant-management` only.
- A SYSTEM TenantManagementGroup references `tenant-management` only.
- Both are protected built-in SYSTEM definitions and are never materialized
  as ordinary Identity/Group Role assignments.

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
