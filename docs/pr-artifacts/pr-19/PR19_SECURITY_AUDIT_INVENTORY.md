# PR 19 Security/Audit Mutation Inventory

**PR:** roadmap PR 19.
**Date:** 2026-10-13.
**Base commit:** `ada8c5e`.
**Status:** inventory complete; no new audit schema added.

## 1. Method

Every `CREATE OR REPLACE FUNCTION mtmf.*` body in
`packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v*/` was parsed
and classified by whether it performs `INSERT`/`UPDATE`/`DELETE` and whether
it writes an audit table. The current head is `0011_authentication_bindings`.
The two existing audit tables are `mtmf.membership_removal_audit` (v002) and
`mtmf.stewardship_audit` (v008); both remain append-only and unchanged.

Classification legend:

- **ATOMIC** — the mutation and its durable audit row commit or roll back together.
- **NO STATE** — reference/seed installation with no Tenant/Identity/Role/subscription authorization state.
- **GAP** — an authoritative security-state mutation with **no** atomic audit row.
- **UNRESOLVED** — the write function receives no verified actor provenance, so an audit row could not truthfully attribute an actor.

## 2. Inventory

| Area | Stored function(s) | Audit | Trust attribution |
|---|---|---|---|
| Membership removal (v002) | `remove_identity_tenant_membership`, `remove_group_tenant_membership`, `remove_principal_tenant_membership`, `remove_identity_group_membership`, `remove_identity_org_membership`, `remove_group_org_membership` | **ATOMIC** (`membership_removal_audit`; one compact row per operation; caller-supplied `actor_identity_id_value` is explicitly *unverified* provenance) | Recorded, explicitly unverified |
| Root/stewardship (v008) | `bootstrap_root`, `designate_steward`, `recover_root_identity` | **ATOMIC** (`stewardship_audit`) | Recorded within the approved stewardship contract |
| Tenant lifecycle (v008) | `activate_tenant`, `suspend_tenant` | **GAP** | **UNRESOLVED** — only `tenant_id`; no actor argument |
| Tenant lifecycle (v007/v008/guards) | `tenant_add`, `tenant_save` | **GAP** | **UNRESOLVED** — structural persistence; no actor argument |
| Identity/Principal/Group/Org (v004, v007) | `org_add/save`… `organization_add`, `organization_save`, `principal_add`, `principal_save`, `identity_add`, `identity_save`, `group_add`, `group_save` | **GAP** | **UNRESOLVED** — structural persistence; no actor argument |
| Membership add (v004) | `principal_tenant_membership_add`, `identity_tenant_membership_add`, `group_tenant_membership_add`, `identity_group_membership_add`, `identity_org_membership_add`, `group_org_membership_add` | **GAP** | **UNRESOLVED** — no actor argument |
| Action catalog (v004) | `action_add` | **GAP** (reference data; granting access requires a Role/PermissionSet change) | **UNRESOLVED** |
| Role/PermissionSet policy (v004, v006) | `role_add`, `role_save`, `role_insert_children` | **GAP** | **UNRESOLVED** — no actor argument |
| Role assignment (v005) | `identity_role_assignment_add`, `identity_role_assignment_remove`, `group_role_assignment_add`, `group_role_assignment_remove` | **GAP** | **UNRESOLVED** — no actor argument |
| Builtin policy install (v006) | `install_builtin_policy` | **NO STATE** (idempotent system seed) | n/a |
| TenantManagementGroup (v009) | `install_management_roles` (`NO STATE`), `create_root_management_group`, `initialize_root_tenant_management_group`, `create_tenant_management_group`, `add/remove_tenant_management_group_membership`, `add/remove_tenant_management_group_actor_eligibility` | **GAP** | **UNRESOLVED** — no actor argument |
| Application registry (v010) | `application_add`, `application_save`, `application_tenant_registration_add`, `application_tenant_registration_save`, `tenant_application_subscription_add`, `tenant_application_subscription_save` | **GAP** | **UNRESOLVED** — no actor argument |
| Authentication bindings (v011) | `service_credential_application_add`, `service_credential_application_revoke`, `external_subject_identity_add`, `external_subject_identity_revoke` | **GAP** | **UNRESOLVED** — no actor argument |

Read-only `*_get`/`*_find_*` functions are out of scope.

## 3. Disposition

The uncovered write functions are the core structural persistence surface
used by the application layer. None of them receives a verified actor
identity, and the persistence SPI does not carry an authenticated session
identity. Adding audit rows for them would either (a) fabricate actor
attribution or (b) require a new trust-boundary contract that threads
verified provenance from the application layer into every stored function.

Per `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` §9 and the PR 19 STOP
conditions, PR 19 therefore:

1. preserves `membership_removal_audit` and `stewardship_audit` unchanged;
2. adds **no** generic `security_event_audit` table, unrestricted audit-write
   function, or unverified actor attribution;
3. records the gap as an **UNRESOLVED TRUST ATTRIBUTION** item requiring an
   approved trust-boundary decision and a separately scoped follow-up PR
   (proposed: "PR 19A — verified-provenance mutation audit").

This disposition matches the approved architecture: the dominant PR 19
concern is the OTel observability pipeline, and a trust-boundary redesign
must not be improvised inside it. See `PR19_STOP_REPORT.md`.
