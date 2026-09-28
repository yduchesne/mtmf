# MTMF Authorization

## 1. Purpose

This document describes the authorization-evaluation architecture implemented by `mtmf-core`.

It is subordinate to [SECURITY_MODEL.md](SECURITY_MODEL.md). The security model defines normative security semantics; this document explains how the `Authorizer` is expected to apply them. If the documents conflict, `SECURITY_MODEL.md` takes precedence.

This document is intentionally shallow while the security model is still evolving.

## 2. Authorizer

`Authorizer` is the authoritative permission-evaluation engine inside `mtmf-core`.

Its fundamental question is:

> May this specific acting Identity, in this (Tenant, Principal, Identity) session, perform this exact Action against this target in this authorization context?

Callers request an **Action**, not a Permission. The caller MUST NOT reconstruct MTMF authorization by selecting a Permission itself.

The Authorizer evaluates policy; it does not perform the protected business operation.

## 3. Default Deny

Authorization is deny-by-default.

The Authorizer MUST positively establish authorization before a protected operation proceeds. Missing roles, unknown Actions, absent or inconsistent membership/context, unresolved scope, invalid delegation, or other insufficient policy state MUST NOT fall through to ALLOW.

An infrastructure failure while evaluating policy is not itself a policy DENY, but the protected operation MUST fail closed.

## 4. Inputs

An authorization decision may require:

- session Tenant, acting Principal, and acting Identity;
- valid active PrincipalTenantMembership and IdentityTenantMembership in the session Tenant;
- requested exact Action;
- target resource and security scope;
- Tenant and Organization context;
- active/deleted state;
- direct Role assignments;
- Group memberships and Group Role assignments;
- Role-assignment context;
- applicable Role-owned PermissionSets, their effects, and owned Permissions;
- Tenant Stewardship;
- TenantManagementGroup delegation and contextual scope;
- operation-specific invariants.

The final input model remains to be designed.

## 5. Permission Resolution

An Identity may have multiple direct Roles and multiple Group-derived Roles in the session Tenant. Groups may themselves have multiple Roles. Roles have no evaluation precedence.

A Role owns an ordered list of PermissionSets. Each PermissionSet carries one `ALLOW` or `DENY` effect and owns an ordered list of Permissions. Ordering does not establish authorization precedence.

A Permission is an Action matcher. Its UUID identifies the owned Permission instance; its Permission URN expresses matching semantics. The Permission itself has no effect; it inherits the effect of its containing PermissionSet.

Actions are shared exact definitions uniquely identified by Action URNs. Action URNs never contain wildcards.

The canonical Action grammar is:

```text
<resource>:<verb>-<qualifier>
```

A Permission uses an exact resource and verb. Its qualifier is either exact or the complete wildcard `*`.

For example:

```text
principal:set-alias
principal:set-*
```

Resolution rules are:

1. discard Roles and PermissionSets that do not apply to the session Tenant and current assignment/context;
2. collect Permissions matching the requested Action;
3. select the most-specific matching Permission or Permissions;
4. exact qualifier match is more specific than wildcard qualifier match;
5. derive each matching Permission's effect from its containing PermissionSet;
6. if equally specific matching Permissions have conflicting effects, `DENY` wins;
7. if no applicable Permission matches, `DENY`.

Example:

```text
PermissionSet(ALLOW): principal:set-*
PermissionSet(DENY):  principal:set-alias
```

For `principal:set-alias`, the exact DENY wins.

Conversely:

```text
PermissionSet(DENY):  principal:set-*
PermissionSet(ALLOW): principal:set-alias
```

For `principal:set-alias`, the exact ALLOW wins.

---

## 6. Additional Authorization Constraints

A matching ALLOW rule is not necessarily sufficient for final authorization.

The Authorizer must also enforce the security-model constraints applicable to the operation, including:

- Tenant and Organization boundaries;
- membership requirements;
- active/deleted state;
- assignment context;
- strict scope dominance where required;
- Tenant Stewardship as a narrowly defined alternate dominance mechanism;
- TenantManagementGroup delegation and contextual ROOT/SYSTEM scope;
- operation-specific invariants.

Scope and Permission are independent.

### 6.1 Application extension mutation

For `<resource>:update-extension`, Permission matching alone is insufficient.

When the target belongs to an ordinary Tenant, the Authorizer must establish that the applicable authorization originates from a TENANT-defined application Role belonging to that same Tenant. A SYSTEM-defined MTMF Role MUST NOT authorize that Tenant actor's extension mutation merely because one of its Permissions matches the Action.

Normal Tenant-boundary and scope/dominance evaluation then applies independently. This prevents application policy from a lesser-scoped or unrelated Tenant from modifying extension data outside its authorized Tenant context.

## 7. TenantManagementGroup Context

TenantManagementGroup elevation is contextual.

The ROOT TenantManagementGroup implicitly manages all Tenants and may provide contextual ROOT scope according to the security model.

SYSTEM TenantManagementGroups manage only explicitly associated Tenants and may provide contextual SYSTEM scope only for operations against those Tenants.

The management group's Role still constrains which Actions may be authorized. Management-group membership never means unrestricted administration.

Manager-side actor eligibility remains unresolved and MUST fail closed until specified.

## 8. Implementation Boundary

The permission-matching computation SHOULD remain separable from authorization-context retrieval.

A likely internal shape is:

```text
Authorizer
  +-- load/validate authorization context
  +-- PermissionEvaluator (PermissionSet/Permission matching)
  +-- apply scope/delegation/stewardship/operation constraints
  +-- produce decision
```

The initial PermissionEvaluator should be implemented in Python.

The evaluator should be deterministic and side-effect-free so that it can be optimized independently. If profiling later demonstrates that permission evaluation is CPU-bound and material to system performance, a Rust implementation may be introduced behind the same internal boundary, for example through PyO3/maturin. Rust is an optimization option, not a current requirement.

Caching/indexing of effective authorization state may prove more important than the matching algorithm itself and will be designed only after realistic profiling.

## 9. Decision and Auditability

The internal authorization result should contain enough information to support testing, audit, diagnostics, and observability rather than exposing only an unexplained Boolean.

The exact decision type and disclosure policy remain to be specified. External error responses MUST NOT reveal security-sensitive information merely because richer reasoning exists internally.

## 10. Open Design Items

The following remain intentionally unresolved:

- exact `Authorizer` and `PermissionEvaluator` Python interfaces;
- exact authorization-context representation;
- manager-side actor eligibility for TenantManagementGroups;
- complete Action catalog and built-in Role policy compositions;
- built-in Role-to-PermissionSet/Permission mappings;
- caching, invalidation, and compiled permission-index design;
- exact audit decision record;
- Rust implementation threshold and benchmarking criteria.
