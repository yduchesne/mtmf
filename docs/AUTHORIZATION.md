# MTMF Authorization

## 1. Purpose

This document describes the authorization-evaluation architecture implemented by `mtmf-core`.

It is subordinate to [SECURITY_MODEL.md](SECURITY_MODEL.md). The security model defines normative security semantics; this document explains how the `Authorizer` is expected to apply them. If the documents conflict, `SECURITY_MODEL.md` takes precedence.

This document is intentionally shallow while the security model is still evolving.

## 2. Authorizer

`Authorizer` is the authoritative permission-evaluation engine inside `mtmf-core`.

Its fundamental question is:

> May this specific acting Identity perform this exact Action against this target in this authorization context?

Callers request an **Action**, not a Permission. The caller MUST NOT reconstruct MTMF authorization by selecting a Permission itself.

The Authorizer evaluates policy; it does not perform the protected business operation.

## 3. Default Deny

Authorization is deny-by-default.

The Authorizer MUST positively establish authorization before a protected operation proceeds. Missing roles, unknown Actions, absent or inconsistent membership/context, unresolved scope, invalid delegation, or other insufficient policy state MUST NOT fall through to ALLOW.

An infrastructure failure while evaluating policy is not itself a policy DENY, but the protected operation MUST fail closed.

## 4. Inputs

An authorization decision may require:

- acting Identity and its Principal;
- requested exact Action;
- target resource and security scope;
- Tenant and Organization context;
- active/deleted state;
- direct Role assignments;
- Group memberships and Group Role assignments;
- Role-assignment context;
- applicable Permission rules and their effects;
- Tenant Stewardship;
- TenantManagementGroup delegation and contextual scope;
- operation-specific invariants.

The final input model remains to be designed.

## 5. Permission Resolution

An Identity may have multiple direct Roles and multiple Group-derived Roles. Groups may themselves have multiple Roles. Roles have no evaluation precedence.

For a requested Action, the Authorizer considers all applicable Permission rules from all effective Roles.

The canonical Action grammar is:

```text
<resource>:<verb>-<qualifier>
```

A Permission rule uses an exact resource and verb. Its qualifier is either exact or the complete wildcard `*`.

For example:

```text
principal:set-alias
principal:set-*
```

The first rule is more specific than the second for Action `principal:set-alias`.

Resolution rules are:

1. discard rules that do not apply to the current assignment/context;
2. find rules matching the requested Action;
3. select the most-specific matching rule or rules;
4. exact qualifier match is more specific than wildcard qualifier match;
5. if equally specific matching rules have conflicting effects, DENY wins;
6. if no applicable rule matches, DENY.

Example:

```text
principal:set-*       ALLOW
principal:set-alias   DENY
```

For `principal:set-alias`, the exact DENY wins.

Conversely:

```text
principal:set-*       DENY
principal:set-alias   ALLOW
```

For `principal:set-alias`, the exact ALLOW wins.

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
  +-- PermissionEvaluator
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
- complete Action and Permission catalogs;
- built-in Role-to-Permission mappings;
- caching, invalidation, and compiled permission-index design;
- exact audit decision record;
- Rust implementation threshold and benchmarking criteria.
