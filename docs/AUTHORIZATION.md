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

Python remains authoritative for authorization-context retrieval and orchestration: session validation, Tenant isolation, context validation, scope/dominance, stewardship/delegation, operation-specific constraints, and fail-closed orchestration all stay in Python, and the `Authorizer` remains the authoritative decision orchestrator.

### 8.1 Rust permission-policy kernel

Since PR 8A, MTMF intentionally includes a Rust permission engine as a Rust/Python integration showcase and as a deterministic native policy kernel (see `ROADMAP_V01.md`, PR 8 series). This is an architecture decision; no profiling evidence claims a performance bottleneck, and performance characterization is useful but not the sole reason for Rust.

The integration mechanism is PyO3/maturin. The native module is the private `_mtmf_permission_engine`, reached only through the internal Python adapter `mtmf_core.authorization.rust_engine`; it is never exposed through `mtmf-api`, Connectors, HTTP, or any public contract.

Boundary rules:

- Rust evaluates policy only; Python determines policy applicability and authorization context.
- Rust's future input is an exact Action plus the already-applicable PermissionSets (no Role is required by the native engine). Python flattens domain state to detached primitive values:

```text
ActionInput
    action_urn: str

PermissionSetInput
    effect: ALLOW | DENY
    permissions:
        PermissionInput
            permission_urn: str
```

- No live Python domain objects (`Action`, `Role`, `PermissionSet`, `Permission`) cross the FFI boundary, and no JSON serialization is introduced to carry policy across PyO3.
- Rust performs no retrieval and no I/O: no PostgreSQL, `MtmfSpi`, UnitOfWork, repositories, membership/session/assignment state, stewardship, delegation, IdP, network service, or filesystem-based policy discovery.

The Python `PermissionEvaluator` remains the semantic reference implementation throughout the Rust migration series. Differential testing against the Python reference precedes any evaluator cutover; Python/Rust integration will sit behind an internal abstraction that fails closed on native errors.

Implemented so far in the Rust series:

- PR 8A: only a deterministic smoke/capability API (`engine_version`) exists; no permission semantics are implemented in Rust, and no active authorization path imports the native module.
- PR 8B: a detached native policy model (`ActionInput`, `PermissionInput`, `PermissionSetInput`, `PermissionEffect` with exactly ALLOW/DENY) exists as the structural input contract for future evaluation; the SYSTEM-only Action/Permission URN parsers exist; exact and complete-qualifier wildcard (`*`) single-Permission matching exists; and match specificity exists with exactly two classes (`EXACT` is more specific than the qualifier wildcard, and nothing else is). A small private primitive matcher bridge (`_mtmf_permission_engine.match_permission`) exposes the match facts (`"exact"`, `"qualifier-wildcard"`, or `None` for a valid non-match) through the internal `rust_engine` adapter, and focused Python/Rust parity tests prove agreement with the Python matcher.

Not implemented: there is still no Rust evaluator, no ALLOW/DENY resolution, no default DENY, no cross-Permission specificity selection, no Role input to Rust, and no conversion of Python domain objects to native inputs. Manifestly invalid URN text raises `ValueError` at the native boundary; a valid non-match is a `None`/`NO_MATCH` fact, so malformed input can never silently become a valid non-match or any authorization decision. PR 8B makes no authorization decision of any kind, and no active authorization path imports the native module.

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
- exact audit decision record;
- caching, invalidation, and compiled permission-index design.
