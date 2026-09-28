# MTMF Security Model

## 1. Status and Purpose

This document is the security constitution for the Multi-Tenant Management Framework (MTMF).

It defines the normative security model that MTMF implementations MUST preserve. It is intended to be read by both humans and coding agents. Security-sensitive implementation decisions MUST conform to this document. Where implementation convenience conflicts with an invariant in this document, the invariant takes precedence.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

This document describes the security model, not persistence layout or API shape. A database schema, Python type, repository interface, or UI representation MUST NOT weaken these semantics.

---

## 2. Core Concepts

MTMF uses the following distinct concepts:

- **Principal** — the underlying account or actor represented by MTMF.
- **Identity** — a concrete identity associated with a Principal. Authentication and authorization operate on the specific acting Identity.
- **Tenant** — the primary tenancy/security boundary.
- **Organization** — a subdivision of a Tenant.
- **Group** — a tenant-bound collection of Identities, represented through GroupMembership.
- **TenantMembership** — explicit membership of a Principal, Identity, or Group in a Tenant, as applicable to the domain model.
- **OrgMembership** — explicit membership of an Identity or Group in an Organization.
- **GroupMembership** — explicit association of an Identity with a Group.
- **Role** — a uniquely identified set of Permission rules.
- **Action** — an exact operation requested against a resource, expressed using the MTMF action grammar.
- **Permission** — a uniquely identified authorization rule that matches one or more Actions and has an `ALLOW` or `DENY` effect.
- **Permission Evaluation Rule** — the matching semantics encoded by a Permission, including exact-action and constrained wildcard matching.
- **Role Assignment** — an assignment of a Role to an Identity or Group in an applicable authorization context.
- **Ownership** — immutable creator provenance recorded as the Identity that created an object.
- **Scope** — the privilege/protection hierarchy used for security dominance.
- **Tenant Stewardship** — tenant-specific ultimate administrative authority used to resolve selected same-scope administrative operations.
- **Definition Namespace** — whether a Role or Permission is defined by MTMF globally or by a particular Tenant.
- **Assignment Context** — the system, Tenant, or Organization context in which a Role grant applies.

These concepts MUST remain distinct. In particular:

1. Ownership is not authorization.
2. Stewardship is not a Role.
3. Scope is not a Role/Permission definition namespace.
4. A Principal is not interchangeable with one of its Identities.
5. Membership is not implicit merely because another authorization relationship exists, except for the explicitly defined ROOT TenantManagementGroup universal managed-Tenant relationship.
6. An Action is not a Permission: callers request Actions; Permissions are rules used to decide whether those Actions are authorized.

---

## 3. Security Scope

MTMF defines exactly four security scopes:

```text
ROOT         = 0
SYSTEM       = 1
TENANT       = 2
ORGANIZATION = 3
```

A smaller numeric value represents a broader and more privileged scope.

The numeric ordering exists to support privilege/protection comparisons. It MUST NOT be used to infer authorization rules that are not explicitly defined by this security model.

### 3.1 Strict scope dominance

For operations classified as destructive or security-sensitive, ordinary scope dominance requires:

```text
subject.scope < target.scope
```

The comparison is strictly less-than, never less-than-or-equal.

Consequences include:

| Subject | May strictly dominate |
| --- | --- |
| ROOT | SYSTEM, TENANT, ORGANIZATION |
| SYSTEM | TENANT, ORGANIZATION |
| TENANT | ORGANIZATION |
| ORGANIZATION | none |

Therefore, ordinary scope dominance deliberately prevents:

- same-scope self-administration;
- same-scope peer administration;
- same-scope privilege escalation.

Possession of a Permission does not override this rule.

### 3.2 Permission and dominance are independent

For an operation requiring strict scope dominance, authorization requires both:

1. the required Permission; and
2. the required dominance relationship.

Conceptually:

```text
authorized =
    permission_granted
    AND
    (
        strict_scope_dominance
        OR explicitly_permitted_alternate_dominance
    )
```

Tenant Stewardship is one such narrowly defined alternate dominance mechanism. It is not a general bypass.

Not every operation necessarily requires scope dominance. Read and ordinary non-security-sensitive operations MAY use different authorization rules. Each security-sensitive operation MUST define its required authorization semantics explicitly.

---

## 4. Principals and Identities

### 4.1 Principal identity requirements

Every Principal MUST have at least one Identity.

Every Principal MUST have exactly one mandatory MTMF-local, non-federated Identity.

A Principal MAY additionally have zero or more federated Identities.

A federated Identity MUST NOT replace the mandatory local Identity.

Conceptually:

```text
Principal
  +-- local MTMF Identity       (mandatory)
  +-- federated Identity        (optional)
  +-- federated Identity        (optional)
```

### 4.2 Identity-specific authorization

Authorization is evaluated for the specific acting Identity.

Permissions, Roles, Group memberships, or other authorization state obtained by one Identity MUST NOT automatically transfer to another Identity merely because both Identities belong to the same Principal.

MTMF MUST NOT implicitly union authorization across all Identities of a Principal.

For example, if one Identity is directly assigned an administrative Role and another Identity of the same Principal is not, the second Identity does not inherit that Role.

The Principal relationship establishes that multiple Identities represent the same underlying Principal; it does not collapse their authorization contexts.

---

## 5. Bootstrap and Root Invariants

Initial system creation MUST establish:

1. exactly one initial user Principal designated as the **root Principal**;
2. exactly one initial Tenant designated as the **root Tenant**;
3. the root Principal has `ROOT` scope;
4. the root Tenant has `ROOT` scope;
5. the root Tenant is the only Tenant with `ROOT` scope;
6. the root Principal is the only Principal with `ROOT` scope;
7. the root Principal is a member of the root Tenant;
8. the root Principal's membership in the root Tenant has `ROOT` scope;
9. the root Principal is the initial creator/owner of the root Tenant;
10. the root Principal's root-Tenant membership is immutable and MUST NOT be deleted.

All non-root Tenants have `TENANT` scope.

Non-root Principals MAY be members of the root Tenant. Such membership uses `SYSTEM` scope, not `ROOT` scope. This is the mechanism for delegated system administration.

No other root-Principal lifecycle restrictions are implied unless explicitly specified by this constitution.

---

## 6. Ownership

Every MTMF object that has ownership MUST record its creator Identity as its owner.

Ownership is immutable.

Conceptually:

```text
object.owner_identity_id = identity_that_created_object.id
```

Ownership means **who created this object**. It does not mean **who currently administers this object**.

Consequently:

- ownership MUST NOT change when administrative responsibility changes;
- ownership MUST NOT be used as a substitute for Roles, Permissions, Scope, membership, or Stewardship;
- transfer of Tenant Stewardship MUST NOT change Tenant ownership;
- authorization MUST NOT infer unrestricted administrative authority merely from ownership unless a specific operation explicitly defines such a rule.

Because ownership is immutable creator provenance, implementations MUST preserve referenced identity provenance. Identity lifecycle handling MUST NOT destroy the ability to identify an object's owner.

---

## 7. Tenant Membership

Membership in a Tenant is explicit.

A tenant-bound Identity or Group MUST NOT exist as a standalone entity outside its Tenant. It MUST have the applicable TenantMembership establishing the Tenant to which it belongs.

Every Principal belonging to a Tenant automatically has Tenant membership. Every Identity belonging to that Principal is tenant-bound to that same Tenant and MUST have the required TenantMembership semantics.

Groups are tenant-bound and MUST have TenantMembership.

An implementation MAY choose an appropriate persistence representation for different member kinds, but it MUST preserve the domain semantics described here.

### 7.1 Tenant boundary invariant

An Identity or Group associated with Tenant A MUST NOT be treated as a member of Tenant B without an explicitly valid membership relationship permitted by the domain model.

Tenant-bound authorization objects MUST NOT cross Tenant boundaries.

---

## 8. Groups and Group Membership

Groups have `TENANT` security scope.

A Group is a group of **Identities**, not Principals.

A Group MUST NOT directly embed or contain Identities. The association MUST be represented through **GroupMembership**.

Conceptually:

```text
Identity --> GroupMembership --> Group
```

GroupMembership is therefore the authoritative relationship between an Identity and a Group.

The distinction between Principal and Identity is security-significant. If a Principal has multiple Identities, those Identities MAY have different Group memberships.

An Identity's membership in a Group MUST NOT imply that another Identity of the same Principal is a member of that Group.

### 8.1 Group tenant integrity

A GroupMembership MUST remain within one Tenant boundary.

The Group and member Identity MUST belong to the same Tenant. A cross-Tenant GroupMembership MUST be rejected.

---

## 9. Organizations and Organization Membership

Organizations exist within Tenants.

Organization membership is explicit and is represented through **OrgMembership**.

Identities and Groups MAY have OrgMembership.

Conceptually:

```text
Identity --> OrgMembership --> Organization
Group    --> OrgMembership --> Organization
```

### 9.1 Tenant membership prerequisite

Organization membership is a refinement of Tenant membership, not an independent route into a Tenant.

If Organization O belongs to Tenant T:

```text
OrgMembership(member, O)
    implies TenantMembership(member, T)
```

An Identity or Group MUST NOT receive OrgMembership in an Organization unless it already has valid Tenant membership in the Organization's containing Tenant.

Cross-Tenant OrgMembership MUST be rejected.

### 9.2 Organization owner membership

The Identity that creates and owns an Organization MUST automatically become a member of that Organization.

Organization creation MUST atomically establish both:

1. the Organization with the creator Identity as immutable owner; and
2. the owner's OrgMembership in that Organization.

The operation MUST NOT leave an Organization whose owner lacks the required OrgMembership.

---

## 10. Tenant Stewardship

Stewardship is exclusively a Tenant-level concept.

MTMF MUST NOT define Organization Stewardship or `OrgStewardship`.

Tenant Stewardship answers:

> Which Principal has ultimate administrative authority over this Tenant when ordinary scope comparison cannot distinguish same-scope tenant administrators?

Stewardship is distinct from ownership, Role, Permission, and Scope.

The stewardship state is:

```python
class TenantStewardship(IntEnum):
    NONE = 0
    ACTIVE = 1
```

Root versus ordinary stewardship MUST NOT be encoded as additional stewardship enum values. Root status is derived from the Tenant/membership security scope.

Stewardship belongs semantically to TenantMembership.

### 10.1 Ordinary Tenant stewardship invariants

Every active ordinary Tenant MUST have exactly one ACTIVE steward.

The ACTIVE steward of an ordinary Tenant MUST:

1. be an active Principal;
2. be a member of that Tenant;
3. have `TENANT` scope in the applicable membership context;
4. hold the built-in Tenant Administrator Role.

An active ordinary Tenant MUST never be left without a valid ACTIVE steward.

### 10.2 Root Tenant stewardship

The root Principal is the steward of the root Tenant.

Root Tenant stewardship:

- is ACTIVE;
- cannot be transferred;
- remains associated with the immutable root-Principal/root-Tenant membership;
- uses `ROOT` scope rather than `TENANT` scope.

### 10.3 Stewardship dominance

Stewardship provides a narrow alternate dominance relationship for explicitly selected Tenant-security operations where strict scope dominance fails because both parties have `TENANT` scope.

The steward MUST still possess the Permission required for the operation.

Stewardship MUST NOT act as a blanket Permission bypass.

A delegated Tenant Administrator who is not the steward MUST NOT gain stewardship merely by holding the Tenant Administrator Role.

Same-scope delegated administrators MUST NOT automatically gain authority over the steward or over peers merely because they share an administrative Role.

### 10.4 Stewardship transfer

Normal succession occurs through explicit transfer by the current steward to another eligible Tenant Principal.

The new steward MUST satisfy all ordinary Tenant steward prerequisites.

A delegate MUST NOT self-promote to steward.

An appropriately authorized `SYSTEM` administrator MAY perform recovery transfer for an ordinary Tenant because SYSTEM strictly dominates TENANT.

Stewardship transfer MUST be explicit, auditable, and atomic with respect to the invariant that an active ordinary Tenant has exactly one valid ACTIVE steward.

If the current steward is to be deactivated or otherwise made ineligible, stewardship MUST first be transferred, or the operation MUST atomically establish a new valid steward.

Stewardship transfer MUST NOT change immutable ownership.

### 10.5 Acting Identity and stewardship

Stewardship is associated with Tenant membership at the Principal level, while authorization is evaluated for a specific acting Identity.

MTMF MUST NOT silently grant stewardship-derived authority to every Identity of the steward Principal.

The exact mechanism by which an Identity of the steward Principal is authorized to exercise stewardship authority remains to be specified. Until specified, implementations MUST NOT infer cross-Identity stewardship privileges.

---

## 11. Roles, Actions, and Permissions

A Role is fundamentally a uniquely identified set of Permission rules.

An Action describes the exact operation an actor is attempting. A Permission is an authorization rule that may match an Action and carries an `ALLOW` or `DENY` effect.

Roles and Permissions have stable identity independent of their presentation metadata:

- a Role URN is immutable and unique;
- a Permission URN is immutable and unique;
- Role and Permission `name` and `description` fields are mutable;
- names and descriptions MUST NOT participate in authorization identity or matching.

An Identity MAY have multiple directly assigned Roles and MAY derive additional Roles from multiple Groups. A Group MAY have multiple assigned Roles. Roles MUST NOT have precedence merely because of assignment order or source.

Roles are assignable to:

- Identities;
- Groups.

Roles are not assigned to Principals merely because the Principal owns one or more Identities.

### 11.1 Effective Roles

For a specific Identity:

```text
effective_roles(identity)
    =
    directly_assigned_roles(identity)
    union
    roles_assigned_to_groups(identity belongs to)
```

### 11.2 Effective Permission rules

For a specific acting Identity, the Authorizer evaluates all applicable Permission rules from all effective Roles. Permission resolution is not a simple union of grants.

For the requested Action:

1. all applicable matching Permission rules are considered;
2. the most-specific matching rule wins;
3. an exact action match is more specific than a wildcard-qualifier match;
4. if multiple rules of equal specificity conflict, `DENY` wins;
5. if no applicable rule matches, the decision is `DENY`.

Roles themselves have no precedence.

Effective authorization MUST additionally respect assignment context, Tenant/Organization membership, scope/dominance requirements, TenantManagementGroup delegation, stewardship rules, and operation-specific constraints.

---

## 12. Role Assignment Context

Role definition and Role assignment context are distinct.

A globally defined Role can be assigned in a Tenant or Organization context without changing the Role definition's ownership/namespace.

For example, the built-in Tenant Administrator Role is globally defined by MTMF but may be assigned to an Identity or Group in the context of a particular Tenant.

A tenant-defined Role MAY be assigned in an Organization context belonging to that same Tenant.

Assignments MUST NOT cause Roles, Permissions, or authorization to cross Tenant boundaries.

The exact storage representation of assignment context is not prescribed by this document.

---

## 13. Role and Permission Definition Namespaces

Roles and Permissions do **not** have security `Scope`.

Instead, they have definition ownership/namespace semantics:

```text
SYSTEM
TENANT
```

This distinction describes where a Role or Permission is defined and where it may be referenced. It does not grant security authority.

### 13.1 SYSTEM definitions

SYSTEM Roles and Permissions are defined by MTMF and are globally available for valid assignments.

A SYSTEM Role or Permission:

- MUST NOT have a `tenant_id`;
- MUST use the `:system:` URN namespace.

### 13.2 TENANT definitions

A Tenant MAY define custom Roles and custom Permissions.

A TENANT Role or Permission:

- MUST have a `tenant_id`;
- MUST use the `:tenant:<tenant-id>:` URN namespace;
- MUST be usable only within that Tenant and its Organizations.

Tenant-defined Permissions MAY represent application-specific capabilities. MTMF stores and evaluates them but does not need to understand their application business semantics.

For example, an application may define:

```text
urn:mtmf:iam:permissions:tenant:1234:investigation:approve
```

MTMF can evaluate whether an Identity has that Permission without interpreting what approval of an investigation means.

### 13.3 Organization definitions

Organizations do not currently define their own Roles or Permissions.

Tenant-defined Roles can instead be assigned in an Organization context within their defining Tenant.

---

## 14. URN Conventions and Integrity

MTMF IAM URNs use colon-separated components. Period-separated resource/operation forms MUST NOT be used.

### 14.1 SYSTEM Role URNs

```text
urn:mtmf:iam:roles:system:<role-name>
```

Example:

```text
urn:mtmf:iam:roles:system:tenant-admin
```

### 14.2 TENANT Role URNs

```text
urn:mtmf:iam:roles:tenant:<tenant-id>:<role-name>
```

Example:

```text
urn:mtmf:iam:roles:tenant:1234:security-analyst
```

### 14.3 SYSTEM Permission URNs

```text
urn:mtmf:iam:permissions:system:<resource>:<operation>
```

Examples:

```text
urn:mtmf:iam:permissions:system:principal:read
urn:mtmf:iam:permissions:system:principal:deactivate
urn:mtmf:iam:permissions:system:role:assign
urn:mtmf:iam:permissions:system:tenant:transfer-stewardship
```

### 14.4 TENANT Permission URNs

```text
urn:mtmf:iam:permissions:tenant:<tenant-id>:<resource>:<operation>
```

Example:

```text
urn:mtmf:iam:permissions:tenant:1234:investigation:approve
```

### 14.5 URN/structural consistency invariant

Whenever a URN encodes security-relevant ownership or namespace information that is also represented structurally, both representations MUST agree.

For a Tenant Role or Permission, the Tenant ID encoded in the URN MUST equal the object's structural `tenant_id`.

For example:

```text
tenant_id = 1234
urn = urn:mtmf:iam:roles:tenant:4567:security-analyst
```

is invalid and MUST be rejected.

The following tuples illustrate the invariant:

```text
(SYSTEM, tenant_id=NULL,
 urn:mtmf:iam:roles:system:tenant-admin)
    VALID

(TENANT, tenant_id=1234,
 urn:mtmf:iam:roles:tenant:1234:security-analyst)
    VALID

(SYSTEM, tenant_id=1234,
 urn:mtmf:iam:roles:system:tenant-admin)
    INVALID

(TENANT, tenant_id=NULL,
 urn:mtmf:iam:roles:tenant:1234:security-analyst)
    INVALID

(TENANT, tenant_id=1234,
 urn:mtmf:iam:roles:tenant:4567:security-analyst)
    INVALID
```

URN strings MUST NOT be trusted as the sole source of Tenant ownership.

This consistency MUST eventually be enforced at trusted persistence/write boundaries in addition to higher-level validation.

---

## 15. Actions and Permission-Rule Grammar

MTMF Actions MUST use the canonical form:

```text
<resource>:<verb>-<qualifier>
```

The verb is mandatory and literal. MTMF does not impose a finite vocabulary of verbs, but the verb MUST NOT be wildcarded.

A Permission rule MUST specify an exact resource and exact verb. The complete qualifier MAY be replaced by `*`. No other wildcard form is valid. In particular, wildcard resources, wildcard verbs, partial qualifier globs, arbitrary glob syntax, and regular expressions MUST NOT be used.

Examples:

```text
principal:set-alias     # exact
principal:set-*         # valid wildcard rule

principal:*-alias       # invalid
principal:*             # invalid
*:set-alias             # invalid
principal:set-a*        # invalid
```

Thus `principal:set-*` can match `principal:set-alias` and `principal:set-active`, but cannot match `principal:delete-object`.

### 15.1 Baseline object actions

Where applicable, MTMF-managed objects including Tenants, Organizations, Principals, Roles, and Permissions support the baseline CRUD actions:

```text
<resource>:create-object
<resource>:get-object
<resource>:update-object
<resource>:delete-object
```

Deletion is soft deletion. An object's immutable identifier and security/audit provenance MUST survive logical deletion.

Security-sensitive operations with distinct semantics MUST use distinct Actions rather than being silently implied by `update-object` or another broad CRUD Action.

Where activation state is relevant, MTMF uses explicit state Actions such as:

```text
principal:set-active
principal:set-inactive
tenant:set-active
tenant:set-inactive
```

Active/inactive state is distinct from soft-deleted state. `set-active` MUST NOT implicitly restore a soft-deleted object. If restoration is supported, it requires a distinct Action such as `restore-object`.

### 15.2 Permission granularity

Permission rules use the resource/action components defined above. The URN wraps these components using the applicable definition namespace.

Permissions SHOULD represent the smallest meaningful security-relevant operation when that operation has distinct authorization, dominance, stewardship, audit, or lifecycle semantics.

Examples include:

```text
principal:create-object
principal:get-object
principal:update-object
principal:delete-object
principal:set-active
principal:set-inactive

role:create-object
role:get-object
role:update-object
role:delete-object

tenant:create-object
tenant:get-object
tenant:update-object
tenant:delete-object
tenant:set-active
tenant:set-inactive
tenant:transfer-stewardship
```

Granular semantic operations are preferred over overly broad CRUD permissions where semantics differ. For example:

- `set-inactive` is distinct from `delete-object`;
- an approval Action is distinct from `update-object`;
- Role assignment is distinct from generic Role modification.

Permission rules SHOULD remain narrowly scoped. Generic CRUD Actions MUST NOT silently imply security-sensitive Actions.

Roles compose the atomic Permissions required for a persona.

---

## 16. Built-In Roles

The initial MTMF built-in Role catalog consists of the following eleven roles.

| Role | Intended purpose |
| --- | --- |
| Tenant Administrator | Broad Tenant administration, including Organizations, Groups, Identities, memberships, and ordinary IAM administration |
| Tenant Reader | Read-only visibility across a Tenant |
| Tenant Contributor | Manage ordinary Tenant resources without security/IAM administration |
| Tenant Security Administrator | Manage Identities, Groups, memberships, Roles, Role assignments, and other Tenant IAM/security configuration |
| Organization Administrator | Broad administration of one Organization |
| Organization Reader | Read-only access within one Organization |
| Organization Contributor | Manage ordinary Organization resources without IAM/security administration |
| Organization Security Administrator | Manage Organization memberships and Organization-level authorization |
| System Administrator | System-wide administration below ROOT, subject to scope and operation-specific rules |
| System Reader | System-wide read-only visibility |
| System Security Administrator | System-wide IAM/security administration below ROOT |

These built-in Roles are SYSTEM-defined Role definitions. Their names do not imply that the Role definition itself carries TENANT or ORGANIZATION security scope.

Potential future roles such as User Administrator or Auditor roles are not part of the initial catalog unless added explicitly to this constitution.

### 16.1 No stewardship role

MTMF MUST NOT define a Tenant Owner or Tenant Steward Role as a substitute for stewardship.

An ordinary Tenant steward is characterized by the required Tenant membership, ACTIVE stewardship state, and required Tenant Administrator Role.

A delegated Tenant Administrator can hold the same Tenant Administrator Role while having stewardship `NONE`.

---

## 17. Delegated Tenant Administration Through Groups

Groups can be used to delegate Tenant administration.

A Tenant administration Group:

1. belongs to its Tenant through TenantMembership;
2. contains Identities through GroupMembership;
3. receives the applicable Tenant Administrator Role through a Role assignment.

An Identity in that Group derives the Role through GroupMembership.

Group-derived Tenant administration MUST NOT grant Tenant Stewardship. Stewardship remains separately and explicitly assigned according to the stewardship invariants.

---

## 18. Security-Sensitive Operations

Operations with distinct security consequences SHOULD have explicit Permissions and explicit authorization rules.

Examples include:

- Role assignment and unassignment;
- security-sensitive membership changes;
- Principal activation/deactivation;
- Identity addition/removal;
- scope-changing operations;
- Tenant Stewardship transfer.

For such operations, implementations MUST NOT rely solely on generic CRUD authorization.

Where strict scope dominance is required, same-scope self-action and peer-action MUST fail unless an explicitly defined alternate dominance rule applies.

This prevents an Identity from self-escalating merely because it possesses a Permission such as Role assignment.

---

## 19. Resource Identity, Names, and Lifecycle

Tenants, Organizations, and Groups use immutable, globally unique UUID identifiers. Their names are mutable and non-unique.

An object's UUID establishes identity. A mutable name is presentation metadata and MUST NOT be used as a foreign key, authorization identity, ownership reference, membership identity, or security boundary.

Name lookup MUST NOT be assumed to return a unique object.

Roles and Permissions use their immutable, unique URNs as their stable authorization identity. Their names and descriptions are mutable presentation metadata.

Soft deletion MUST preserve stable identity and security/audit references.

---

## 20. Tenant Management Groups

A `TenantManagementGroup` represents explicit delegated cross-Tenant administration. It is distinct from an IAM Group.

A TenantManagementGroup has:

- one manager Tenant;
- zero or more managed Tenants according to the membership rules below;
- one Role defining the delegated tenant-management Permission rules;
- a security scope of either `ROOT` for the bootstrap root management group or `SYSTEM` for delegated management groups.

The Role determines **what** operations may be performed. Management-group scope and managed-Tenant membership determine **where** that authority may be exercised. Scope and Permission remain independent.

A manager Tenant MUST NOT acquire intrinsic global SYSTEM or ROOT scope merely because it manages another Tenant. Elevated scope is contextual and applies only while authorizing operations against Tenants managed through the applicable TenantManagementGroup.

### 20.1 ROOT TenantManagementGroup

System bootstrap MUST create exactly one ROOT TenantManagementGroup.

It MUST:

1. be managed by the root Tenant;
2. have `ROOT` scope;
3. implicitly manage every Tenant, including Tenants created after bootstrap;
4. use implicit universal managed-Tenant membership rather than materialized TenantManagementGroupMembership rows.

A ROOT TenantManagementGroup MUST NOT require or contain explicit managed-Tenant membership rows.

The implicit-universal membership behavior is a root invariant and MUST NOT be configurable for ordinary management groups.

### 20.2 SYSTEM TenantManagementGroups

A non-root TenantManagementGroup has `SYSTEM` scope and MUST use explicit managed-Tenant memberships.

When an eligible actor of its manager Tenant performs an operation against an explicitly managed Tenant, the management relationship MAY provide contextual SYSTEM scope. That contextual elevation MUST NOT apply to any Tenant outside the management group's explicit membership.

Membership in a TenantManagementGroup does not by itself grant an Action. The applicable management Role must also produce an authorization result permitting the requested Action, and all other required invariants must hold.

The exact rule identifying which manager-Tenant Identities or Groups are eligible to exercise a TenantManagementGroup's delegated Role remains unresolved and MUST NOT be inferred permissively.

---

## 21. Cross-Tenant Isolation

Tenant isolation is a fundamental invariant.

MTMF MUST reject security relationships that improperly cross Tenant boundaries, including at minimum:

- GroupMembership between a Group and Identity from different Tenants;
- OrgMembership involving a member outside the Organization's containing Tenant;
- assignment or use of a Tenant-defined Role outside its defining Tenant;
- assignment or use of a Tenant-defined Permission outside its defining Tenant;
- mismatches between structural Tenant IDs and Tenant IDs encoded in URNs.

A caller-supplied URN, identifier, Role assignment, membership identifier, or other reference MUST NOT be sufficient to bypass structural Tenant validation.

---

## 22. Authorization Evaluation Principles

An authorization decision MAY require multiple independent inputs. Implementations MUST NOT collapse them into a single undifferentiated "is admin" flag.

Depending on the operation, evaluation may include:

1. the specific acting Identity;
2. its Principal;
3. active status;
4. Tenant membership;
5. Organization membership;
6. direct Role assignments;
7. Group memberships;
8. Group Role assignments;
9. assignment context;
10. effective Permissions;
11. subject security scope;
12. target security scope;
13. strict scope dominance;
14. Tenant Stewardship, where explicitly applicable;
15. TenantManagementGroup delegation and contextual scope, where applicable;
16. requested Action and matching Permission rules;
17. rule specificity and DENY precedence;
18. operation-specific invariants.

Authorization MUST be deny-by-default. An operation MUST NOT proceed unless authorization can be positively established. Missing, unknown, inconsistent, invalid, or insufficient authorization context MUST NOT result in an allow decision. Operational inability to evaluate authorization is not semantically equivalent to a policy DENY, but the protected operation MUST still fail closed.

---

## 23. Invariant Enforcement

Security invariants are not merely UI rules.

They MUST be enforced at trusted domain/service and persistence boundaries appropriate to the implementation.

Client-side validation MAY improve usability but MUST NOT be the sole enforcement mechanism.

In particular, implementations MUST independently validate security-critical consistency such as:

- Tenant boundaries;
- membership prerequisites;
- URN/structural Tenant consistency;
- root invariants;
- stewardship uniqueness and eligibility;
- ownership immutability;
- authorization of security-sensitive operations.

Operations that establish multiple required invariants MUST be atomic where partial completion would create an invalid security state.

---

## 24. Explicitly Unresolved Security Design

The following security details have not yet been fully specified and MUST NOT be invented by an implementation:

1. the exact mechanism identifying which Identity of the steward Principal may exercise stewardship-derived authority;
2. the final complete Permission catalog and exact Permission composition of each built-in Role;
3. the exhaustive classification of operations requiring strict scope dominance;
4. the precise domain/persistence representation of Role assignments and their contexts;
5. detailed Principal/Identity lifecycle and tombstone/soft-deletion behavior required to preserve immutable provenance;
6. agent/service-principal authentication and authorization details;
7. IdP-specific federation semantics beyond the invariant that every Principal retains a mandatory local MTMF Identity;
8. which manager-Tenant Identities or Groups are eligible to exercise TenantManagementGroup delegated authority;
9. whether soft-deleted objects can be restored and, if so, their restoration lifecycle semantics.

Until these matters are explicitly defined, implementations MUST choose the more restrictive behavior when a security decision would otherwise require an unstated assumption.

---

## 25. Constitutional Summary

The MTMF security model rests on these non-negotiable principles:

- authorization is evaluated for a specific Identity;
- Identities of the same Principal do not implicitly share authorization;
- Tenant boundaries are structurally enforced;
- membership relationships are explicit;
- Groups contain Identities through GroupMembership;
- Roles are assigned to Identities and Groups;
- effective Permission rules may be direct or Group-derived;
- authorization is deny-by-default;
- callers request exact Actions while Permissions define ALLOW/DENY matching rules;
- the most-specific matching Permission rule wins and equal-specificity DENY overrides ALLOW;
- Action verbs are never wildcardable;
- stable identifiers, not mutable names, establish resource identity;
- deletion is soft deletion;
- TenantManagementGroups provide explicitly bounded cross-Tenant delegated administration;
- Role/Permission definition ownership is distinct from security Scope and assignment context;
- ownership is immutable creator provenance;
- Tenant Stewardship is separate from ownership and Roles;
- Stewardship exists only for Tenants;
- destructive/security-sensitive authority requires both Permission and applicable dominance;
- ordinary scope dominance is strict, preventing same-scope self/peer escalation;
- root Principal/root Tenant invariants are immutable;
- URN namespace information must agree with structural Tenant ownership;
- security invariants must be enforced server-side/trusted-side, not merely in a UI;
- undefined security behavior is not permission to broaden authority.
