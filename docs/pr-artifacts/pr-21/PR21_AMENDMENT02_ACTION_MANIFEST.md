# PR21_AMENDMENT02_ACTION_MANIFEST

**PR:** roadmap PR 21 — Amendment 02
**Status:** **CANDIDATE MANIFEST — STOP-03 remains OPEN.** No new literal URN,
Permission, built-in Role grant, or system-management Role here is approved.
This table is review-ready input for a human decision. **Do not implement.**

## 1. Grammar validation (grounded)

Canonical grammar (`domain/iam_urn.py`): exactly three colon-separated
components after `urn:mtmf:iam:actions:`:

```text
urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>
```

- definition namespace `system` only (a `tenant` Action namespace is rejected);
- resource is a single non-empty, whitespace-free, colon-free component
  (hyphens allowed, e.g. `application-tenant-registration`);
- operation is `<verb>-<qualifier>` (first `-` splits; both non-empty);
- no wildcard in any component. Action URNs are exact.

Permission URNs mirror the Action with the `urn:mtmf:iam:permissions:` prefix
and an exact qualifier (no `*`), or a complete `*` qualifier where a wildcard
matcher is explicitly approved (none is proposed here).

Every literal in §2 was validated against these rules. Grammar-validity does
**not** imply approval.

## 2. Candidate manifest

Status legend: **APPROVED** = already seeded and human-approved; **NEEDS HUMAN
APPROVAL** = new literal/grant requiring an explicit human decision;
**PROPOSED** = naming recommendation that is not approved and whose grant is
not approved.

| # | Operation | Literal Action URN | Resource kind | Target scope | Verified actor | Required Permission (ALLOW) | Authorized Role / entitlement | Existing/New | PR owner | Audit kind | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Tenant resolve / inspect | `urn:mtmf:iam:actions:system:tenant:get-object` | tenant | exact Tenant (authorized) | verified user | `urn:mtmf:iam:permissions:system:tenant:get-object` | existing built-in Roles holding it | Existing | 24 | none (read) | APPROVED |
| 2 | Initial Tenant provisioning | `urn:mtmf:iam:actions:system:tenant:provision-object` | tenant | new ordinary Tenant | pre-Tenant entitlement | `urn:mtmf:iam:permissions:system:tenant:provision-object` | Application onboarding entitlement (not a Role) | New | 22/23 | provision | NEEDS HUMAN APPROVAL |
| 3 | Application create | `urn:mtmf:iam:actions:system:application:create-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:create-object` | new system-management Role | New | 24 | create | NEEDS HUMAN APPROVAL |
| 4 | Application inspect | `urn:mtmf:iam:actions:system:application:get-object` | application | exact Application | system operator | `urn:mtmf:iam:permissions:system:application:get-object` | new system-management Role | New | 24 | none | NEEDS HUMAN APPROVAL |
| 5 | Application suspend | `urn:mtmf:iam:actions:system:application:suspend-object` | application | exact Application | system operator | `urn:mtmf:iam:permissions:system:application:suspend-object` | new system-management Role | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 6 | Application resume (SUSPENDED→ACTIVE) | `urn:mtmf:iam:actions:system:application:resume-object` | application | exact Application | system operator | `urn:mtmf:iam:permissions:system:application:resume-object` | new system-management Role | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 7 | Application retire | `urn:mtmf:iam:actions:system:application:retire-object` | application | exact Application | system operator | `urn:mtmf:iam:permissions:system:application:retire-object` | new system-management Role | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 8 | Registration create | `urn:mtmf:iam:actions:system:application-tenant-registration:add-object` | registration | exact Application+Tenant | system operator | `urn:mtmf:iam:permissions:system:application-tenant-registration:add-object` | new system-management Role | New | 24 | create | NEEDS HUMAN APPROVAL |
| 9 | Registration inspect / list | `urn:mtmf:iam:actions:system:application-tenant-registration:get-object` | registration | exact Application+Tenant | system operator or Tenant admin (read own Tenant) | `urn:mtmf:iam:permissions:system:application-tenant-registration:get-object` | system Role / scoped read | New | 24 | none | NEEDS HUMAN APPROVAL |
| 10 | Registration revoke | `urn:mtmf:iam:actions:system:application-tenant-registration:revoke-object` | registration | exact Application+Tenant | system operator | `urn:mtmf:iam:permissions:system:application-tenant-registration:revoke-object` | new system-management Role | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 11 | Registration replacement (new UUID) | reuses `...:add-object` | registration | exact Application+Tenant | system operator | same | system Role | New | 24 | replacement | NEEDS HUMAN APPROVAL |
| 12 | Subscription create | `urn:mtmf:iam:actions:system:application-subscription:add-object` | subscription | exact Tenant (Application via path) | Tenant admin or system operator | `urn:mtmf:iam:permissions:system:application-subscription:add-object` | Tenant Administrator (own Tenant) | New | 24 | create | NEEDS HUMAN APPROVAL |
| 13 | Subscription inspect / list | `urn:mtmf:iam:actions:system:application-subscription:get-object` | subscription | exact Tenant | Tenant admin or system operator | `urn:mtmf:iam:permissions:system:application-subscription:get-object` | Tenant Administrator (own Tenant) | New | 24 | none | NEEDS HUMAN APPROVAL |
| 14 | Subscription suspend | `urn:mtmf:iam:actions:system:application-subscription:suspend-object` | subscription | exact Tenant | Tenant admin or system operator | `urn:mtmf:iam:permissions:system:application-subscription:suspend-object` | Tenant Administrator (own Tenant) | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 15 | Subscription resume (SUSPENDED→ACTIVE) | `urn:mtmf:iam:actions:system:application-subscription:resume-object` | subscription | exact Tenant | Tenant admin or system operator | `urn:mtmf:iam:permissions:system:application-subscription:resume-object` | Tenant Administrator (own Tenant) | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 16 | Subscription cancel | `urn:mtmf:iam:actions:system:application-subscription:cancel-object` | subscription | exact Tenant | Tenant admin or system operator | `urn:mtmf:iam:permissions:system:application-subscription:cancel-object` | Tenant Administrator (own Tenant) | New | 24 | lifecycle | NEEDS HUMAN APPROVAL |
| 17 | Subscription replacement (new UUID) | reuses `...:add-object` | subscription | exact Tenant | Tenant admin or system operator | same | Tenant Administrator (own Tenant) | New | 24 | replacement | NEEDS HUMAN APPROVAL |
| 18 | Invitation create | `urn:mtmf:iam:actions:system:tenant-invitation:create-object` | invitation | exact Tenant | steward/Tenant admin | `urn:mtmf:iam:permissions:system:tenant-invitation:create-object` | Tenant Administrator (own Tenant) | New | 25 | create | NEEDS HUMAN APPROVAL |
| 19 | Invitation accept | `urn:mtmf:iam:actions:system:tenant-invitation:accept-object` | invitation | invited Tenant only | verified recipient + capability | `urn:mtmf:iam:permissions:system:tenant-invitation:accept-object` | pre-membership seam | New | 25 | accept | NEEDS HUMAN APPROVAL |
| 20 | Invitation revoke | `urn:mtmf:iam:actions:system:tenant-invitation:revoke-object` | invitation | exact Tenant | steward/Tenant admin | `urn:mtmf:iam:permissions:system:tenant-invitation:revoke-object` | Tenant Administrator (own Tenant) | New | 25 | lifecycle | NEEDS HUMAN APPROVAL |
| 21 | Entitlement grant | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:grant-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object` | new system-management Role | New | 22/23 | grant | NEEDS HUMAN APPROVAL |
| 22 | Entitlement revoke | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:revoke-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object` | new system-management Role | New | 22/23 | revoke | NEEDS HUMAN APPROVAL |
| 23 | Entitlement inspect | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:get-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object` | new system-management Role | New | 24 | none | NEEDS HUMAN APPROVAL |
| 24 | Credential binding add | `urn:mtmf:iam:actions:system:service-credential-binding:add-object` | credential binding | exact Application | system credential admin | `urn:mtmf:iam:permissions:system:service-credential-binding:add-object` | new system-management Role + PR 14 gate | New | 24 (gated) | create | NEEDS HUMAN APPROVAL |
| 25 | Credential binding revoke | `urn:mtmf:iam:actions:system:service-credential-binding:revoke-object` | credential binding | exact Application | system credential admin | `urn:mtmf:iam:permissions:system:service-credential-binding:revoke-object` | new system-management Role + PR 14 gate | New | 24 (gated) | revoke | NEEDS HUMAN APPROVAL |

## 3. Existing approved URNs reused unchanged

| Literal | Seed | Grant |
| --- | --- | --- |
| `urn:mtmf:iam:actions:system:tenant:get-object` | revision `0006` | built-in Roles (Tenant Administrator, System Reader, …) |
| `urn:mtmf:iam:actions:system:role:get-object` | revision `0006` | built-in Security Administrator Roles |
| `urn:mtmf:iam:actions:system:organization:get-object` | revision `0006` | built-in Organization Roles |
| `urn:mtmf:iam:actions:system:identity-group-membership:add-object` | revision `0012` | sole built-in `urn:mtmf:iam:roles:system:tenant-administrator` |

These are **APPROVED** and MUST NOT be re-litigated or duplicated.

## 4. Required human decisions (STOP-03 subgate)

1. Approve or amend every **NEEDS HUMAN APPROVAL** literal above.
2. Approve the new **system-management Role** (name, URN, exact Permissions) or
   an equivalent approved authority model. No SYSTEM Role is approved here.
3. Approve the additive, idempotent, fail-closed seed migration(s) that add any
   new Action/Permission/Role grant without mutating the immutable
   `0006`/`0012` definitions.
4. Approve the entitlement administrative Actions (rows 21–23) and the
   credential-binding Actions (rows 24–25, gated by PR 14).

Until all four are approved, **STOP-03 remains OPEN** and PR 21 remains NOT DONE.

## 5. Constraints

- No wildcard Action or Permission.
- No auto-grant and no Role escalation.
- No runtime grant of operator-only registry/credential functions.
- Immutable revision `0006`/`0012` definitions are not modified; additions are
  separate additive seeds.
