# PR21_AMENDMENT02_AUTHORIZATION_MATRIX

**PR:** roadmap PR 21 — Amendment 02
**Status:** **PROPOSED / NOT IMPLEMENTED.** Exact Action/Permission/Role literals
are in `PR21_AMENDMENT02_ACTION_MANIFEST.md` and remain **STOP-03 open**.
This is a design-review artifact, not a test result.

## 1. Trust seams

| Seam | Proves | Never proves |
| --- | --- | --- |
| Verified Application service token | one registered Application | user, Tenant, operator, Permission |
| Verified user token | `(issuer, subject, client)` binding | membership, subscription, Action grant |
| Application onboarding entitlement (P02) | entitlement to first-Tenant provisioning for the new-Identity branch | Role, subscription, general management |
| Ordinary verified actor | `AuthenticatedActorContextService.resolve` for an ACTIVE Tenant + memberships + eligible subscription | new Tenant/first user |
| System management authority | operator/system management operations | end-user session |
| Tenant Administrator (exact scoped Permission) | own-Tenant subscription management and invitation create/revoke | Application lifecycle, registration, entitlement, credential binding |
| Pre-membership recipient seam | verified recipient + single-use capability | membership before acceptance |
| System credential administration (P06) | `(issuer, client_id)→Application` binding management | end-user session; separate from Application CRUD |

## 2. Operation matrix

| Op | Verified service | Verified user | Tenant scope | Authority | Exact Action (manifest) | Permission | Denial | Audit |
|---|---|---|---|---|---|---|---|---|
| Resolve/inspect Tenant | required | required | authorized exact Tenant | ordinary actor | `tenant:get-object` (APPROVED) | existing exact | fail closed / opaque 404 | read |
| Provision first Tenant (new Identity) | required | required | none (new) | P02 entitlement | `tenant:provision-object` (STOP-03) | entitlement, not a Role | deny | provision |
| Reuse existing Identity/Tenant | required | required | existing eligible | ordinary actor | `tenant:get-object` | existing exact | deny | read |
| Multi-Tenant selection | required | required | existing eligible set | ordinary actor | `tenant:get-object` | existing exact | authorized choices only | read |
| Application create | required | — | global | system management | `application:create-object` (STOP-03) | new system Role | deny | create |
| Application inspect | required | — | exact Application | system management | `application:get-object` | new system Role | deny | read |
| Application suspend/resume/retire | required | — | exact Application | system management | `application:suspend/resume/retire-object` | new system Role | deny | lifecycle |
| Registration create/revoke/replace | required | — | exact Application+Tenant | **system** (P04) | `application-tenant-registration:add/get/revoke-object` | new system Role | deny; no Tenant-admin registration | create/lifecycle |
| Subscription create/resume/replace | required | required | exact Tenant | Tenant admin or system | `application-subscription:add/resume-object` | exact Tenant Permission | deny; requires ACTIVE registration | create/lifecycle |
| Subscription suspend/cancel | required | required | exact Tenant | Tenant admin or system | `application-subscription:suspend/cancel-object` | exact Tenant Permission | deny | lifecycle |
| Subscription inspect/list | required | required | exact Tenant | Tenant admin or system | `application-subscription:get-object` | exact Tenant Permission | deny; no enumeration | read |
| Invitation create/revoke | required | required | exact Tenant | steward/Tenant admin | `tenant-invitation:create/revoke-object` | exact Tenant Permission | deny | create/lifecycle |
| Invitation accept | required | required (recipient) | invited Tenant only | pre-membership seam | `tenant-invitation:accept-object` | capability + verified subject | deny | accept |
| Entitlement grant/revoke/inspect | required | — | exact Application | system management | `application-onboarding-entitlement:grant/revoke/get-object` | new system Role | deny | grant/revoke |
| Credential binding add/revoke | required | — | exact Application | system credential admin (P06) | `service-credential-binding:add/revoke-object` | new system Role + PR 14 gate | deny | create/revoke |

## 3. Actor-capability matrix

| Operation | Regular user | Tenant Administrator (own Tenant) | System operator | Malicious Application | Invited user (no membership) | Cross-Tenant actor |
|---|---|---|---|---|---|---|
| First-Tenant provisioning | only if new Identity + entitled Application (via entitlement) | no (not a Tenant yet) | via entitlement only | denied without entitlement | no | n/a |
| Reuse existing Identity/Tenant | yes if member+eligible | yes | yes | only for its own verified user | no | no |
| Tenant selection | authorized choices | authorized choices | authorized choices | authorized choices for its user | no | no |
| Application management | no | no | yes | no (not self-registration) | no | no |
| Registration management | no | **no** (P04) | yes | no self-registration | no | no |
| Subscription management | no | **yes** (own Tenant, exact Permission) | yes | no (no silent subscription) | no | no |
| Invitation create/revoke | no | yes (own Tenant) | yes | no | no | no |
| Invitation accept | only with verified proof + capability for the invited Tenant | no | no | no | yes (exact Tenant only) | no |
| Entitlement administration | no | no | yes | no | no | no |
| Credential binding administration | no | no | yes (separate, P06) | no | no | no |

## 4. Denial behavior and audit

- Default DENY; missing/inconsistent/unevaluable context fails closed.
- No existence oracle: invisible targets return the same opaque result; no
  cross-Tenant enumeration.
- Permission evaluation preserves exact-over-wildcard specificity and
  equal-specificity DENY; no wildcard is proposed.
- Mutation operations write one atomic append-only audit row (actor,
  Application, entitlement/predecessor where applicable, exact Action, target,
  outcome, operation/correlation ID, UTC time) in the same transaction; a
  no-op/failed attempt writes no false success row.
- The entitlement and credential-binding operations are separate from normal
  Role/Permission assignment and never implicitly grant each other.

## 5. Cross-references

- `PR21_AMENDMENT02_ACTION_MANIFEST.md`, `PR21_AMENDMENT02_DECISION_RECORD.md`,
  `PR21_AMENDMENT02_STOP_REPORT.md`.
- `docs/ONBOARDING_ARCHITECTURE.md` §§3, 17; `docs/ONBOARDING_HTTP_CONTRACT.md` §15.
