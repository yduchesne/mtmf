# PR21_AMENDMENT01_AUTHORIZATION_MATRIX

**PR:** roadmap PR 21 — Amendment 01
**Status:** **PROPOSED / NOT IMPLEMENTED.** Every Action URN is an **UNAPPROVED
candidate** (STOP-03). No wildcard Permission and no invented built-in Role
grant. This matrix is a design-review artifact, not a test result.

## 1. Actors and trust seams

| Actor / seam | Meaning | Never proves |
| --- | --- | --- |
| Verified Application (service token) | OAuth 2.0 client credentials mapped to exactly one registered Application | a user, a Tenant, an operator, or a Permission |
| Verified user proof | Independently verified signed user token `(issuer, subject, client)` | a Tenant membership or an Action grant |
| Pre-Tenant entitlement | Separately configured, least-privilege authority bound to one Application; evaluated only in the new-Identity/new-Tenant branch | ordinary Tenant membership, subscription eligibility, or root |
| Ordinary verified actor | `AuthenticatedActorContextService.resolve` for an already ACTIVE Tenant + memberships + eligible subscription | a new Tenant or first user |
| System management authority | Approved operator/system authority for Application and registration management | an end-user session |
| Pre-membership recipient seam | Verified user proof + single-use invitation capability for acceptance | ordinary membership before acceptance |

## 2. Operation matrix

| # | Operation | Verified Application | Verified acting user | Existing Tenant context | Candidate exact Action (UNAPPROVED) | Permission/authority owner | Operator/entitlement required | Atomic audit | Negative cases |
|---|---|---|---|---|---|---|---|---|---|
| M01 | `resolve-or-provision` — new Identity + new Tenant | required | required | none | `...:tenant:provision-object` | pre-Tenant entitlement (STOP-02) | yes (entitlement) | yes | A01, A02, A03, A04, A16 |
| M02 | `resolve-or-provision` — existing Identity + one eligible Tenant | required | required | required | `...:tenant:get-object` (reused) | ordinary actor (and entitlement only for a create branch) | no | yes (no mutation) | A05, A06, A08 |
| M03 | `resolve-or-provision` — multiple eligible Tenants | required | required | required | read-only resolution | ordinary actor | no | no | A07, A15 |
| M04 | `resolve-or-provision` — membership, no subscription | required | required | membership only | read-only | ordinary actor | no | no | A09 |
| M05 | Application create | required | — | none | `...:application:create-object` | system management Role (STOP-03) | operator/system | yes | A02, A11 |
| M06 | Application inspect | required | — | none | `...:application:get-object` | system management Role | no | no | A11 |
| M07 | Application suspend/retire | required | — | none | `...:application:update-object` | system management Role | operator/system | yes | A11, A18 |
| M08 | Application–Tenant registration create/revoke | required | — | exact Tenant | `...:application-tenant-registration:add-object` / `:revoke-object` | STOP-04 | operator/system | yes | A10, A17 |
| M09 | Subscription create | required | required | exact Tenant | `...:application-subscription:manage-object` | Tenant administrator or operator (D6) | independent approval | yes | A10, A12, A19 |
| M10 | Subscription inspect/list | required | required | exact Tenant | `...:application-subscription:get-object` | Tenant administrator | no | no | A12, A15 |
| M11 | Subscription suspend/cancel | required | required | exact Tenant | `...:application-subscription:manage-object` | Tenant administrator or operator | independent approval | yes | A12, A20 |
| M12 | Invitation create/revoke | required | required | exact Tenant | `...:tenant-invitation:create/revoke-object` | invitation authority | no | yes | A13 |
| M13 | Invitation accept | required | required (recipient) | invited Tenant only | `...:tenant-invitation:accept-object` | pre-membership seam | no | yes | A13, A14 |

## 3. Scope, dominance, and isolation rules

- Exact Action + exact Tenant target. No wildcard Action and no wildcard
  Permission.
- Pre-Tenant admission (M01) is the **only** branch that omits an existing
  Tenant membership; it is bounded to a truly new global Identity with no
  eligible Tenant and requires the entitlement. It confers no ordinary
  cross-Tenant bypass.
- Authorization state is never unioned across Tenants; selection returns only
  authorized choices.
- Registration and subscription are independent facts; a missing `ACTIVE`
  registration denies even when a subscription exists.
- The protected SYSTEM/root Tenant is rejected for every ordinary onboarding
  and subscription operation.
- Resource-qualifier/scope rules and existing dominance semantics are preserved
  for all subsequent same-Tenant operations.

## 4. Negative-case legend

A01 no entitlement · A02 service token alone · A03 wrong issuer/audience/client ·
A04 forged subject/UUID · A05 existing Tenant not eligible for calling
Application · A06 suspended Tenant · A07 ambiguous/multiple Tenants without
selection · A08 internal integrity failure · A09 membership but no subscription ·
A10 subscription without registration · A11 inactive/retired Application ·
A12 cancelled/expired subscription · A13 wrong/absent recipient proof ·
A14 capability replay/double accept · A15 cross-Tenant enumeration ·
A16 idempotency collision · A17 registration authority not held ·
A18 retired Application reopened · A19 silent subscription · A20 terminal
subscription reopened. Full expected outcomes are in
`PR21_AMENDMENT01_SECURITY_CASES.md`.

## 5. Cross-references

- `docs/ONBOARDING_HTTP_CONTRACT.md` §15.
- `docs/ONBOARDING_ARCHITECTURE.md` §§3, 17.
- `PR21_CONTRACT_REVIEW.md` §1 (grammar), `PR21_AMENDMENT01_STOP_REPORT.md`
  (STOP-02…STOP-06).


---

## Amendment 02 update (2026-10-15)

The candidate Actions here remain UNAPPROVED and are superseded by
[PR21_AMENDMENT02_ACTION_MANIFEST.md](PR21_AMENDMENT02_ACTION_MANIFEST.md)
(STOP-03 open). Actor/authority decisions P02/P04/P05/P06 are now approved; see
[PR21_AMENDMENT02_AUTHORIZATION_MATRIX.md](PR21_AMENDMENT02_AUTHORIZATION_MATRIX.md).
