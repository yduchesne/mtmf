# PR21_AMENDMENT01_STOP_REPORT

**PR:** roadmap PR 21 — Amendment 01
**Status:** **STOP-01 CLOSED (Option B direction approved). Narrower STOP-02…STOP-06 OPEN.**
**Effect:** the admission direction is settled, but PR 21 MUST NOT be marked
DONE while any narrower STOP below is unresolved. No runtime behavior is
implemented.

## STOP-01 — CLOSED: pre-Tenant Application-initiated admission (Option B)

**Resolution (human decision D8):** v0.1 uses a narrowly scoped **pre-Tenant
Application-initiated admission** (Option B), not operator-only provisioning and
not ordinary `AuthenticatedActorContextService.resolve`. The trusted
`ResolveOrProvisionTenant` operation authenticates the Application service token
and independently verifies the user proof, then performs Identity resolution and
the Tenant-context outcome.

This closes the original PR 21 STOP-01 in favor of Option B. It does **not**
approve the detailed security implementation (which Action, which entitlement
store, which Role grant, which composite registration authority). Those are the
narrower STOPs below. The original `PR21_STOP_REPORT.md` resolution is updated
with a link to this record; history is preserved.

## STOP-02 — Pre-Tenant onboarding entitlement issuer/state

**Issue.** D3 requires an "appropriately entitled Application". The entitlement
must be a separately configured, least-privilege authority bound to the
authenticated Application — not implied by client credentials, ordinary
subscription eligibility, Tenant Administrator Role, or root impersonation.
Neither the issuer of that entitlement nor where its authoritative state lives
is approved.

**Chosen proposal (UNAPPROVED).** A dedicated, operator-managed, versioned
**Application onboarding-entitlement record** (or an equivalent explicitly
scoped SYSTEM Role assignment) bound to exactly one registered `Application`,
with `ACTIVE`/`REVOKED` lifecycle and immutable grant provenance, evaluated only
in the pre-Tenant branch. Granting/revoking is a separately authorized system
management operation, never self-service through the Application service token.
The exact naming, storage (new table vs. existing binding mechanism), and
authority are subject to human approval; the implementation would require an
additive migration owned by PR 23/24.

**Required reviewer decision.** Approve, amend, or reject the entitlement model
and name its grant/revoke authority.

**Impact on PRs 22–26.** PR 22/23 cannot finalize the pre-Tenant authorization
check; PR 24 cannot expose the route.

## STOP-03 — Exact onboarding Action URNs and Role/Permission composition

**Issue.** `PR21_CONTRACT_REVIEW.md` §1 proposes Action URNs
(`tenant:provision-object`, `application-subscription:manage-object`,
`tenant-invitation:create/revoke/accept-object`, etc.) and a Role/Permission
composition. None is approved. The revision-`0006` built-in seed is immutable
policy and cannot be mutated at runtime.

**Required reviewer decision.** Approve the exact URNs and the additive,
idempotent, fail-closed seed of the exact ALLOW Permissions and their Role
grants. No wildcard.

**Impact.** PRs 22–25 cannot register Actions/Permissions without approval.

## STOP-04 — Application–Tenant registration authority

**Issue.** Eligibility requires an `ACTIVE` registration **and** an `ACTIVE`
subscription. In PR 13, registration mutation is operator/installation-only. A
Tenant administrator may plausibly be granted subscription authority, but
registration authority is not defined. Silently broadening Tenant Administrator
privileges is forbidden.

**Required reviewer decision.** Either (a) a separately authorized operator step
for registration, or (b) an approved composite admission that atomically creates
registration + subscription under a single reviewed exact Action with explicit
operator delegation. The chosen model and its audit must be specified.

**Impact.** PR 24 cannot define `POST .../subscriptions` semantics without this;
the initial first-Tenant registration is already covered by D3.

## STOP-05 — Terminal re-subscription / re-registration policy

**Issue.** The schema retains terminal rows as history and permits a later
current row for the same `(application_id, tenant_id)` (a new UUID). The
*policy* for when an Application may be re-subscribed after `CANCELLED`/`EXPIRED`
or re-registered after `REVOKED` is not approved. `REVOKED` registration and
`CANCELLED`/`EXPIRED` subscription are individually terminal (no in-place
reactivation); replacement is a new row.

**Required reviewer decision.** Approve the replacement policy (allowed,
forbidden, or operator-gated) and the required audit.

**Impact.** PR 24 must not promise reactivation. Until decided, replacement is
documented as a new row with unspecified policy and is **not** implemented.

## STOP-06 — Application service-credential binding management

**Issue.** D7 adds Application lifecycle management. PR 14 maps
`(issuer, client_id)` → Application through `ServiceCredentialBinding`. Whether
Application management may create/revoke credentials is a separate
security-sensitive decision.

**Required reviewer decision.** Confirm that credential binding management is
**separate** from Application create/retire and assign it to the PR 14/24
boundary. An Application record alone must not grant authentication credentials.

## Interaction with PR 21 status

PR 21 remains **NOT DONE**: STOP-02…STOP-06 require human approval. The amendment
is a reviewed design freeze and safe partial deliverable only.

## Resolution record

_No resolution recorded for STOP-02…STOP-06. STOP-01 is closed per D8._
