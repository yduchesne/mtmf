# PR21_AMENDMENT02_STOP_REPORT

**PR:** roadmap PR 21 — Amendment 02
**Status:** **STOP-02, STOP-04, STOP-05, STOP-06 CLOSED by P02/P04/P05/P06.
STOP-03 remains OPEN (conditional subgate) pending human approval of the exact
Action/Role manifest.** PR 21 remains **NOT DONE**.

## STOP-02 — pre-Tenant onboarding entitlement — CLOSED

**Resolution (P02).** MTMF owns a separately provisioned, per-Application
onboarding entitlement keyed to the canonical Application UUID, `ACTIVE`/
`REVOKED` (terminal), granted/revoked only by an authenticated, explicitly
authorized system management authority through a reviewed management/
installation boundary; authoritative state in MTMF persistence; immutable grant
provenance and append-only revocation history; used only for the new verified
global Identity branch of `ResolveOrProvisionTenant`; bounded quotas with atomic
reservation; idempotency scoped to Application + subject + operation; fail
closed on missing entitlement/quota; audit of grants/revocations/provisioning;
and explicit separation from Role/Permission/subscription/credential.

**Closure rule met:** the entitlement is MTMF-owned, token-independent, and
inferred from nothing else. No Tenant membership is required in this narrow
branch; no broader bypass exists.

**Remaining subgate (implementation shape):** the exact table/function shape
and operator-policy numeric quota defaults are deferred to PR 22/23. This does
not reopen STOP-02.

## STOP-03 — exact Action / Role manifest — OPEN (conditional)

**Resolution (P03).** The **method** is approved: exact operation-specific
Actions, explicit scoped Permissions, additive versioned seeds. A complete
candidate manifest exists in `PR21_AMENDMENT02_ACTION_MANIFEST.md`, with every
grammar-valid literal and a per-row status.

**Why OPEN.** No new literal URN, exact Permission, built-in Role grant, or
system-management Role is human-approved. Approving the manifest method does not
approve the literals. In particular:

- new system-management Role(s) and their exact Permissions are unapproved;
- new binding to existing built-in Roles is unapproved;
- the entitlement administrative Actions are unapproved;
- credential-binding Actions are unapproved and gated by the PR 14 trust model.

**Required human decision.** Approve/amend the manifest table (all rows marked
NEEDS HUMAN APPROVAL), the system-management Role composition, and the additive
seed migrations. Until then STOP-03 is **OPEN** and PR 21 is NOT DONE.

**Owner on approval:** PR 22/23 (provision/entitlement), PR 24 (management),
PR 25 (invitations).

## STOP-04 — Application–Tenant registration authority — CLOSED

**Resolution (P04).** Registration create/revoke/replacement is system
management authority only; Tenant Administrators manage **subscriptions** for
their own Tenant only when an `ACTIVE` registration already exists. The narrow
first-Tenant exception lets the entitled initiating Application create the
**exact initial** registration + subscription atomically, bound to that
Application and the newly created Tenant, never other Applications/existing
Tenants/SYSTEM/root, with audit identifying the entitlement and both records.

**Closure rule met:** no Tenant Administrator registration bypass; no implicit
self-registration; registration alone does not activate a subscription;
operator-only PR 13 functions are not runtime-exposed.

## STOP-05 — terminal re-registration / re-subscription — CLOSED

**Resolution (P05).** PR 13 transitions and constraints are preserved exactly.
Replacement is a **fresh record/UUID** only: `REVOKED` registration replacement
requires system management authority; `CANCELLED`/`EXPIRED` subscription
replacement requires a Tenant-scoped authorized manager and an `ACTIVE`
registration; retired Applications cannot reopen. Replacements are explicit,
separately authorized, idempotent, concurrency-safe, atomically audited with
predecessor/reason/new UUID/actor/correlation ID. `SUSPENDED→ACTIVE` is an
in-place permitted transition, not terminal replacement.

**Closure rule met:** PR 13 lifecycle and unique-current constraints preserved;
no terminal reactivation; no silent replacement.

**Schema note:** current-row uniqueness supports a new current row after a
terminal row (partial unique indexes filter current lifecycles). If the
predecessor-reference/audit requires a schema addition, PR 22/24 reports the
exact additive change; no schema edit is made in PR 21.

## STOP-06 — service credential binding separation — CLOSED

**Resolution (P06).** Application registry lifecycle and OAuth service
credential lifecycle are separate operations and trust boundaries. Application
create/retire does not mint/bind credentials; subscription does not grant
credentials. Only separately authorized system credential administration may
add/revoke `(issuer, client_id)→Application` bindings with immutable provenance,
conflict detection, strict issuer/client/audience validation, and audit. The
PR 14 verified-binding boundary is preserved; suspension/retirement immediately
fails the active-Application eligibility check even with a cryptographically
valid old credential; credential cleanup is not claimed atomic with an external
IdP; raw secrets never appear in Application requests/responses.

**Closure rule met:** no credential issuance is implied by Application CRUD.

**Gated follow-up:** credential-binding management is a separate future
contract owned by PR 24 **only if** the approved PR 14 trust model supports it;
otherwise a separately named prerequisite with an exact owner and no fake
endpoint.

## Decision matrix

| STOP | Resolution | Closure rule | State |
| --- | --- | --- | --- |
| 02 | MTMF-owned per-Application entitlement, ACTIVE/REVOKED, system grant/revoke, quotas | token/role/subscription cannot imply entitlement | CLOSED |
| 03 | Exact Action/Permission/Role manifest | only with human-approved literals | **OPEN** |
| 04 | System registration + narrow first-Tenant composite exception | no Tenant-admin registration bypass | CLOSED |
| 05 | Fresh-UUID terminal replacement with separate authority/audit | PR 13 lifecycle preserved | CLOSED |
| 06 | Separate credential binding management | no credential issuance via Application CRUD | CLOSED |

## Effect on PR 21

Amendment 02 passes as a documentation-only deliverable even with STOP-03 open,
provided the unapproved literals remain isolated in the review-ready manifest
and no implementation is authorized. **PR 21 remains NOT DONE** until STOP-03
is human-approved and the normative documents are reconciled.
