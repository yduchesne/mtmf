# PR21_AMENDMENT01_DECISION_RECORD

**PR:** roadmap PR 21 — Amendment 01
**Status:** **D1–D8 are human decisions already made and binding for this
amendment.** Their *direction* is approved; the implementation-level security
policy they do not settle is listed as proposed/unapproved in §3 and in
`PR21_AMENDMENT01_STOP_REPORT.md`.

## 1. Approved decisions (human)

| ID | Decision | Rationale |
| --- | --- | --- |
| **D1** | A Tenant is an organizational security boundary; it is not owned by ATI, Digr, or any consuming Application. One Tenant may have many Application subscriptions; one Application may serve many Tenants. | Removes product-specific Tenancy; matches `SECURITY_MODEL.md` Tenant isolation and PR 13's global Application model. |
| **D2** | Single registration-facing orchestration: an Application submits verified user identity proof + authenticated service identity to an MTMF `ResolveOrProvisionTenant` operation. MTMF owns Identity resolution and the Tenant-context outcome. ATI is never required to call `CreateTenant` because it cannot find a Tenant locally. | Prevents consumer-side duplicate Tenant logic and product-specific state. |
| **D3** | Automatic initial creation is only for a **truly new global Identity** (no verified `(issuer, subject)` binding). An appropriately entitled Application may then atomically create the global Identity/Principal and initial ordinary Tenant, establish first stewardship and memberships, and establish an explicitly authorized initial Application registration/subscription. A service token alone never grants this entitlement. | Makes first registration work without circular authorization, while keeping creation behind an explicit entitlement. |
| **D4** | Reuse over duplication. Existing Identity + eligible existing Tenant ⇒ reuse. Never create a second Tenant because the user signs into a different Application. Existing Identity with no eligible Tenant ⇒ explicit onboarding-required/selection state, **not** automatic new-Tenant creation. Suspended/inaccessible Tenants are never circumvented by silent provisioning. | Preserves global Identity/Principal and Tenant isolation; prevents Tenant sprawl and status bypass. |
| **D5** | Multi-Tenant ambiguity: more than one eligible Tenant ⇒ explicit selection-required result with only authorized, non-enumerating choices; never arbitrarily select. | Avoids oracle leakage and wrong-Tenant decisions. |
| **D6** | Subscription approval: existing Tenant membership does not authorize a new Application subscription. If the Application is not subscribed, an explicitly authorized Tenant administrator or approved operator must authorize it; no silent subscription. Subscription is eligibility, never permission. | Preserves PR 13's registration/subscription separation and `SECURITY_MODEL.md` §25. |
| **D7** | Provide planned HTTP management contracts for Application create/inspect/suspend/retire; Application–Tenant registration lifecycle; subscription create/inspect/list/suspend/cancel. Prefer logical deactivation to physical deletion in v0.1. Preserve PR 13 terminal-state and timestamp invariants. | Completes the management lifecycle surface; matches the existing append/history model. |
| **D8** | Resolve STOP-01 in favor of **Option B — a narrowly scoped pre-Tenant Application-initiated admission**. Do not use `AuthenticatedActorContextService.resolve` for an unknown Tenant, operator/root impersonation, or the privileged development initializer. | User-approved direction for v0.1 self-service onboarding without circular actor resolution. |

**Boundary of D8:** this approves the *direction*, not arbitrary Action URNs,
new built-in grants, an unconstrained public registration policy, or an exact
wire contract. Those are §3 open items.

## 2. Alternatives considered

| Decision | Alternative | Why not chosen |
| --- | --- | --- |
| D1 | Product-owned Tenant per Application | Breaks MTMF's shared security boundary and forces account duplication across Applications. |
| D2 | Application calls `CreateTenant` when local lookup fails | Requires consumer-side Tenant decision logic and creates duplicate Tenants for an existing Identity. |
| D3 | Always create a Tenant for any new Application sign-in | Violates D4 and Tenant isolation; enables Tenant sprawl and abuse. |
| D4 | Auto-provision when no eligible Tenant exists | Ignores suspended/inaccessible Tenants and existing global Identity; contradicts D4. |
| D8 | Option A operator-mediated provisioning only | Rejected: blocks the roadmap's "authorized consuming Application onboards a new ordinary Tenant" objective for v0.1. |

## 3. Approved vs proposed boundary

**Approved (direction):** D1–D8 above.

**Proposed / NOT approved (narrow STOPs — see `PR21_AMENDMENT01_STOP_REPORT.md`):**

| STOP | Unresolved policy | Owner |
| --- | --- | --- |
| STOP-02 | Pre-Tenant onboarding-entitlement issuer/grant/revoke model and where its authoritative state lives | Human reviewer, then PR 23/24 |
| STOP-03 | Exact onboarding Action URNs and built-in Role/Permission composition | Human reviewer, then PR 22–25 |
| STOP-04 | Authority for the initial and subsequent Application–Tenant registration, given PR 13 registration mutation is operator-only | Human reviewer, then PR 22/24 |
| STOP-05 | Terminal re-subscription / re-registration replacement policy | Human reviewer, then PR 24 |
| STOP-06 | Application service-credential binding management boundary | Human reviewer, then PR 24 |

## 4. Non-negotiable constraints carried forward

- No production code, migration, route, SQL, or dependency change in PR 21.
- Every future endpoint/Action/DTO is **PROPOSED / NOT IMPLEMENTED**.
- No wildcard Permission; no invented built-in Role grant.
- The protected SYSTEM/root Tenant is excluded from ordinary onboarding and
  subscriptions.
- `mtmf_runtime` never receives a privileged registry mutation grant.


---

## Amendment 02 update (2026-10-15)

D1–D8 remain binding. The narrower STOPs listed in §3 were resolved by
Amendment 02: STOP-02 (P02), STOP-04 (P04), STOP-05 (P05), STOP-06 (P06) closed;
STOP-03 (exact Action/Permission/Role manifest) remains open. See
[PR21_AMENDMENT02_DECISION_RECORD.md](PR21_AMENDMENT02_DECISION_RECORD.md).
