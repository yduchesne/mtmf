# PR22_STOP_REPORT

**PR:** roadmap PR 22
**Status:** **STOP-P22-A / STOP-P22-B FIRED. PR 22 is PARTIAL — BLOCKED.** The
safely isolated entitlement foundation is implemented and verified; the
first-Tenant composite transaction is **not implemented** and PR 22 must **not**
be marked DONE.

## STOP-P22-A — privilege boundary

**Condition:** implementation requires `mtmf_runtime` to call an operator-only
function directly or through `SECURITY DEFINER`, or to impersonate
root/operator.

**Evidence:**
- PR 13 registry mutations (`application_add`, `application_save`,
  `application_tenant_registration_add/save`,
  `tenant_application_subscription_add/save`) are owner-owned `SECURITY INVOKER`
  and **not** granted to `mtmf_runtime`
  (`persistence/postgres/sql/v010/02..03`).
- The service connects as `mtmf_runtime`; the mandatory post-upgrade verifier
  enforces exactly the 78-signature runtime allowlist
  (`persistence/postgres/roles.py`).
- A runtime-callable first-Tenant composite would have to be `SECURITY DEFINER`
  and runtime-granted, granting the runtime login a privileged mutation
  capability (Tenant/registration/subscription creation). That is forbidden.

**Decision:** do not create a runtime-callable privileged composite wrapper. No
workaround.

## STOP-P22-B — atomic stewardship / composite seam

**Condition:** cannot guarantee new active Tenant + Identity/Principal/initial
steward + initial registration/subscription in one transaction, or cannot keep
the production incomplete coordinator non-callable.

**Evidence:**
- The first-Tenant composite must atomically create a Tenant plus
  Identity/Principal/membership/steward (PR 23) plus the initial
  registration/subscription, audit, and replay/quota outcome.
- The only production execution identity is `mtmf_runtime`; there is no
  operator sign-in, SYSTEM-scope Role assignment, global/Tenant-independent
  target authorization, or privileged audited execution adapter (PR 21 operator
  prerequisite; see `docs/pr-artifacts/pr-21/PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`).
- Therefore the composite cannot be invoked by the production use case without
  either STOP-P22-A escalation or an unimplemented operator adapter. No partial
  Tenant-commit path may be created.

**Decision:** the composite is **BLOCKED**. No Tenant-committing function, no
placeholder Identity/Principal/steward, and no runtime admission read surface
were created.

## Required reviewer decision (smallest unblocking change)

Choose one and record it authoritatively:

- **Option 1 (recommended for PR 24 scope):** implement a privileged, audited
  operator execution adapter (separate protected credentials, exact Action
  authorization, atomic audit) that can invoke owner-only composite stored
  functions **without** granting them to `mtmf_runtime`; then PR 23 composes the
  verified Identity/Principal/steward participant in the same transaction.
- **Option 2:** add an explicitly reviewed privilege-separated composite seam
  (for example a dedicated restricted execution role, distinct from
  `mtmf_runtime`) with its own allowlist and tests, and document the new trust
  boundary in `SECURITY_MODEL.md`/`DATABASE.md`.

Until that decision exists, the composite and the quota/replay consumption
remain BLOCKED.

## Preserved isolated work (implemented, verified)

Revision `0014` adds the operator-only onboarding-entitlement foundation
(schema, guards, grant/revoke/read functions, append-only history) with no
runtime grant and no Role/Permission seed. Verified by 10 real-PostgreSQL
integration tests (P22-01..06/16/17/18 subset) and the full canonical gates.

## STOP dispositions

| STOP | State |
| --- | --- |
| STOP-P22-A (privilege boundary) | **FIRED — no workaround** |
| STOP-P22-B (atomic stewardship/composite) | **FIRED — BLOCKED** |
| STOP-P22-C (existing architecture conflict) | Not fired; PR 13 reuse verified |
| STOP-P22-D (authorization seed) | Not fired; no `0006`/`0012` change, zero new grants |
| STOP-P22-E (security proof) | Not fired; real restricted-runtime and postflight tests executed |
| STOP-P22-F (policy ambiguity) | Not fired; quota bound to explicit operator limit |
