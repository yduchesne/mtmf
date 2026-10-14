# PR19_STOP_REPORT

**PR:** roadmap PR 19.
**Date:** 2026-10-13.
**Trigger:** database mutation-audit trust-boundary decision.

## Exact location

- `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v*/**.sql`
- Every mutating stored function except the six v002 membership-removal
  functions and the three v008 stewardship functions.
- Example signatures (current behavior): `mtmf.tenant_save(id_value uuid,
  name_value text, lifecycle_value smallint, deletion_status_value smallint,
  extension_value jsonb)`, `mtmf.identity_role_assignment_add(...)`,
  `mtmf.application_save(...)`, `mtmf.service_credential_application_revoke(id_value uuid)`.

## Current behavior and evidence

- These functions mutate authoritative security-relevant state inside one
  UnitOfWork transaction, but write **no** audit row.
- None of them accepts an actor/provenance argument.
- The application persistence SPI does not carry an authenticated database
  session identity, and the runtime role is shared across Tenants.
- Evidence: `PR19_SECURITY_AUDIT_INVENTORY.md` (function-by-function table).

## Required invariant

`docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` §6: for database security-state
mutations, the mutation and its database audit entry must commit or roll
back together; a failed or no-op mutation must not be misrepresented. The
same document §9 and the PR 19 plan require that an uncovered write function
that cannot receive verified actor provenance must not have actor identity
falsely claimed.

## Blocking condition

Closing the gap requires either fabricating actor attribution or extending
the trust boundary so that verified actor provenance is threaded from the
application layer into every structural write function. That is a
trust-boundary/contract change, not an observability change, and the plan
explicitly forbids improvising a generic audit framework or a new management
API inside PR 19.

## Smallest decision needed

Approve a scoped follow-up ("PR 19A — verified-provenance mutation audit")
that defines: which mutation categories require durable audit; how verified
actor provenance is carried (per-call argument, authenticated session
identity, or an application-layer audit transaction); and whether the
existing `actor_identity_id` semantics remain explicitly unverified. No
implementation of that decision was performed in PR 19.

## Safe alternative (not implemented)

Leave the current atomic audit foundations unchanged, keep the uncovered
mutations as-is, and document them as known gaps. This preserves the
existing privilege boundary and makes no false completeness claim. PR 19
took exactly this alternative.
