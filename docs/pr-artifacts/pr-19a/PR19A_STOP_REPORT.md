# PR19A_STOP_REPORT

**PR:** roadmap PR 19A — verified-provenance mutation audit.
**Date:** 2026-10-14.
**Status:** **BLOCKED** — mandatory early STOP. Contract scaffold and deterministic tests implemented; no schema, stored function, grant, route, DTO, or client method added.
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5`.

## 1. Primary blocker

`BLOCKED: no existing authenticated management mutation entry point`.

Phase 0 (`PR19A_TRUST_BOUNDARY_RECONCILIATION.md`) proved that the codebase contains **no category-A** (verified actor + exact authoritative Action `ALLOW` + target binding + security-state mutation) application operation:

- the only production HTTP routes are `POST /v1/authorization/evaluate` (a decision endpoint) and the two health probes;
- `AuthenticatedActorContextService.resolve`, `ManagementAuthorizationResolver.resolve`, `EffectiveRoleResolver`, and the `Authorizer`/`BatchAuthorizer` are all read-or-decide-only;
- no production application, service, client, or script calls a persistence repository write method;
- every mutation is either category B (privileged operator/bootstrap raw SQL, `SET ROLE mtmf_owner`) or category C (structural repository functions exercised only by tests).

The plan's mandatory early STOP therefore applies: **do not manufacture a management API or a synthetic mutation path**. Per the plan, only the internal provenance contract and deterministic tests were implemented.

## 2. Exact unresolved gap (unchanged from PR 19)

- Location: `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v*/**.sql`; every mutating stored function except the six v002 membership-removal functions and the three v008 root/stewardship functions.
- Current behavior: these functions mutate authoritative security-relevant state with **no** audit row and receive no verified actor provenance.
- Runtime posture: 29 mutating functions remain runtime-`EXECUTE`-granted (19 repository writes, 4 role-assignment writes, 6 already-audited removals). No legacy `EXECUTE` was revoked because no operation was migrated.
- Invariant at risk: `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` §6 — mutation and database audit entry must commit or roll back together; no-op/failed mutations must not be misrepresented.

## 3. STOP conditions triggered

| # | Condition | Triggered |
|---|---|---|
| 1 | No existing authenticated+authorized management mutation path can be proven | **YES** |
| 2 | Selected mutation lacks exact Action authorization or target binding | n/a (no selected mutation) |
| 3 | TOCTOU-safe mutation not achievable with existing seams | not evaluated (no path) |
| 4 | Shared runtime credential can invoke an unaudited legacy bypass for a purportedly covered operation | **YES** (no operation covered, so every legacy mutator is a bypass) |
| 5 | Requirement changes to cryptographically DB-verifiable human identity | no |
| 6 | New public management API / generic framework / new Action-Permission semantics necessary | not added; would be required to proceed, hence STOP |
| 7 | Existing membership/stewardship/root audit duplicated or weakened | no (preserved) |
| 8 | New migration would destroy authoritative data or edit shipped SQL | no (no migration) |
| 9 | Privilege postflight cannot pass without widening runtime privileges | no |
| 10 | Non-MTMF container/volume/network modified | no |
| 11 | Canonical tests unavailable/failing before changes, or feature tests unexecuted | no — baseline green; blocked cases are labeled, not faked |
| 12 | Scope expands to partitioning/retention or a generic per-decision ledger | no |

## 4. Smallest reviewer decisions required

1. **Authorize the category-A entry point.** Choose whether PR 19A proceeds by (a) approving a narrowly scoped, authenticated, authorized management mutation use case (route or internal application use case) for one or more operations, or (b) formally amending PR 19A scope to contract-only and keeping every uncovered mutator `BLOCKED`.
2. **Choose the provenance enforcement mechanism.** Confirm the locked decision: explicit provenance arguments to a new versioned, narrowly scoped stored function (no `SET LOCAL`/GUC as identity). Confirm the accepted residual risk that a compromised runtime credential can forge those arguments (application-verified, not DB-attested).
3. **Confirm the bypass-closure requirement.** Confirm that migrating an operation requires revoking the legacy runtime `EXECUTE` on the corresponding mutator and proving denial on the real `mtmf_runtime` login before the operation may be called "covered".
4. **Confirm PR 19B ownership.** Confirm date partitioning remains deferred to PR 19B.

No implementation of these decisions was performed in this PR beyond the contract scaffold.

## 5. Safe alternative (implemented)

- Keep the existing atomic audit foundations unchanged.
- Keep every uncovered mutator as-is and label it `STRUCTURAL/UNVERIFIED`, `PRIVILEGED-OPERATOR`, or `BLOCKED`.
- Add only the internal provenance contract with an empty closed registration map and fail-closed validation.
- Make no false completeness claim. This preserves the existing privilege boundary and the PR 19 STOP.

PR 19 remains **not DONE**; PR 19A is **PARTIAL/BLOCKED**.
