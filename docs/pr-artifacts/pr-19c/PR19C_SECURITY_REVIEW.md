# PR19C_SECURITY_REVIEW

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation.
**Date:** 2026-10-14.
**Base commit:** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db`.
**Status:** STOP triggered before production edits. This review documents the verified current security boundary and the exact gap that blocks the approved operation. It is a review of the **unmodified** base, not of new code.

## 1. Verified-actor boundary (present, unchanged)

`AuthenticatedActorContextService.resolve(service_token, user_token, tenant_id)` independently verifies the service token and the user token, enforces same-client `azp`, issuer profiles, class separation, fresh zero-cache attestation, persisted credential/subject bindings, lifecycle/membership and Application–Tenant eligibility, and excludes root. It returns an immutable `VerifiedActorContext`.

The intended PR 19C design uses exactly this service and ignores every client-supplied actor/principal/application/action/operation/audit field. That design is not weakened; it simply cannot proceed without an approved Action.

## 2. Authorization boundary (present, unchanged)

`EffectiveRoleResolver.resolve` reads persisted assignments and prerequisite typed memberships in one UnitOfWork and returns detached, Tenant-filtered Role aggregates. `build_authorization_context` turns the verified state into the `AuthorizationContext`; `Authorizer.authorize` makes the authoritative exact-Action decision (default `DefaultAuthorizationPolicyResolver -> EffectivePolicy(CompiledPolicy, context)`). Default-deny, "exact beats wildcard", "equal-specificity DENY wins", and fail-closed context are unchanged.

`ManagementAuthorizationResolver` is explicitly a delegated **cross-Tenant** seam and must not be used for this same-Tenant operation. No change was made.

## 3. Exact-Action / target-binding gap (blocking)

PR 19C requires the operation to request one exact, approved Action for `target_kind = "identity_group_membership"` and `target_id = group_id`.

- The built-in policy installs and asserts exactly three Action definitions: `tenant:get-object`, `role:get-object`, `organization:get-object`.
- No typed-membership Action exists anywhere in the repository.
- The authoritative PR 10 manifest defers typed-membership Actions to a separate reviewed inventory and forbids generic CRUD substitution.
- `docs/SECURITY_MODEL.md` §15.1/§15.2 requires a distinct Action for security-sensitive operations.

Substituting `group:update-object`, a wildcard, or a newly invented Action is forbidden by the plan and the Security Model. `VerifiedMutationProvenance` remains unregistered, so the existing fail-closed guard (`require_registered_mutation`) would reject any such attempt. This is the correct secure posture: **fail closed rather than authorize against an unapproved Action.**

## 4. Target binding (designed, not implemented)

The approved design distinguishes the authorization target (`target_id = group_id`) from the affected subject (`identity_id` recorded separately in audit), avoiding a fabricated membership UUID. Because implementation did not start, no target-binding code exists; no partial binding was introduced.

## 5. Atomic audit and provenance (present scaffold, unchanged)

- `VerifiedMutationProvenance` is immutable, validates UTC and `DomainId`s, and is internal-only.
- `_MIGRATED_MUTATIONS` remains **empty**; no target kind or Action pairing is registered. This preserves the PR 19A fail-closed state.
- No `security_mutation_audit` table, stored function, migration, or grant was created. Migration head remains `0011`.

## 6. Runtime privilege manifest (before = after; no change)

No SQL or `roles.py` change was made. The 75-signature runtime EXECUTE allowlist through v011 is unchanged. In particular:

- `mtmf.identity_group_membership_add(uuid,uuid)` remains runtime-granted and **unaudited** (known prerequisite to close in Step 8 of an actual implementation).
- No new function was granted; the mandatory post-upgrade runtime-privilege verifier is unchanged.

Had implementation proceeded, the required posture would be: revoke the legacy `identity_group_membership_add` runtime EXECUTE (and PUBLIC/transitive equivalents), grant only the exact new `identity_group_membership_add_verified` signature, and have the mandatory postflight reject both a missing new grant and a surviving legacy effective EXECUTE. None of this was performed.

## 7. Concurrency / TOCTOU (designed, not proven)

The plan requires a transaction-level advisory lock for the Tenant management lane only if **all** relevant policy writers participate in the same discipline. Phase 0 found no such shared lane; existing writers use row-level locks and trigger guards. Therefore the plan's own prerequisite ("If they do not already share this discipline, STOP: advisory lock cannot guarantee TOCTOU safety") is also unmet. This is a second, independent blocker requiring reviewer-approved bounded design.

## 8. Residual shared-runtime-credential risk (unchanged, must be documented in any implementation)

PostgreSQL performs no cryptographic attestation of the human actor. `mtmf_runtime` is a shared application credential; a compromised runtime credential could forge provenance arguments. PR 19C audit provenance is **application-verified**, not database-attested. This residual risk is unchanged because no code was added, and it must be documented explicitly in the eventual implementation.

## 9. Security disposition (Phase 0 STOP)

The secure outcome of this PR is to make **no** change: the operation is denied by absence, and the existing default-deny/fail-closed boundaries are preserved. Introducing an endpoint or a stored function against an unapproved Action would have weakened the Security Model. The reviewer decision required is to approve one exact membership-add Action and its built-in Role grant (or amend scope).

---

# Amendment 01 implementation review (2026-10-14)

The Phase 0 STOP above is superseded by human approval (Amendment 01 §A). This section reviews the implemented security boundary.

## 10. Approved-action boundary

The exact Action `urn:mtmf:iam:actions:system:identity-group-membership:add-object` and its exact Permission are installed by an idempotent, operator-only seed; the sole grant is the Tenant Administrator built-in Role. No wildcard, generic CRUD, or unrelated-Action substitution exists. `VerifiedMutationProvenance` now registers exactly this target-kind/Action pairing.

## 11. Atomic audit

`mtmf.security_mutation_audit` is append-only (UPDATE/DELETE/TRUNCATE guards), carries no runtime table DML, and receives exactly one row iff `identity_group_membership_add_verified` actually inserted a membership row (`INSERT … ON CONFLICT DO NOTHING RETURNING`, then the audit insert in the same statement/transaction). A duplicate is a no-op with zero audit rows; an audit failure aborts the whole statement.

## 12. Privilege boundary

The runtime allowlist is exactly 78 reviewed signatures. The legacy `identity_group_membership_add(uuid,uuid)` grant is revoked from `mtmf_runtime` and `PUBLIC` and demoted to `SECURITY INVOKER`, so it is neither runtime-executable nor part of the elevated surface. The mandatory post-upgrade verifier passes; direct audit-table DML and legacy invocation are denied on the real runtime login (`test_i06`, `test_i07`).

## 13. Concurrency

The ordered row-lock/recheck protocol was proven against real PostgreSQL 18 (E1–E5 blocked). The application takes the locks before resolving applicable Roles and authorizing, so the exact-Action ALLOW cannot be invalidated by a concurrent revocation/replacement/suspension before commit; a conflicting writer blocks or forces a safe abort. `SERIALIZABLE` was not substituted.

## 14. Residual risk (unchanged, explicit)

`mtmf_runtime` is a shared application credential; the database cannot cryptographically attest the human actor. Provenance is **application-verified**, not database-attested. A compromised runtime credential can forge the provenance arguments. This is documented, not mitigated, and no DB-attested claim is made.

## 15. Present security gaps

The HTTP/DTO/service composition is not implemented, so the operation is not externally reachable; the core is callable only by trusted application code today. The live dual-token acceptance is not executed. No other mutator is covered. The Security Model and DATABASE docs are not yet updated to claim coverage, which is the correct fail-closed posture for a PARTIAL implementation.

---

# Amendment 02 security review addendum (2026-10-14)

- **Trust boundary:** the HTTP body carries only `tenant_id`/`identity_id`/`group_id`. The route extracts exactly one service bearer token and one configured user bearer token (duplicate/missing/wrong-scheme rejected) and never trusts forwarded headers. The verified `ManagementMembershipService` performs one dual-token resolution and one authorized UoW; the adapter performs no policy decision and opens no UoW.
- **Authorization:** the exact approved Action, same-Tenant target, steward acting-Identity guard and atomic audit are unchanged from Amendment 01. The adapter maps a guard/target failure to the opaque `FORBIDDEN` (no existence oracle); it does not catch DB outages, which remain `DEPENDENCY_UNAVAILABLE`/503.
- **Concurrency:** unchanged; the ordered row-lock/recheck proof (E1–E5) still holds, plus the new concurrent-duplicate DB test (CC-H04).
- **Privilege surface:** unchanged from Amendment 01; `mtmf_runtime` allowlist remains 78, the legacy unaudited function is not runtime-executable, and direct audit DML is denied.
- **Residual risk:** shared `mtmf_runtime` credential => application-verified (not DB-attested) provenance, unchanged.
- **Error classification:** `FORBIDDEN` is the explicitly approved additive v1 code; a policy denial is never reported as `UNTRUSTED_ACTOR`/`INELIGIBLE_APPLICATION`. Existing evaluate-route error mappings are unchanged.
- **Open gap:** live H01–H05 not executed (BLOCKED), so the end-to-end live trust chain is not yet independently demonstrated.
