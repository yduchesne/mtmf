# PR19C_STOP_REPORT

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation (add an existing Identity to an existing Group in one ACTIVE Tenant).
**Date:** 2026-10-14.
**Base commit:** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db` (branch `dev/mgmt-mutation`; equals `main`/`origin/main`).
**Status:** **BLOCKED — mandatory early STOP. No production edits made.**

## 1. Exact blocker

```text
BLOCKED: no approved exact Action for identity-to-group membership addition
```

PR 19C may create the authenticated management endpoint, but it is explicitly forbidden to invent an Action URN, a Permission, a built-in Role grant, or relaxed dominance semantics. Phase 0 proved that **no approved exact Action** exists for this operation, and no settled operation-specific guard exists either.

## 2. Where the gap is (file / schema / object)

| Layer | Location | Actual state |
| --- | --- | --- |
| Approved Action definitions (authoritative) | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v006/02_builtin_seed_function.sql` + assertion `.../v006/04_builtin_privilege_assertions.sql` | Exactly **three** Actions installed and enforced: `urn:mtmf:iam:actions:system:tenant:get-object`, `...:role:get-object`, `...:organization:get-object`. Assertion fails the migration unless exactly 3 exist. |
| Action examples | `packages/mtmf-core/src/mtmf_core/domain/action.py` (`BASELINE_ACTIONS`) | 17 examples for principal/role/tenant only; explicitly "NOT an exhaustive Action catalog"; no membership Action. |
| Repository-wide Action scan | all `.py`/`.sql`/`.md`/`.json` | No Action URN for any typed-membership operation exists. |
| Candidate manifest | `docs/pr-artifacts/pr-10/PR10_EXACT_PERMISSION_MANIFEST.md` §3, §6 | Typed-membership Actions deferred to "their own reviewed Action inventory"; "Do not replace missing operations with generic container CRUD"; human approval of missing membership Actions is an open checklist item. |
| Constitution | `docs/SECURITY_MODEL.md` §15.1, §15.2, §18 | Security-sensitive operations MUST use distinct Actions; broad CRUD substitution forbidden; membership/Role assignment listed as security-sensitive. |
| Provenance registration | `packages/mtmf-core/src/mtmf_core/application/mutation_provenance.py` (`_MIGRATED_MUTATIONS`) | Empty; fail-closed. No approved pairing to register. |
| Legacy bypass (would need closing) | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v004/03_membership_functions.sql` `mtmf.identity_group_membership_add(uuid,uuid)`; runtime grant in `.../postgres/roles.py` line 143 | Present, `SECURITY DEFINER`, no actor/audit; runtime-granted. Known Step 8 prerequisite, not itself the blocker. |

## 3. Actual behavior vs. required behavior

- **Actual:** an identity-to-group membership add can only be performed by the unaudited runtime function `mtmf.identity_group_membership_add`, which carries no verified actor provenance and no audit row. There is no authenticated management route and no approved Action to authorize one.
- **Required by PR 19C:** an authenticated service resolving a verified actor, evaluating a single **exact approved Action** against the target Group in the session Tenant, then atomically inserting the membership and one append-only audit row.
- **Gap:** the "single exact approved Action" input does not exist and may not be invented.

## 4. Violated invariant / STOP rule

- Plan §0: "If no applicable approved Action exists, STOP before production edits and report `BLOCKED: no approved exact Action for identity-to-group membership addition`."
- Plan §10 STOP rule: "STOP before edits if exact membership-add Action/guard is not approved."
- `AGENTS.md`: "Do not silently broaden scope, resolve documented open questions by assumption, or introduce product-specific behavior into MTMF."
- `docs/SECURITY_MODEL.md` §15.1/§15.2: distinct security-sensitive operations require distinct Actions; implication by broad CRUD is forbidden.

Proceeding would have required fabricating security semantics, which is precisely what the plan and the Security Model prohibit.

## 5. Secondary unresolved prerequisite (recorded, not the primary blocker)

Plan Step 3 makes the transaction-level advisory lock sufficient **only if all relevant role/permission/membership/tenant-state mutators participate in the same lock discipline**. Phase 0 found no shared per-Tenant lane: current mutators use row-level `FOR UPDATE`/`FOR KEY SHARE` locks and trigger guards (`docs/DATABASE.md` §181). The plan's fallback in that case is itself a STOP requiring the "smallest bounded lock/DB recheck alternative" reviewer approval. This is unresolved independently of the Action decision.

## 6. Smallest human decision required (single)

**Approve exactly one exact membership-add Action and its authorization grant — or amend PR 19C scope to defer.**

Concretely, approve:

1. one exact Action URN for adding an existing Identity to an existing Group, proposed candidate (unapproved):
   `urn:mtmf:iam:actions:system:identity-group-membership:add-object`
   (or a human-chosen canonical spelling), and
2. the Permission matcher plus the built-in Role grant(s) that may produce `ALLOW` for it (for example Tenant Administrator / Tenant Security Administrator), and
3. the operation-specific guard/dominance rule (target Group in the session Tenant; subject and Group same-Tenant prerequisite memberships; anti-escalation and protected-root/stewardship exclusions).

Alternatively, approve a bounded lock/DB-recheck concurrency design for same-Tenant management authorization (to satisfy Step 3) in the same decision.

No PR 19C production work should proceed until decision (1)–(3) is recorded in an authoritative document or code commit referencing it.

## 7. STOP-rule checklist

| Rule (§10) | Triggered |
| --- | --- |
| Exact membership-add Action/guard not approved | **YES (primary)** |
| Current main differs materially from verified facts | no — base matches PR 19A evidence |
| Migration head differs from `0011` | no |
| No provable TOCTOU-safe lock discipline for all relevant writers | **YES (secondary)** |
| Existing production caller needs the legacy runtime grant | no evidence found |
| Unapproved dominance/stewardship semantics required | **YES (guard unsettled)** |
| Endpoint/connector parity requires new architecture | not reached |
| Required HTTP error code cannot be expressed | not reached |
| Canonical harness unavailable / mandatory tests cannot execute | no (baseline gates green) |
| Migration destroys authoritative data | no migration created |
| Runtime effective-privilege verifier would require widening | no change made |
| Remote IdP call inside UoW | no code created |
| Unrelated infrastructure affected | no |

## 8. Evidence and preserved state

- Baseline `./build.sh --qa`: 2394 passed, 90.89% coverage. `./build.sh --sec`: 0 findings.
- No file under `packages/`, no migration, no SQL, no test, and no route was modified.
- Migration head remains `0011`; `_MIGRATED_MUTATIONS` remains empty; the runtime EXECUTE manifest is unchanged.
- Baseline reconciliation: [PR19C_BASELINE_RECONCILIATION.md](PR19C_BASELINE_RECONCILIATION.md).
- Security review: [PR19C_SECURITY_REVIEW.md](PR19C_SECURITY_REVIEW.md).

**Disposition: BLOCKED — not DONE.** The PR is stopped pending the single human decision in §6; no scaffold was fabricated and no invariant was weakened.
