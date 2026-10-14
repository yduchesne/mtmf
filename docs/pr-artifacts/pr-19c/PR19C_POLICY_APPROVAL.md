# PR19C_POLICY_APPROVAL

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation.
**Date:** 2026-10-14.
**Base:** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db`; prior documentation STOP commit `ed206ab`.
**Authority:** human-approved design amendment `PR19C_AMENDMENT_01_APPROVED_POLICY_AND_CONCURRENCY.md` (2026-10-14).

## 1. Decision

The Phase 0 STOP (`BLOCKED: no approved exact Action for identity-to-group membership addition`) is superseded by an explicit human approval recorded in Amendment 01 §A. The exact Action is **newly approved by that decision**. The historical PR 19C STOP report and baseline reconciliation remain correct for their date and are preserved unchanged; the PR 10 Gate M seed decision is **not** retrospectively rewritten as though it had approved this Action.

## 2. Approved exact authorization policy (normative)

| Item | Exact value |
| --- | --- |
| Operation | Add an existing Identity to an existing Group in the same active ordinary Tenant |
| Action | `urn:mtmf:iam:actions:system:identity-group-membership:add-object` |
| Permission | `urn:mtmf:iam:permissions:system:identity-group-membership:add-object` |
| Match | Exact only, `ALLOW`; no wildcard, generic CRUD, or implicit grant |
| Sole built-in Role grant | `urn:mtmf:iam:roles:system:tenant-administrator` |
| Other ten built-in Roles | No new permission or grant |
| Additional guard | Acting Identity MUST equal the active Tenant's explicitly designated steward acting Identity, valid at authorization and at mutation time (stewardship-based alternate dominance for this one operation only) |
| Target | Existing, non-deleted Identity and Group eligible for the same active ordinary Tenant |
| Exclusions | No root, no cross-Tenant delegated management, no self-granted stewardship, no organization-scoped substitute, no alternate Identity of the same Principal, no manager-Tenant Role union |
| Audit | Exactly one durable atomic audit row for a newly inserted membership; duplicate/no-op inserts none |

Authorization is a conjunction: authenticated actor ∧ active Application/subscription ∧ active ordinary Tenant ∧ exact-Action `ALLOW` from the authoritative Authorizer ∧ current designated steward acting Identity ∧ valid same-Tenant target/subject. A Role grant never bypasses the steward guard; a designation never supplies the Permission.

## 3. Fixed implementation identifiers (local, not policy semantics)

Amendment §B authorizes the agent to choose routine local identifiers:

| Identifier | Value | Rationale |
| --- | --- | --- |
| Alembic revision | `0012_security_mutation_audit` (`down_revision = "0011"`) | next additive revision; single head preserved |
| Permission UUID | generated once, recorded in the migration and asserted by tests | deterministic, replay-safe |
| Permission `position` | `1` (existing `tenant:get-object` remains position `0`) | `permission_set` has `UNIQUE (permission_set_id, position)`; inspect at implementation |
| `target_kind` | `identity_group_membership` | matches the approved provenance registration |

## 4. Build gate satisfied

The §D concurrency proof passed before production edits; see [PR19C_CONCURRENCY_PROOF.md](PR19C_CONCURRENCY_PROOF.md). Implementation may proceed.
