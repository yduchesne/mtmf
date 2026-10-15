# PR21_CONTRACT_REVIEW

**PR:** roadmap PR 21 — Application-neutral onboarding architecture and API contracts
**Status:** review evidence. **No URN, Permission, Role grant, error code, or
migration proposed here is approved.** PRs 22–26 may implement only what a human
reviewer explicitly approves.

## 1. Exact Action-URN grammar reconciliation

The authoritative grammar is `docs/SECURITY_MODEL.md` §§14.3/15 and the parser
`packages/mtmf-core/src/mtmf_core/domain/iam_urn.py`:

```text
urn:mtmf:iam:actions:<definition-namespace>:<resource>:<verb>-<qualifier>
```

Observed rules (verified against the parser and tests):

- exactly three colon-separated components after `urn:mtmf:iam:actions:`:
  namespace, resource, operation;
- only the `system` definition namespace is supported for Actions/Permissions;
  a `tenant` Action namespace is rejected fail-closed;
- the operation uses the `<verb>-<qualifier>` form (the first `-` separates
  verb and qualifier; both non-empty);
- the resource and operation components MUST NOT contain a wildcard; Action
  URNs are exact;
- there is no finite verb vocabulary, but the verb MUST NOT be wildcarded;
- multi-hyphen resources are valid (`identity-group-membership`, `document`).

**No grammar conflict was found** for the conceptual capabilities in the
execution plan. The mapping below is a **proposal**, not an approved decision.
Every proposed Action must be registered through the sanctioned, additive,
human-approved seed path (the PR 19C pattern) — never a wildcard Permission and
never a runtime mutation.

### 1.1 Proposed mapping (UNAPPROVED)

| Conceptual capability | Proposed exact Action URN | Notes / conflict |
| --- | --- | --- |
| `tenant.provision` | `urn:mtmf:iam:actions:system:tenant:provision-object` | Grammar-valid. Chosen over the baseline `tenant:create-object` to make the distinct provisioning semantics (initial steward + activation) explicit per SECURITY_MODEL §15.1. `tenant:create-object` appears in `BASELINE_ACTIONS` (§15.2) but is **not** in the revision-`0006` seed, so nothing currently conflicts. |
| `tenant.resolve` | `urn:mtmf:iam:actions:system:tenant:get-object` | **Already seeded** (revision `0006`) and granted to the Tenant Administrator. Reuse with an operation-specific authorized-scope guard; no global enumeration. Alternative if distinct semantics are required: `tenant:resolve-object`. |
| `application_subscription.manage` | `urn:mtmf:iam:actions:system:application-subscription:manage-object` | Grammar-valid. If create/change-state/remove later acquire distinct dominance or audit semantics, split into `add-object` / `update-object` / `delete-object`. |
| `tenant_invitation.create` | `urn:mtmf:iam:actions:system:tenant-invitation:create-object` | Grammar-valid; new resource. |
| `tenant_invitation.revoke` | `urn:mtmf:iam:actions:system:tenant-invitation:revoke-object` | Grammar-valid. |
| `tenant_invitation.accept` | `urn:mtmf:iam:actions:system:tenant-invitation:accept-object` | Grammar-valid. Acceptance admission is **pre-membership** (see `docs/ONBOARDING_ARCHITECTURE.md` §5.2); it is not evaluated through the ordinary already-member actor path. |

### 1.2 Manifest / built-in Role reconciliation

- The revision-`0006` built-in seed owns exactly 11 SYSTEM Roles, 11 ALLOW
  PermissionSets, 11 exact Permissions, and 3 shared Actions
  (`tenant:get-object`, `role:get-object`, `organization:get-object`).
- `mtmf.builtin_role` plus the `role_save` guard prevent ordinary runtime
  mutation of built-in definitions. Adding a Permission to a built-in Role is an
  **additive, idempotent, fail-closed, human-approved** seed step (as PR 19C did
  in revision `0012`), never a runtime write and never a wildcard.
- Registering a new Action URN is not itself a grant: an exact ALLOW Permission
  and a Role assignment are still required, and the `Authorizer` remains
  deny-by-default.
- **Proposed, unapproved:** grant the Tenant Administrator Role the exact
  invitation-create/revoke Permissions, and introduce a **separate** approved
  operator provisioning authority Role for `tenant:provision-object` and
  `application-subscription:manage-object`. The concrete Role/Permission
  composition requires explicit human approval before PR 22 seeds anything.

### 1.3 `VerifiedMutationProvenance` registration

Each future mutation MUST register a closed `target_kind` → exact-Action-URN
entry in `packages/mtmf-core/src/mtmf_core/application/mutation_provenance.py`
(currently only `identity_group_membership` →
`...:identity-group-membership:add-object`). An unregistered pairing fails
closed (`UnregisteredMutationError`). PR 22–25 own the additions.

## 2. Error-catalog reconciliation

The frozen PR 15 catalog (`packages/mtmf-api/src/mtmf_api/errors.py`) currently
contains **no** `404`, `409`, or `410` code. The onboarding contract needs:

| Needed category | Current catalog | Additive change required |
| --- | --- | --- |
| Malformed request | `INVALID_REQUEST` (400) | none |
| Invalid service token | `UNAUTHENTICATED` (401) | none |
| Unauthorized user/scope | `UNTRUSTED_ACTOR`/`INELIGIBLE_APPLICATION`/`FORBIDDEN` (403) | none |
| Invisible target (no enumeration) | — | new opaque `NOT_FOUND` (404) |
| Idempotency/conflicting state | — | new `CONFLICT` (409) |
| Expired/revoked invitation | — | new `GONE` (410) **only if safe to disclose** |
| Rate limit | `RATE_LIMITED` (429) | none |
| IdP/DB unavailable | `DEPENDENCY_UNAVAILABLE` (503) | none |

Any new code MUST be additive, static-message, and preserve the existing PR 15
wire semantics; PR 24/25 own the catalog change. Do not mutate an existing code
or its status in place.

## 3. `tenant_key` persistence reconciliation

- `mtmf.tenant` on baseline head `0013` has **no** immutable semantic key and no
  idempotency store. `Tenant.name` is mutable, non-unique presentation metadata
  and MUST NOT be used to deduplicate.
- Proposed grammar: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, case-sensitive, no
  whitespace, no name fallback.
- **New persistence requirement:** an immutable provisioner-scoped
  `(provisioning authority, tenant_key)` uniqueness constraint plus a durable
  idempotency table. PR 22 owns the migration. If any compatible immutable
  semantic key already exists at implementation time, reuse it and document its
  unique constraint instead of adding a second key.

## 4. Open questions requiring a human decision

| ID | Question | Owner | Blocking? |
| --- | --- | --- | --- |
| ~~**STOP-01**~~ | **CLOSED (Amendment 01, D8): Option B pre-Tenant admission direction approved.** | Human | — (see STOP-02…STOP-06) |
| Q2 | Approve the exact Action URNs in §1.1 (or amend them) | Human reviewer | Blocks PR 22 seeding |
| Q3 | Approve the Role/Permission composition for onboarding Actions | Human reviewer | Blocks PR 22–25 seeding |
| Q4 | Confirm the `tenant_key` grammar and unique scope | PR 22 | No |
| Q5 | Invitation capability default expiry (bounded 15 min–7 days) and single-use semantics | PR 25 | No |
| Q6 | Which PR makes the additive 404/409/410 catalog change | PR 24/25 | No |
| Q7 | Durable idempotency fingerprint canonicalization and scope | PR 22 | No |
| Q8 | Pre-membership invitation-acceptance admission seam shape | PR 25 | No |
| Q9 | Whether `tenant:get-object` can safely serve resolve-by-key without enumeration | PR 24 | No |

## 5. Cross-references

- `docs/ONBOARDING_ARCHITECTURE.md`, `docs/ONBOARDING_HTTP_CONTRACT.md`.
- `PR21_SECURITY_MATRIX.md` (C01–C36) and `PR21_AMENDMENT01_SECURITY_CASES.md` (A01–A24).
- `PR21_AMENDMENT01_DECISION_RECORD.md` (D1–D8),
  `PR21_AMENDMENT01_STOP_REPORT.md` (STOP-02…STOP-06).


---

## Amendment 02 update (2026-10-15)

STOP-01 was closed by Amendment 01 (D8). **Amendment 02 closes STOP-02, STOP-04,
STOP-05, and STOP-06 (P02/P04/P05/P06).** The open item is now **STOP-03**: the
exact Action/Permission/Role manifest, for which a review-ready candidate table
(grammar-validated, per-row status) is in
[PR21_AMENDMENT02_ACTION_MANIFEST.md](PR21_AMENDMENT02_ACTION_MANIFEST.md). No
new literal or grant is approved. The §1.1 proposals here are superseded by that
manifest and remain UNAPPROVED.


---

## STOP-03 addendum cross-reference (2026-10-15)

The §1.1 candidate literals are superseded by the exact proposed manifest and
Role partition in
[PR21_AMENDMENT02_ACTION_MANIFEST.md](PR21_AMENDMENT02_ACTION_MANIFEST.md) and
[PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md](PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md).
All new literals remain `PROPOSED — AWAITING HUMAN APPROVAL`.


---

## Amendment 03 closure (2026-10-15) — preserve history

**STOP-03 is CLOSED by recorded human approval** (`PR21-STOP03-APPROVAL-2026-10-15`):
the exact 25-row manifest, the 11/2/7 Role composition, the two admission-only
zero-grant identifiers, the additive seed plan, the PR 14 credential-binding
gate, and the operator boundary (deferred prerequisite). Provenance:
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md).
All earlier `OPEN`/`AWAITING` statements in this file are historical; nothing is
implemented and PRs 22–26 own implementation.
