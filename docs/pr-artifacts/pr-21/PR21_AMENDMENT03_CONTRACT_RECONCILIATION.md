# PR21_AMENDMENT03_CONTRACT_RECONCILIATION

**PR:** roadmap PR 21 — Amendment 03
**Status:** documentation-only reconciliation. Approved design; **not implemented**.

## 1. Manifest integrity

| Check | Result |
| --- | --- |
| Manifest rows present | **25** (contiguous 1–25) |
| Existing approved reused Action | 1 (row 1, `tenant:get-object`) |
| New Permission-backed operations | **20** |
| Admission-only identifiers (zero grants) | **2** (rows 2, 19) |
| Aliases | **2** (row 11 → row 8; row 17 → row 12) |
| Distinct new Permission URNs in the Role tables | **20** |

No Action/Permission/Role literal drift: the URNs, grant counts, and
admission-only distinction are unchanged from the frozen STOP-03 manifest.

## 2. Role composition (11/2/7)

| Role URN | Count | Composition |
| --- | --- | --- |
| `urn:mtmf:iam:roles:system:application-administrator` | **11** | 5 `application` + 3 `application-tenant-registration` + 3 `application-onboarding-entitlement` |
| `urn:mtmf:iam:roles:system:application-credential-administrator` | **2** | 2 `service-credential-binding` (PR 14 gate) |
| `urn:mtmf:iam:roles:system:tenant-administrator` (existing, additive) | **7** | 5 `application-subscription` + 2 `tenant-invitation` create/revoke, exact Tenant scope |
| **Total** | **20** | |

Admission-only zero-grant identifiers: `tenant:provision-object`,
`tenant-invitation:accept-object`. Existing `tenant:get-object` unchanged.

## 3. Current vs future implementation gates

| Operation group | Design status | Implementation status |
| --- | --- | --- |
| Row 1 Tenant resolve/inspect | APPROVED (existing) | Implemented (reused) |
| Rows 2, 19 admission markers | APPROVED DESIGN (zero grants) | NOT IMPLEMENTED — PR 22/23 and PR 25 admission seams |
| Rows 3–11 Application/registration | APPROVED DESIGN | NOT IMPLEMENTED — operator prerequisite (PR 24) |
| Rows 12–17 subscription | APPROVED DESIGN | NOT IMPLEMENTED — PR 24 (verified Tenant-scoped actor) |
| Rows 18, 20 invitation | APPROVED DESIGN | NOT IMPLEMENTED — PR 25 |
| Rows 21–23 entitlement | APPROVED DESIGN | NOT IMPLEMENTED — PR 22/23 persistence + PR 24 operator gate |
| Rows 24–25 credential binding | APPROVED DESIGN — IMPLEMENTATION GATED BY PR 14 | NOT IMPLEMENTED — PR 14 compatibility review first |

**Operator prerequisite (PR 24 or named predecessor):** operator sign-in,
SYSTEM-scope Role assignment, global-target authorization, and a privileged
audited execution adapter — none exist; no privileged `mtmf_runtime` grant,
Tenant-bound Authorizer bypass, or root impersonation.

## 4. Seed immutability

The approved additions are additive, versioned, idempotent, and fail-closed. The
immutable revision `0006`/`0012` definitions are **not** modified. Admission
markers must not receive a Role grant.

## 5. Link audit

All PR 21 artifacts and normative docs use repository-relative links; the
approval artifact `PR21_AMENDMENT03_HUMAN_APPROVAL.md` is referenced from the
STOP-03 decision, manifest, STOP reports, architecture, HTTP contract, and
roadmap. A deterministic link check is recorded in
`PR21_AMENDMENT03_ACCEPTANCE_REPORT.md`.

## 6. Approval provenance

`PR21-STOP03-APPROVAL-2026-10-15` — project owner (user, in ChatGPT
conversation), 2026-10-15, explicit conversational approval; no GitHub review or
signature is claimed. See
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md).
