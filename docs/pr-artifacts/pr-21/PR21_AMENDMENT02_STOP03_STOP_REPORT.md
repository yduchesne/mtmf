# PR21_AMENDMENT02_STOP03_STOP_REPORT

**PR:** roadmap PR 21 — Amendment 02 STOP-03 Authorization Approval Addendum
**Status:** **STOP-03 OPEN — PROPOSED, AWAITING HUMAN APPROVAL.** The design is
complete and internally consistent; the human approval is not recorded. PR 21
remains **NOT DONE**.

## 1. What is proposed (exact)

- **Two new SYSTEM Role URNs:** `urn:mtmf:iam:roles:system:application-administrator`
  (11 Permissions) and
  `urn:mtmf:iam:roles:system:application-credential-administrator`
  (2 Permissions).
- **Additive Tenant Administrator set:** `urn:mtmf:iam:roles:system:tenant-administrator`
  gains exactly 7 Permissions (5 subscription + 2 invitation), at exact Tenant
  scope.
- **Admission-only identifiers:** `tenant:provision-object` and
  `tenant-invitation:accept-object` carry **zero** Role/Permission grants.
- **Operator boundary:** identity, authority, execution, audit, and the explicit
  non-claim that no operator sign-in / SYSTEM-scope assignment /
  global-target authorization / privileged execution adapter exists today.

Exact detail: `PR21_AMENDMENT02_ACTION_MANIFEST.md` §3–§4,
`PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md`,
`PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`.

## 2. Why OPEN

No human approval record exists. A coding agent must not impersonate the
approver. Approving the manifest *method* (P03) does not approve the literals,
Roles, scope partitions, or the operator gate.

## 3. Required reviewer decisions

| # | Decision | Owner on approval |
| --- | --- | --- |
| D-a | Approve/amend all 25 manifest rows and the 11/2/7 partition | PR 22/24 |
| D-b | Approve the two new SYSTEM Role definitions | PR 22/24 |
| D-c | Approve the additive, idempotent, fail-closed seed migrations (no `0006`/`0012` mutation) | PR 22 |
| D-d | Approve the admission-only treatment of rows 2 and 19 | PR 22/25 |
| D-e | Approve or defer the operator sign-in / SYSTEM-scope assignment / global-target authorization / privileged execution gate | PR 24 or named prerequisite |
| D-f | Approve the credential-binding PR 14 compatibility gate | PR 24 |

## 4. Grounded conflict / gap

The current `Authorizer` binds a session to exactly one Tenant and accepts a
cross-Tenant target only through a TenantManagementGroup `management_scope`; the
`Role` object has no scope field. A global, Tenant-independent Application
target authorized as a SYSTEM-scoped operator is therefore **not representable
today**. This is documented as a future gate (not an implemented capability),
per the addendum's instruction, rather than redesigned. No STOP condition was
triggered: no URN collision, no Role-namespace impossibility, and no trust
invariant is contradicted; the gap is explicitly recorded.

## 5. Effect

- Amendment addendum documentation: **PASS** (see acceptance report).
- **STOP-03: OPEN.**
- PR 21: **NOT DONE.**

## 6. Resolution record

_No approval recorded. STOP-02/04/05/06 remain CLOSED and unchanged._
