# PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION

**Status:** **APPROVED — HUMAN DECISION RECORDED 2026-10-15.**
This is the exact authorization contract for STOP-03. It is a documentation
decision only; no Action, Permission, Role, or grant is created. (Original
proposal status prior to 2026-10-15 was `PROPOSED — AWAITING HUMAN APPROVAL`;
that history is retained below.)

## 1. URN rule

For every new Action: `urn:mtmf:iam:actions:system:<resource>:<verb>-object`.
For ordinary Permission-backed operations the Permission mirrors the Action
under `urn:mtmf:iam:permissions:system:`. The existing `tenant:get-object`
Action/Permission is unchanged. No alternate names, aliases, or wildcard
variants.

`system` is the **definition namespace**, not a license for SYSTEM-scope
execution. Tenant subscription and invitation grants are **Tenant-scoped**.

## 2. Exact operation matrix

| Rows | Resource | Operations | Authorization decision |
|---|---|---|---|
| 1 | `tenant` | `get-object` (existing) | Existing approved Tenant-scoped grants only; do not reseed |
| 2 | `tenant` | `provision-object` | **Admission marker only:** active per-Application onboarding entitlement + independently verified new Identity; no Role/Permission grant |
| 3–7 | `application` | `create-object`, `get-object`, `suspend-object`, `resume-object`, `retire-object` | SYSTEM-definition `application-administrator` |
| 8–11 | `application-tenant-registration` | `add-object`, `get-object`, `revoke-object` | `application-administrator`; replacement reuses `add-object` |
| 12–17 | `application-subscription` | `add-object`, `get-object`, `suspend-object`, `resume-object`, `cancel-object` | Existing Tenant Administrator, **exact Tenant scope**; replacement reuses `add-object` |
| 18,20 | `tenant-invitation` | `create-object`, `revoke-object` | Existing Tenant Administrator, **exact Tenant scope** |
| 19 | `tenant-invitation` | `accept-object` | **Admission marker only:** verified intended recipient + valid single-use capability; no Role/Permission grant |
| 21–23 | `application-onboarding-entitlement` | `grant-object`, `revoke-object`, `get-object` | `application-administrator` |
| 24–25 | `service-credential-binding` | `add-object`, `revoke-object` | `application-credential-administrator`, **PR 14 compatibility gate** |

Exact Role URNs:
- `urn:mtmf:iam:roles:system:application-administrator`
- `urn:mtmf:iam:roles:system:application-credential-administrator`

Exact grant composition (see `PR21_AMENDMENT02_ACTION_MANIFEST.md` §4):
- `application-administrator`: exactly 11 Permissions (5 `application` +
  3 `application-tenant-registration` + 3 `application-onboarding-entitlement`).
- `application-credential-administrator`: exactly 2 `service-credential-binding`
  Permissions.
- Existing `urn:mtmf:iam:roles:system:tenant-administrator`: additive 7
  Permissions (5 `application-subscription` + 2 `tenant-invitation`
  create/revoke), enforced at the **exact same Tenant**.
- `tenant:get-object`: no change.
- `tenant:provision-object` and `tenant-invitation:accept-object`: **no Role
  grant and no ordinary Permission assignment** (dormant exact Permission with
  zero grants if the catalog requires a row).
- No automatic assignment of either new SYSTEM Role to root, operator,
  Application, Tenant Administrator, or any principal; Role assignment is a
  separately authorized verified operation, and if none exists it is
  **BLOCKED** (not invented).

**Scope check (grounded).** `Role` has no scope field; `SecurityScope` is
`ROOT/SYSTEM/TENANT/ORGANIZATION`; the current `Authorizer` binds a session to
exactly one Tenant and permits a cross-Tenant target only via a positively
resolved TenantManagementGroup `management_scope`. A global, Tenant-independent
`application` target as a SYSTEM-scoped operator is **not representable today**;
the operator authorization and privileged execution are a future gate
(`PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`). Tenant-scoped grants MUST NOT
be evaluated as SYSTEM-wide authority.

## 3. System-operator authentication and execution contract

1. **Operator identity:** independently verified human/system administrator
   principal authenticated by the existing approved MTMF operator/root
   mechanism; service client credentials alone never qualify; the identity
   resolves to a canonical Principal.
2. **Authority:** an explicitly assigned, effective SYSTEM-scoped Role with the
   exact Action Permission and existing scope/dominance rules. An unassigned
   Role definition conveys no authority. The canonical root remains subject to
   its documented protected rules; no root impersonation or implicit fallback.
3. **Execution:** for v0.1, registry/entitlement/credential mutations remain
   **privileged administrative operations**. The future HTTP route is **not
   authorized for exposure** merely because its Action URN is approved. A future
   PR must specify and test a trusted, audited operator execution adapter
   preserving `mtmf_runtime` privilege separation, or retain an operator-only
   interface. Do not grant privileged DB functions to the runtime account.
4. **Tenant administrative operations:** a verified user must hold the exact
   effective Tenant Administrator grant in the target Tenant; the service token
   is independent transport authentication and never substitutes for the actor.
5. **Audit:** canonical operator/actor, exact Action, target
   Application/Tenant, old/new lifecycle states, correlation/idempotency
   identifier, decision, and privileged executor identity as appropriate. No raw
   credentials/tokens.
6. **No current implementation claim:** where verified code lacks operator
   sign-in, Role assignment, or privileged execution adapter, the HTTP
   management surface remains **gated** and implementation is assigned to
   PR 24 (or an explicitly approved prerequisite), with no route created here.

## 4. Admission-path contracts

**New-Identity provisioning.** Independently validate the Application token and
signed user proof; confirm the global `(issuer, subject)` Identity does not
already exist; confirm an ACTIVE Application and ACTIVE per-Application
onboarding entitlement; enforce atomic quota/idempotency; create only the first
ordinary Tenant and that Application's initial registration/subscription in one
real transaction; audit `tenant:provision-object`. The entitlement is not a Role
and permits no other operation. PR 22/23 persistence and PR 24 transport own
implementation.

**Invitation acceptance.** Verify signed recipient proof, exact recipient
binding, valid nonexpired and unused capability, and intended Tenant; consume the
capability and create only the approved membership atomically; audit
`tenant-invitation:accept-object`. Do not require a preexisting Tenant Role and
do not issue one to pass authorization. PR 25 owns implementation.

## 5. Future additive seed rule

A future implementing PR must seed exact Actions/Permissions and Role
definitions/grants with versioned migrations and explicit manifest tests; all
grants additive and immutable under the established seed-protection design. The
two admission markers must not result in a Role grant. Credential-binding Action
implementation must pass the PR 14 trust-boundary review first. This addendum
only documents this future contract.

## 6. Approval checklist (human reviewer)

- [x] Approve/amend all PROPOSED literals in the manifest §3. — **APPROVED 2026-10-15**
- [x] Approve the two new SYSTEM Role URNs and the exact 11/2/7 composition. — **APPROVED 2026-10-15**
- [x] Approve the additive seed migration plan (no `0006`/`0012` mutation). — **APPROVED 2026-10-15**
- [x] Approve admission-only treatment of rows 2 and 19 (zero grants). — **APPROVED 2026-10-15**
- [x] Approve the operator boundary and the Role-assignment/privileged-execution
      gate. — **APPROVED 2026-10-15 as a deferred implementation prerequisite,
      NOT IMPLEMENTED** (PR 24 or a named predecessor).
- [x] Approve the `application-credential-administrator` PR 14 compatibility
      gate. — **APPROVED 2026-10-15 (implementation gated by PR 14 review).**

**Reviewer:** Project owner (user, in ChatGPT conversation)
**Date:** 2026-10-15
**Decision:** APPROVED
**Evidence / reference:** [`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md)
(`PR21-STOP03-APPROVAL-2026-10-15`); explicit conversational approval, not a
GitHub review or signature.

**Status now:** `APPROVED — HUMAN DECISION RECORDED 2026-10-15`. The operator
sign-in, SYSTEM-scope assignment, global-target authorization, and privileged
execution adapter remain **NOT IMPLEMENTED** future prerequisites.
