# PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY

**Status:** **APPROVED (deferred implementation prerequisite) — NOT IMPLEMENTED.**
The operator boundary was approved as design by
`PR21-STOP03-APPROVAL-2026-10-15` (see
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md));
its implementation is deferred to PR 24 (or a named predecessor). Documents the
exact
system-operator boundary for STOP-03. Documentation only; nothing here is
implemented.

## 1. Exact six-point operator contract

1. **Operator identity.** An independently verified human/system administrator
   principal authenticated by the existing approved MTMF operator/root
   mechanism. Service client credentials alone never qualify. The identity must
   resolve to a canonical Principal.
2. **Authority.** Evaluate an explicitly assigned, effective SYSTEM-scoped Role
   with the exact Action Permission and the existing scope/dominance rules. An
   unassigned Role definition conveys no authority. The canonical root remains
   subject to its documented special protected rules; no root impersonation or
   implicit fallback.
3. **Execution.** For v0.1, registry/entitlement/credential mutations remain
   **privileged administrative operations**. The future HTTP route is **not
   authorized for exposure** merely because its Action URN is approved. A future
   PR must specify and test a trusted, audited operator execution adapter that
   preserves `mtmf_runtime` privilege separation, or retain an operator-only
   interface. Privileged DB functions are never granted to the runtime account.
4. **Tenant administrative operations.** A verified user must hold the exact
   effective Tenant Administrator grant in the target Tenant. The Application
   service token is independent transport authentication and never substitutes
   for the actor.
5. **Audit.** Record canonical operator/actor, exact Action, target
   Application/Tenant, old/new lifecycle states, correlation/idempotency
   identifier, decision, and privileged executor identity as appropriate. Never
   log raw credentials or tokens.
6. **No current implementation claim.** Where verified code lacks operator
   sign-in, Role assignment, or a privileged execution adapter, the HTTP
   management surface remains **gated** and implementation is assigned to
   PR 24 (or an explicitly approved prerequisite). No route is created in PR 21.

## 2. Actor-type separation

| Actor | Proves | Does NOT prove |
| --- | --- | --- |
| System operator (human admin principal) | an operator identity, when authenticated by the approved operator/root mechanism | a Tenant membership, a specific Action, or a global resource authority by itself |
| Tenant Administrator | an effective, exact Tenant-scoped grant in one Tenant | global Application/registration/entitlement/credential authority |
| Application service identity (service token) | exactly one registered Application | a user, operator, Tenant, or Permission |
| Pre-Tenant onboarding entitlement | entitlement to first-Tenant provisioning for the new-Identity branch of one Application | a Role, subscription, or any other operation |
| Invitation recipient | a verified `(issuer, subject)` intended recipient plus a single-use capability | Tenant membership before acceptance or any Role |

## 3. Inventory — exists vs future gate (source-grounded)

Verified on branch tip `8c5937d` / base `455ae7a`:

| Piece | State | Evidence |
| --- | --- | --- |
| Two-token verified actor composition for an existing Tenant | EXISTS | `application/authentication.py` `AuthenticatedActorContextService.resolve` |
| Application/registration/subscription registry persistence (operator-only mutation) | EXISTS (PR 13) | `sql/v010/02..03`; `mtmf_runtime` not granted |
| Credential-binding persistence (operator-only add/revoke; runtime find-active) | EXISTS (PR 14 dev scope) | `sql/v011/01..03` |
| First authenticated/authorized management mutation (membership add) | EXISTS (PR 19C) | `application/management_memberships.py`, `sql/v012` |
| `Authorizer` same-Tenant evaluation and TenantManagementGroup cross-Tenant delegation | EXISTS | `authorization/authorizer.py`, `application/management_authorization.py` |
| Global, Tenant-independent Application target authorization as a SYSTEM-scoped operator | **NOT PRESENT** | `AuthorizationContext` is Tenant-bound; `AuthorizationRequest` accepts cross-Tenant only via `management_scope`; no scope field on `Role` |
| Operator sign-in / canonical operator principal resolution | **NOT PRESENT** | no operator authentication path found in `packages/**` |
| Assignment of the proposed SYSTEM Roles to an operator principal | **NOT PRESENT** | assignments are Tenant-bound (`IdentityRoleAssignment`/`GroupRoleAssignment`); no global operator assignment mechanism |
| Privileged operator execution adapter for global registry/entitlement/credential mutations | **NOT PRESENT** | no route/adapter; mutations are operator/installation-only stored functions |
| Entitlement persistence | **NOT PRESENT** | no table/domain type (PR 22/23) |

## 4. Consequences for exposure

- Because no operator sign-in, SYSTEM-scope assignment, or global-target
  authorization mechanism exists, the proposed Application Administrator /
  Application Credential Administrator operations are **NOT EXECUTABLE** as
  HTTP operations today.
- The future HTTP surface for rows 3–11 and 21–25 is therefore
  **NOT IMPLEMENTED / OPERATOR-EXECUTION GATED** until PR 24 (or a named
  prerequisite) designs and tests:
  1. an operator principal authentication path;
  2. a Role-assignment mechanism for the SYSTEM Roles (or an equivalent approved
     authority model);
  3. a global-target authorization representation (or an explicitly approved
     adapter) that preserves Tenant isolation; and
  4. a privileged, audited execution adapter that does not grant privileged
     functions to `mtmf_runtime`.
- Tenant subscription/invitation routes (rows 12–18, 20) require a verified
  actor context with the exact Tenant-scoped grant; they are future PR 24/25 and
  are not executable today either.
- The admission markers (rows 2, 19) use specialized admission seams (PR 22/23
  and PR 25) and never ordinary Role authorization.

## 5. Root / SYSTEM protected resources

The canonical root/SYSTEM resources remain protected. Ordinary onboarding,
Application subscription, and management never operate on them. The operator
boundary does not create a root impersonation path, and root recovery remains
the separate production release gate.

## 6. Gate

No privileged HTTP exposure is authorized by this addendum. Closing STOP-03
requires the human approval in
`PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md` plus an explicit decision on
the operator/Role-assignment/execution gate (approve a named future owner, or
record it as a separately gated prerequisite with no fake endpoint).
