# PR21_AMENDMENT02_DECISION_RECORD

**PR:** roadmap PR 21 — Amendment 02 (Final Security Policy Decisions)
**Status:** **P02–P06 are human-approved policy direction** for documentation of
future implementation. They authorize normative documentation, **not** runtime
authority, migrations, seeds, or grants. D1–D8 remain binding.

## 1. Approved decisions

### P02 — STOP-02: explicit pre-Tenant onboarding entitlement

- **Authority.** A separately provisioned, MTMF-controlled **Application
  onboarding entitlement**, keyed to the canonical registered `Application`
  UUID — never to an arbitrary OAuth client ID, user, Tenant, or service token.
  Its administrative issuer is an authenticated, explicitly authorized **system
  management authority** operating through a reviewed management/installation
  boundary; not a Tenant Administrator, consuming Application, or self-asserted
  root.
- **State.** `ACTIVE` or `REVOKED`; `REVOKED` is terminal, and re-granting
  requires a new grant record/identifier. Immutable grant provenance
  (issuer/operator, time, reason, approved policy version, operation/correlation
  ID), optional bounded validity, and append-only revocation history. The
  authoritative state lives in MTMF persistence, not in an IdP claim or
  consumer database. Exact table/function shape is deferred to PR 22/23; the
  authority and semantics are binding.
- **Use.** Only the **new verified global Identity** branch of
  `ResolveOrProvisionTenant`; not required for a read-only reuse branch. A valid
  service token and an independently verified user token are both necessary but
  insufficient. Requires active Application, trusted service binding, exact
  user audience/client binding, explicit entitlement, and any installation-level
  quota/abuse policy. No Tenant-membership prerequisite in this narrow branch.
- **Abuse.** Bounded per-Application rate and provisioning quotas; atomic quota
  reservation/check under concurrency; idempotency scoped to verified
  Application + user subject + operation; fail closed on unavailable
  entitlement/quota state; audit successful grants/revocations and provisioning.
  Initial quotas are operator policy, not invented constants. Revocation
  prevents new provisioning and does not silently revoke already-created Tenants.
- **Separation.** Not a Role, Permission, subscription, credential, or general
  system-management authority. It MUST NOT be implemented as a SYSTEM Role
  assignment without an explicit new human decision.

### P03 — STOP-03: exact Action and Role/Permission manifest

- The **principle** is approved: exact, operation-specific Actions; explicit
  scoped Permissions; additive versioned seeds.
- The previously proposed literal URNs are **not** assumed valid. Every literal
  must be reconciled against the canonical grammar, resource registry, approved
  action catalog, and immutable seed conventions.
- A complete candidate manifest is produced in
  `PR21_AMENDMENT02_ACTION_MANIFEST.md`.
- Existing approved URNs/grants are reused unchanged. Any **new literal URN,
  new built-in Role grant, new system-management Role, or change to the
  immutable revision `0006`/`0012` seed** that cannot be derived from an
  already-approved exact manifest remains **PENDING HUMAN APPROVAL**. Approving
  the manifest method does not approve the literals. **STOP-03 remains OPEN.**
- Default privilege mapping: Tenant Administrator may manage subscriptions for
  its own Tenant only through an explicitly approved exact Permission and
  existing dominance rules; system management authority is required for
  Application lifecycle, credential-binding administration, entitlement
  grant/revoke, and Application–Tenant registration; invitation authority is
  exact Tenant-scoped; acceptance uses the separate pre-membership capability
  seam. No wildcard, no auto-grant, no role escalation.

### P04 — STOP-04: Application–Tenant registration authority

- **Separate system-authorized registration** is the normal model. Only
  explicitly authorized system management authority may create/revoke an
  Application–Tenant registration. Tenant Administrators may independently
  approve/manage the **subscription** of their own Tenant only when an `ACTIVE`
  registration already exists. No implicit self-registration by the Application.
- **Initial-Tenant exception.** P02-entitled first-Tenant provisioning may
  create the **exact initial** registration and subscription in the same
  reviewed atomic onboarding transaction. The narrowly delegated composite
  authority is bound to the authenticated initiating Application and the newly
  created Tenant; it cannot register other Applications, existing Tenants, or
  SYSTEM/root. Its audit identifies the entitlement and both created records.
- An `ACTIVE` subscription without an `ACTIVE` registration is ineligible.
  Registration alone does not activate a subscription. Existing-Tenant
  subscription approval never grants registration authority. Operator-only
  PR 13 functions are not exposed to `mtmf_runtime` directly; future PRs design
  separately authorized audited runtime use cases/stored functions.

### P05 — STOP-05: terminal re-registration and re-subscription

- Preserve PR 13 exactly: Application `ACTIVE↔SUSPENDED`,
  `ACTIVE/SUSPENDED→RETIRED` (terminal); registration `ACTIVE→REVOKED`
  (terminal); subscription `PENDING→ACTIVE/CANCELLED`,
  `ACTIVE→SUSPENDED/CANCELLED/EXPIRED`,
  `SUSPENDED→ACTIVE/CANCELLED/EXPIRED` (`CANCELLED`/`EXPIRED` terminal);
  restrictive-only `ends_at`, immutable `starts_at`, historical records, unique
  current-row constraints.
- **Replacement is permitted only through a fresh record/UUID**, never by
  reactivating a terminal row. A `REVOKED` registration may be replaced only by
  system management authority. A `CANCELLED`/`EXPIRED` subscription may be
  replaced by a Tenant-scoped authorized subscription manager **only if an
  `ACTIVE` registration exists** and the Application/Tenant are eligible.
  Retired Applications cannot be reopened. No silent replacement, auto-renewal,
  or conflict-masking reconciliation.
- Replacements are explicitly requested, separately authorized, idempotent,
  concurrency-safe, and atomically audited with predecessor reference, reason,
  new UUID, actor, and correlation ID. If the schema cannot support this, PR 22/24
  reports the exact additive change; no schema edit here.
- `SUSPENDED→ACTIVE` is an **in-place permitted transition** where PR 13 allows
  and exact management authorization exists; it is not terminal replacement.
  Time-window expiry remains enforced.

### P06 — STOP-06: service credential binding separation

- Application registry lifecycle and OAuth service credential lifecycle are
  **separate operations and trust boundaries**. Creating an Application does not
  mint or bind OAuth credentials; subscribing a Tenant does not grant
  credentials. Only separately authorized system credential administration may
  add/revoke `(trusted issuer, client_id)→Application` bindings, with immutable
  identity/provenance, conflict detection, strict issuer/client/audience
  validation, and audit.
- The existing PR 14 verified service-binding trust boundary is preserved. No
  caller-supplied Application UUID, issuer, client ID, email, or unverified
  token can establish authentication. Credential rotation/revocation fails
  closed. Suspend/retire Application immediately fails the active-Application
  eligibility check even if an old credential remains cryptographically valid;
  retirement cleanup of credentials is not claimed atomic with an external IdP.
- Credential-binding management is a **separate future contract**. It is owned
  by PR 24 only if the approved PR 14 trust model supports it; otherwise a
  separately gated prerequisite is recorded with an exact owner and no fake
  endpoint. Raw client secrets never appear in Application create/PATCH
  requests or responses. No automatic IdP provisioning is implied.

## 2. Approval scope

- **Approved:** D1–D8 (Amendment 01) and P02–P06 policy direction.
- **Not approved:** exact Action URNs, exact Permissions, built-in/system Role
  grants, the entitlement table/function shape, quotas/numeric constants, and
  the credential-binding management contract (subject to STOP-03 and the
  PR 14 trust-model gate).
- P02–P06 authorize **documentation**; they do not create runtime authority.

## 3. Rationale vs alternatives

| Decision | Chosen | Alternative rejected |
| --- | --- | --- |
| P02 | MTMF-owned per-Application entitlement in MTMF persistence | IdP claim / consumer DB / system Role reuse without approval |
| P03 | Exact manifest, explicit human approval per literal | Assume Amendment 01 literals are valid |
| P04 | System registration + narrow first-Tenant composite exception | Tenant Administrator self-registration; implicit Application self-registration |
| P05 | Fresh-UUID replacement with separate authority + audit | Terminal reactivation; silent replacement |
| P06 | Separate credential administration | Application CRUD mints/binds credentials |

## 4. Non-negotiable invariants carried forward

- Two-token trust boundary, default DENY, SYSTEM/root isolation, exact
  Action/Permission model, stewardship invariants, stored-function-only writes,
  atomic mutation audit, PR 13 terminal lifecycle constraints, and PR 14
  verified credential binding.
- No production/executable change in PR 21; no endpoint claimed implemented.

## 5. References

- `PR21_AMENDMENT02_STOP_REPORT.md`, `PR21_AMENDMENT02_ACTION_MANIFEST.md`,
  `PR21_AMENDMENT02_AUTHORIZATION_MATRIX.md`.
- `PR21_AMENDMENT01_DECISION_RECORD.md` (D1–D8), `PR21_AMENDMENT02_BASELINE_RECONCILIATION.md`.
