# PR 10 architecture decisions: resolving the implementation STOP gates

**Status:** Proposed normative design amendment for review. Documentation only; no implementation or privilege grant is implied.  
**Applies to:** PR 10 — Bootstrap, root invariants, and Tenant Stewardship.  
**Read first:** [Root Administration and Tenant Stewardship](ROOT_AND_STEWARDSHIP.md), [Security Model](SECURITY_MODEL.md), [Domain Model](DOMAIN_MODEL.md), [Authorization](AUTHORIZATION.md), [Database Architecture](DATABASE.md).

## Why this decision record exists

MTMF must never allow a customer Tenant to lose its designated steward, or its system root to become silently replaceable. The PR 10 coding agent correctly stopped because the earlier implementation plan had not settled six decisions. This document specifies the intended behavior in human terms, then defines the constraints an implementation must satisfy. **The six gates are design-resolved by this proposal, not implementation-complete.** Any discrepancy with existing code is an implementation task, not permission to weaken the contract.

### A concrete example

Acme is an ordinary Tenant. Pat is its steward Principal and uses Identity A to exercise stewardship. Pat also owns Identity B. Both Identities may have ordinary administrative Roles, but **only Identity A** is explicitly designated to exercise stewardship dominance. If Pat leaves, an authorized transfer names both the next steward Principal and that Principal's eligible Identity. Until the transfer commits, Pat remains steward; an unsuccessful transfer does not create an administratorless Tenant.

## Decision summary

| Gate | Decision | Boundary |
|---|---|---|
| STOP-01: privileged identity | Separate deployment installation authority, verified application actor context, and database structural enforcement. Never trust a supplied actor UUID as authentication. | No ordinary runtime grant for bootstrap, root recovery, or transfer before a trustworthy authorization boundary exists. |
| STOP-02: built-in Roles | Explicit SYSTEM-owned Role definitions with reviewed, narrow action permissions; stewardship is never a Role. | No catch-all or implicit root ALLOW. |
| STOP-03: local Identity | Explicit immutable `IdentityOrigin` classification (`LOCAL`, `FEDERATED`) independent of names. | No invented password or IdP integration. |
| STOP-04: Tenant lifecycle | Ordinary Tenant states `PROVISIONING`, `ACTIVE`, `SUSPENDED`; only ACTIVE is authorizing. | Root Tenant is established ACTIVE during bootstrap and cannot be suspended. |
| STOP-05: transaction | Enforce root/steward invariants at all write paths under deterministic locks and one transaction; no invalid committed state. | Existing SQL functions included. |
| STOP-06: recovery | Authorized SYSTEM recovery transfer for ordinary Tenants; separate operator-controlled root recovery. | No public reset endpoint or broad runtime capability. |

## STOP-01 — Who is allowed to perform privileged operations?

Three different concepts must not be confused:

1. **Installation authority** is a deployment/operator capability used for first bootstrap and exceptional root recovery. It is not an MTMF end-user session, and it does not arise from holding a Tenant Role. Bootstrap must run only through a separately controlled installation path with credentials unavailable to ordinary MTMF runtime connections.
2. **Application actor authority** is a verified, authenticated acting Identity, Tenant, and Principal context established by a trusted application boundary. The authorization layer validates membership, effective Roles, exact Permission, scope, and steward designation. The caller must not be able to assert its own trusted actor by passing IDs.
3. **Database structural authority** ensures that even a call through an allowed stored function cannot leave root or steward state invalid. The shared `mtmf_runtime` login is not an end-user authentication proof.

**Delivery rule:** PR 10 may implement pure authorization policies, structural validators, migration constraints, and non-runtime-granted privileged stored functions. It MUST NOT expose a transfer/recovery/bootstrap capability through the shared runtime credential or an HTTP route unless a reviewed, verifiable authenticated actor boundary and controlled invocation path are actually implemented and tested. An internal Python method accepting arbitrary `actor_identity_id` is not such a boundary. If the trusted service boundary is deferred to PR 14, privileged operations remain **implemented but inaccessible to ordinary runtime callers**; PR 10 cannot claim end-to-end user-initiated transfer support.

**Non-goal:** implementing OAuth, OIDC, password authentication, IdP federation, or a complete HTTP service in PR 10. Those are separate security-sensitive integration work; no temporary trust bypass is permitted.

## STOP-02 — What do the built-in Roles grant?

Role definitions are SYSTEM-owned and distinct from a Principal's root status and from stewardship. PR 10 must create the existing documented built-in Role names and their explicit PermissionSet/Permission relationships. A Role grants only reviewed actions, not a blanket wildcard over every namespace or resource.

**Minimum administrative action policy for PR 10:**

| Role | Exact allowed action intent | Explicit exclusions |
|---|---|---|
| System Administrator | `tenant:recover-stewardship` for an ordinary Tenant; `tenant:create` / `tenant:activate` for authorized provisioning; `tenant:read` for necessary administrative inspection. | No root transfer, root deletion, bootstrap, credential reset, or implicit all-Tenant application-data access. |
| Tenant Administrator | `tenant:transfer-stewardship` for the steward's own Tenant; `tenant:read` for its Tenant; scoped administration of Tenant membership and Role assignments **only when separately specified in the existing Action catalog and permitted by dominance rules**. | No SYSTEM recovery, cross-Tenant mutation, root mutation, or implicit stewardship designation. |

**Important catalog rule:** the labels above express intended action semantics, not authorization to invent arbitrary URN grammar. Before seeding, the implementation must reconcile exact Action URNs with `SECURITY_MODEL.md` §15–16 and the existing Action catalog, and document a complete, explicit mapping: Role URN → PermissionSet URN → Permission URN → Action match/effect. Only defined operations may be seeded; if an operation is not defined, omit its Permission and keep its entry point inaccessible. Do not silently grant `*:*` or generic root ALLOW. Permission DENY, specificity and dominance continue to apply. Seeding must be deterministic and idempotent, with conflict detection on incompatible preexisting definitions.

**Mandatory implementation hold:** a human reviewer must approve the concrete Role/Permission manifest before any migration seeds it. This is an approval checkpoint, not permission for the coding agent to guess.

## STOP-03 — How do we know an Identity is local?

Add an explicit **IdentityOrigin** classification with `LOCAL` and `FEDERATED` values. It is a stable identity attribute, not inferred from username, email, Identity UUID, issuer-shaped text, or external login availability. PR 10 schema migration must preserve existing Identities without falsely classifying them: use a migration/backfill policy that distinguishes genuinely known origins from legacy unknowns. **Do not default all legacy Identities to LOCAL.** Legacy unknown origin must remain non-eligible for protected root-local continuity until verified by a privileged operator.

A Principal must retain at least one local MTMF Identity as required by the Security Model. For the root Principal, the **designated** root acting Identity must be LOCAL, active, belong to root Principal, and have explicit valid root-Tenant Identity membership. Replacing it requires privileged atomic replacement; the old one remains valid until the replacement is committed.

This classification is **not** a password store, an authentication implementation, or evidence that a human can sign in. Local credential enrollment and rotation require a separate, explicitly authenticated design.

## STOP-04 — What does an active Tenant mean?

For ordinary Tenants, introduce the explicit lifecycle:

- **PROVISIONING:** initial setup; may temporarily lack a steward or administrative Role assignments. No user session or Tenant authorization may succeed.
- **ACTIVE:** only after an eligible ACTIVE steward Principal, one designated eligible acting Identity, required memberships, and reviewed Tenant Administrator assignment(s) are present. The Tenant must retain these invariants throughout its ACTIVE lifetime.
- **SUSPENDED:** Tenant is not authorizing, but its stewardship records are retained and cannot be casually rewritten. Resuming to ACTIVE requires full revalidation.

Permitted ordinary transitions: `PROVISIONING → ACTIVE`, `ACTIVE → SUSPENDED`, `SUSPENDED → ACTIVE`; other transitions require a separately specified administrative lifecycle operation. Soft deletion remains separate and never means ACTIVE. The root Tenant is created ACTIVE at bootstrap and cannot be suspended, demoted, or soft-deleted.

**Authorization rule:** a PROVISIONING or SUSPENDED Tenant fails closed for ordinary Tenant sessions, even if its Role and membership rows still exist. Any privileged provisioning/resumption operation must use a trusted administrative boundary and a transaction that validates eligibility before ACTIVE becomes visible. A generic repository update must not bypass this transition rule.

**Legacy data:** an existing ordinary Tenant without authoritative stewardship must not be silently classified ACTIVE during migration. Choose a conservative, explicit migration state and provide a reviewed activation path; no implicit steward inference from creator or existing Role assignments.

## STOP-05 — How are invariants guaranteed under concurrent writes?

PR 10's PostgreSQL migration (next additive revision after current head) must install authoritative root registry, steward designation and lifecycle/origin representation as appropriate, with reviewed constraints, restrictive runtime grants, and enforcement across **every existing and new write path** that could invalidate protected state.

Required transaction contract:

1. Acquire locks in a documented global order (Tenant/root registry first, then affected Principal/Identity/membership/assignment rows); serialize conflicting transfers, revocations, membership removals, and lifecycle transitions.
2. Validate trusted actor authorization at the application boundary; validate structural eligibility inside the database at mutation/commit boundary.
3. Update steward Principal and designated Identity as one atomic state transition, preserving exactly one valid designation for ACTIVE Tenants.
4. Reject revocation, deactivation, soft deletion, scope change, membership removal, Role policy mutation, or Tenant activation that would break protected invariants, including calls through pre-PR-10 functions.
5. Append an operation-level audit entry for successful stewardship transfer/recovery; failed operations leave no committed audit. Never treat audit actor IDs as proof of authentication.
6. Fail closed on stale expected steward/designation (compare-and-swap or equivalent), concurrent conflicts, and corrupted bootstrap state.
7. Ensure a runtime login cannot bypass constraints with direct table writes or call a privileged function that the application has not securely authorized.

PostgreSQL constraints alone may not express cross-row invariants. Use reviewed guard functions/triggers, locks, and/or deferred validation as appropriate; test actual commit behavior. Application-only checks are insufficient. Preserve PR 6B compact membership-removal audit semantics and PR 9 Role-assignment foreign-key restrictions.

## STOP-06 — What happens if administrators lose access?

**Ordinary Tenant recovery:** a SYSTEM administrator with verified authenticated acting Identity, applicable SYSTEM authorization, and explicit recovery Permission may designate a qualified successor Principal and its eligible acting Identity. This is not self-promotion by a Tenant delegate. Record prior/new stewardship, verified actor, reason, and time. If the trusted actor boundary is not yet available, this operation stays inaccessible.

**Root recovery:** a separate deployment/operator procedure using protected installation/recovery credentials; never a normal Role Permission, unauthenticated HTTP route, or general runtime stored function. It must retain the same canonical root Principal and Tenant, protected membership and immutable ownership; any root acting-Identity replacement must be atomic and audited. Production deployments must define credential custody, emergency approvals, logging and verification before enabling recovery. Dual control is recommended but is an operational policy choice, not a fictitious implemented guarantee.

**Corrupted state:** reject mutation and surface an integrity diagnostic. Do not auto-create a new root Principal, auto-promote another steward, or silently convert a FEDERATED Identity into LOCAL.

## Execution checkpoints for a revised PR 10 plan

1. **Inventory current code and migration head** on main, including every write path affecting Tenants, Principals, Identities, memberships, Role assignments and Role policy. Reuse existing names and conventions; do not assume the structural slice from the stopped agent has been committed.
2. **Approve the explicit built-in Permission manifest** and legacy origin/lifecycle migration policy before writing seed or data-changing migration SQL.
3. **Implement domain types and structural validation** with focused unit tests. Treat validators as structural only, not authentication or authorization.
4. **Implement additive schema and protective guards**, then verify the actual restricted runtime login and privilege manifest.
5. **Implement serialized, idempotent installation bootstrap** through a deployment-only authority path.
6. **Implement ordinary Tenant provisioning/activation and stewardship designation/transfer** only through a trusted actor boundary; if unavailable, leave privileged write entry points non-runtime-granted and mark end-to-end operations deferred.
7. **Test adversarial concurrency, rollback, corruption, stale transfers, cross-Identity and cross-Tenant escalation, privilege bypass, and legacy migration** against real PostgreSQL.
8. **Run canonical QA, security, integration and Rust gates** and report precisely what is implemented versus intentionally inaccessible.

### Completion and reporting rules

A design decision marked resolved here does **not** mean the corresponding feature is delivered. A coding agent must report independently for each gate: (a) design resolved, (b) structural implementation, (c) trusted invocation available, (d) real PostgreSQL evidence, and (e) end-to-end availability. Do not mark PR 10 DONE while its stated acceptance contract requires unavailable privileged operations. If a required boundary cannot be built safely in PR 10, split a clearly named prerequisite implementation PR rather than weakening the contract.

## Explicitly still open outside these six decisions

The full administrative Permission manifest and migration of legacy unknown-origin Identities require **reviewed concrete artifacts**, not guesswork. HTTP authentication/OAuth/IdP integration, service-to-service authentication, TenantManagementGroup actor eligibility, Principal service/agent kinds, and detailed operational root recovery approvals remain separate work. This document must not be read as implementing them.
