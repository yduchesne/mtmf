# Root administration and Tenant Stewardship

**Status:** The protected root/ordinary-Tenant stewardship database foundation is implemented, including the built-in policy seed, Identity origin, Tenant lifecycle, canonical root registry, serialized root bootstrap, designated stewardship, append-only audit, and database guards. Its privileged bootstrap/designation/activation/recovery functions are installation-only (`SECURITY INVOKER`, never granted to `mtmf_runtime`). A general authenticated end-user recovery/transfer interface and production root-login recovery procedure must not be inferred from the existence of these database primitives.

This guide explains how MTMF establishes its first administrator, how each customer Tenant keeps a responsible administrator, and how the system prevents accidental or unauthorized loss of administrative control. For the complete installation and recovery sequence—including the distinction between root, Keycloak administrator, SYSTEM operator, and database installer—start with [Bootstrap and Recovery](BOOTSTRAP_AND_RECOVERY.md). This guide complements the [Security Model](SECURITY_MODEL.md), [Domain Model](DOMAIN_MODEL.md), [Authorization](AUTHORIZATION.md), and [Database Architecture](DATABASE.md). If this explanation conflicts with the Security Model, the Security Model governs.

## The concepts in plain language

- A **Tenant** is an isolated administrative boundary, typically representing one customer.
- A **Principal** represents the person or other subject to whom authority belongs.
- An **Identity** is the particular login identity used by that Principal. One Principal can have several Identities; they do **not** automatically share permissions.
- A **Role** supplies permissions for ordinary operations. Having a Tenant Administrator Role does **not** make someone the Tenant's steward.
- A **steward** is the one designated Principal responsible for an ordinary Tenant's administrative continuity.
- The **root Principal** and **root Tenant** are the unique system-wide starting point for administration. Root is not an ordinary transferable Tenant stewardship designation.

For example, a company may have three administrators with the same Tenant Administrator Role, but only one designated steward. Another Identity owned by that steward cannot invoke stewardship privileges unless it has been explicitly designated as the **steward acting Identity**.

## Guarantees MTMF must preserve

1. Exactly one root Principal and one root Tenant exist after successful bootstrap, each with ROOT scope, with the root Principal's protected ROOT-scope membership in the root Tenant.
2. The root Principal, root Tenant, and their protected relationship cannot be deleted, deactivated, reassigned, or demoted through ordinary application operations. Root ownership remains immutable.
3. At least one **designated, active, local MTMF Identity** belonging to the root Principal must remain able to form a structurally valid session in the root Tenant. The designated root Identity and its required membership cannot be removed, deactivated, or rebound without an atomic, authorized replacement.
4. Every active ordinary Tenant has exactly one eligible ACTIVE steward Principal. The steward has active Tenant membership at TENANT scope and the built-in Tenant Administrator Role.
5. Stewardship is **not** a Role and does not transfer through Group membership, another Identity, ownership, or a Role assignment.
6. No protected change may commit an intermediate state violating these guarantees. A failed transaction must leave the previous valid state intact.
7. Permission and scope/dominance checks remain mandatory. Stewardship supplies only the narrowly specified same-scope dominance exception; it never turns a DENY into an ALLOW.

These guarantees concern **database state and authorization semantics**. They cannot guarantee that a human still knows a password, that an external identity provider is online, or that an operator can access the deployment. Operational recovery must address those separate risks.

## How a steward uses an Identity

Every active Tenant stewardship designation must identify **one explicitly designated acting Identity** of the steward Principal. This is a separate authorization fact, not a new Role or stewardship enum value.

To exercise stewardship-derived authority, MTMF must verify all of the following:

1. The request is associated with an authenticated, verified acting Identity—not a user-supplied Identity UUID alone.
2. The Identity belongs to the current steward Principal, is active, and has valid active membership in the session Tenant; the Principal and Tenant are active.
3. The Identity is the **currently designated steward acting Identity** for that Tenant.
4. The action is permitted by the Identity's effective Roles and all applicable Tenant, target, and dominance checks. The designation alone does not grant the Tenant Administrator Role to that Identity.

The designated Identity must be eligible to perform the required stewardship operations through an explicit applicable Role assignment. A Group-derived Role may satisfy ordinary permission checks, but does not designate an Identity as steward. Other Identities of the same Principal receive no stewardship-derived dominance.

The designation is changed only by an explicit, authorized, atomic operation. A lost or deactivated designated Identity requires an authorized designation change or recovery; MTMF must never choose another Identity automatically.

For the root Principal, bootstrap establishes one **protected root acting Identity**. Any later replacement is a separate privileged recovery operation and must atomically preserve a valid designated local root Identity. No ordinary user operation can transfer root status.

## Bootstrap: create the first administrator once

Bootstrap is a trusted **deployment/installation** operation, not an unauthenticated HTTP endpoint or an ordinary runtime function callable by any holder of `mtmf_runtime` credentials.

A successful bootstrap transaction:

1. Acquires an exclusive database lock to serialize concurrent bootstrap attempts.
2. Confirms the database is uninitialized or matches one complete canonical bootstrap record.
3. Creates the single ROOT Tenant and ROOT Principal, with immutable creator/owner provenance.
4. Creates the required local root Identity and the Principal/Identity Tenant memberships.
5. Establishes the protected ROOT-scope Principal membership, root stewardship, designated root acting Identity, and built-in system administration Role/policy and applicable explicit assignment(s).
6. Stores canonical identifiers in a protected singleton **bootstrap registry** and validates all root invariants before commit.

The installed `mtmf.root_registry` identifies canonical objects by stable IDs, never by display names. Approved built-in Role definitions belong to the separate protected policy seed; no bootstrap process may invent broader wildcard Permissions.

**Retry semantics:** a retry against a fully valid completed bootstrap is read-only/idempotent and returns the canonical identifiers. An empty database may bootstrap once. A partial, contradictory, or corrupted state raises an integrity error and requires an explicit privileged recovery procedure. No automatic root recreation, reassignment, or privilege broadening is allowed.

## Creating and administering an ordinary Tenant

Creating an **active** ordinary Tenant and designating its first eligible steward must be atomic. If an installation workflow needs to stage incomplete Tenant data, the Tenant must remain **PROVISIONING and non-authorizing** until its first steward and acting Identity are valid; an active stewardless Tenant is forbidden.

The initial steward must be an active Principal with the required Tenant membership, TENANT scope, explicit Tenant Administrator Role assignment, and an active designated acting Identity with valid Tenant membership and applicable administrative permissions.

A normal stewardship transfer:

1. Authenticates the current designated steward acting Identity and checks the exact transfer Permission and applicable dominance rules.
2. Validates the proposed successor Principal, its Tenant membership, built-in Tenant Administrator Role, and explicitly nominated eligible acting Identity.
3. Locks the Tenant's stewardship state and dependent membership/assignment state in a consistent order.
4. Atomically replaces the old steward and acting-Identity designation; does **not** change immutable Tenant ownership.
5. Writes an auditable operation record identifying the verified actor, Tenant, previous/new steward and designated Identity, outcome, and time, without treating a caller-provided actor ID as authentication.
6. Commits only if the Tenant still has exactly one valid steward. Concurrent or stale transfers must not silently overwrite one another.

A delegated Tenant Administrator cannot self-promote to steward. A duly authorized SYSTEM administrator may perform a **recovery transfer** for an ordinary Tenant when normal succession is impossible, subject to the same successor validations and audit requirements. Recovery must not grant a general cross-Tenant bypass.

## What happens when someone removes or disables something?

- Removing a membership, Role assignment, Principal, or Identity that would invalidate the current steward or protected root chain must fail **before** the change commits, unless an explicitly authorized transaction establishes a valid replacement atomically.
- Existing membership-removal and Role-assignment stored functions must also enforce these protections. Guarding a bootstrap-only function is insufficient.
- A failed membership removal must roll back its cascade and compact removal-audit row, preserving PR 6B/PR 9 semantics.
- Role removal/revocation and lifecycle changes must not silently revoke the final steward's mandatory Tenant Administrator authority.
- A Tenant's lifecycle transition may not be used to bypass root protections; activating a Tenant requires a valid steward.

Example: if an administrator tries to remove the current steward's Tenant membership, MTMF rejects the operation. The administrator must first perform an authorized transfer to a qualified successor.

## Enforcement: two independent boundaries

**Application authorization** determines *who may request an operation*. It verifies the actual authenticated acting Identity, effective Roles, Permission, target Tenant, scope/dominance, and stewardship designation. A Principal UUID or `actor_identity_id` passed by a caller is not proof of authentication.

**PostgreSQL enforcement** determines *whether the resulting data state is structurally legal*, even when a permitted stored function is called incorrectly. The root/stewardship foundation uses reviewed constraints, guards/triggers, stored functions, transaction-level locking, and privilege restrictions to protect this state. Runtime connections remain restricted to exact reviewed `SECURITY DEFINER` function signatures; no direct table access is introduced. All new and existing write paths capable of invalidating the invariants must be covered.

**Important current limitation:** MTMF's shared `mtmf_runtime` database login is not an end-user authentication boundary. A holder of those credentials can call its granted functions; the database cannot independently verify a caller-supplied acting Identity. Privileged bootstrap, stewardship-transfer, or recovery operations must never be broadly runtime-granted. Their existence as installation-owned functions does not establish an accessible, authenticated public recovery API or an independently verified SYSTEM-operator session.

PostgreSQL superusers and deployment administrators remain an operational trust boundary: they can bypass database protections. Access to those credentials must be separately controlled and audited.

## Recovery without silent escalation

- **Ordinary Tenant:** an authorized SYSTEM administrator can initiate a recorded recovery transfer to a qualified successor and designated Identity.
- **Root:** recovery requires a separate deployment/operator procedure with privileged credentials and documented approvals. It is **not** an ordinary application Role permission or an unauthenticated reset endpoint. Root recovery must preserve canonical root IDs, immutable ownership and the unique ROOT membership.
- **Corruption:** fail closed and report the inconsistent object/constraint; do not guess a new steward or root Identity.
- **Authentication outage:** structural continuity is not login continuity. Maintain operational credential recovery, secret rotation and backup procedures independently.

The precise operator approval mechanism (for example, dual control), credential custody and incident runbook are deployment policy and must be documented before a production rollout. They are not claimed as already implemented.

## Verification expectations and feature availability

Any claim that the protected root/stewardship boundaries—or a future authenticated recovery interface—are production-ready requires evidence of the applicable cases:

- concurrent bootstrap yields one root; retries are idempotent; partial/corrupt bootstrap fails closed;
- root Principal/Tenant uniqueness, ROOT scope, immutable membership and designated local Identity survive attempted deletion, deactivation, reassignment and demotion;
- an ordinary Role assignment, Group membership or second Identity cannot confer stewardship or root authority;
- a steward acting Identity with valid permissions can perform the specifically permitted stewardship operation; another Identity of the same Principal cannot;
- active Tenant creation never commits without one valid steward and designated acting Identity;
- transfer and SYSTEM recovery are atomic, authorized, auditable and race-safe; stale competing transfers do not both succeed;
- prerequisite membership removal, Role revocation and lifecycle changes cannot orphan a steward or root chain, including via legacy stored functions;
- a failed protected operation leaves no committed partial state or forged audit event;
- real `mtmf_runtime` tests prove direct DML is denied and the exact stored-function allowlist remains enforced;
- local and PostgreSQL persistence semantics agree wherever their contracts overlap; CI runs QA, security, Rust regression and real PostgreSQL integration gates.

**Structural database protection is not the same as a completed human recovery workflow.** A public or operator-facing transfer/recovery operation must be implemented and independently verified at the trusted acting-Identity boundary before it can be claimed available. The implemented owner-only `mtmf.recover_root_identity` database primitive is not itself a production recovery CLI, a password reset procedure, or root login.

## Further reading

- [Security Model](SECURITY_MODEL.md) §§5, 10, 16, 24 — authoritative invariants.
- [Domain Model](DOMAIN_MODEL.md) §§7, 14, 18 — entities, memberships, atomicity.
- [Authorization](AUTHORIZATION.md) — acting Identity, Permissions and dominance.
- [Database Architecture](DATABASE.md) — runtime privileges, stored functions, trust boundaries.
- [Bootstrap and Recovery](BOOTSTRAP_AND_RECOVERY.md) — reader-oriented installation, SYSTEM-operator distinction, recovery and current availability.
