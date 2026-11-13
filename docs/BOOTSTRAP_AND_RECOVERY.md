# Bootstrap, System Operator Installation, and Recovery

This guide explains how MTMF establishes its initial administrative foundation, how a separately authenticated SYSTEM operator obtains bounded management authority, how development installation differs from production, and what to do when bootstrap or access recovery cannot safely complete.

**Audience:** deployers, operators, integrators, and engineers new to MTMF. **Scope:** behavior and approved security contracts, not change history. See [Development Setup](DEVELOPMENT_SETUP.md) for existing local commands and [Root Administration and Tenant Stewardship](ROOT_AND_STEWARDSHIP.md) for the detailed root/stewardship invariants.

> **Implementation status matters.** The protected root database foundation and ordinary local development initializer are implemented. The dedicated SYSTEM-operator control plane and its opt-in development operator installation have an approved design but are **not yet operational on the documented baseline**. Production operator enrollment, production root-login recovery, and an HTTP first-Tenant onboarding workflow must not be assumed available. A design approval is not proof of a deployed, tested feature.

## 1. Bootstrap is several different operations

"Bootstrap" is not one superuser login or a single API request. It describes a series of separately trusted operations:

| Operation | What it establishes | Trust boundary | Baseline status |
| --- | --- | --- | --- |
| **Database installation** | MTMF schema, approved built-in policy, restricted PostgreSQL roles | Deployment administrator and short-lived authenticated migrator | **Implemented** |
| **Root foundation bootstrap** | One protected root Tenant and Principal, one designated LOCAL root Identity, and immutable registry/memberships | Owner-authorized installation transaction | **Implemented** |
| **Development fixture initialization** | A real development Keycloak user, ordinary test Tenant, steward, Application registration/subscription and binding | Short-lived development initializer with separately held credentials | **Implemented** |
| **SYSTEM-operator installation** | Independently authenticated non-root operator with an explicit approved SYSTEM Role assignment, audited provenance and isolated control access | Separate installation authority and future privileged control worker | **Approved design; implementation pending** |
| **First-Tenant admission** | Preliminary, non-authorizing assessment of a verified new user, Application and onboarding entitlement | Independently verified service/user token pair; isolated read-only admission | **Internal verification foundation implemented; private control admission pending** |
| **Root access recovery** | Controlled replacement of the designated LOCAL root Identity without recreating root | Separate owner-authorized recovery ceremony | **Database primitive implemented; general operational recovery workflow not delivered** |

These operations have different credentials, authorization checks, lifecycles, and failure behavior. None can be substituted for another.

## 2. Which identities and credentials mean what?

| Term | Meaning | Does **not** mean |
| --- | --- | --- |
| **Root Principal** | Unique canonical ROOT-scope Principal in MTMF | PostgreSQL superuser or Keycloak administrator |
| **Root Identity** | Protected, designated **LOCAL** MTMF Identity belonging to the root Principal | Automatically available external SSO account, service token or operator login |
| **Bootstrap identity provider (IdP)** | Configured external authentication trust anchor used to verify user/service identities | Root Principal, or a provider whose users automatically gain SYSTEM rights |
| **Keycloak development administrator** (`mtmf-admin`) | Administrator of the development Keycloak master realm, used only for issuer/client/user setup | MTMF root Identity or MTMF SYSTEM operator |
| **Ordinary development user** | Example user in `mtmf-dev` used to exercise normal Tenant authentication | Global privileged operator |
| **SYSTEM operator** | Independently authenticated, non-root human Identity with an **explicit**, active SYSTEM-scope assignment and exact Action permissions | Root impersonation, broad Tenant membership, ownership-derived authority or client credentials |
| **PostgreSQL administrator** | Deployment-level account that can create database roles | Ordinary MTMF runtime or signed end-user identity |
| **`mtmf_migrator` / `mtmf_owner`** | Short-lived authenticated migration login / database object-owner role | A credential for the public HTTP service or long-lived control worker |
| **`mtmf_runtime`** | Restricted login for normal service persistence | Privileged operator authority, even if a caller forges user IDs |
| **`mtmf_control_exec`** | Separately restricted **planned** login for the isolated control worker, with only five approved private function EXECUTEs | Owner/migrator membership, table write privileges, or authority to decide an Action without verified operator policy |

**Key rule:** knowing a database password, owning an object, trusting an IdP, or supplying an Identity UUID does not authenticate a human SYSTEM operator. MTMF must verify the real acting Identity, persisted binding, exact Role assignment, applicable Permission and operation target separately.

## 3. The ordinary installation sequence

The deployed database and local development initializer use the following order:

```text
Deployment administrator provisions restricted database roles
    |
    v
Authenticated migrator applies versioned schema and approved built-in policy
    |
    v
Mandatory effective runtime-privilege postflight
    |
    v
Short-lived initializer establishes / verifies canonical root foundation
    |
    v
Development only: verifies real Keycloak subject and ordinary test fixtures
    |
    v
Installer exits; restricted MTMF HTTP service starts
```

### 3.1 Database installation

- An administrator provisions `mtmf_owner`, `mtmf_migrator`, and `mtmf_runtime` using the supported provisioning tool. They must have the documented attributes and membership structure.
- Migration uses the actual `mtmf_migrator` connection and temporarily `SET ROLE mtmf_owner` for installation-owned database objects. A runtime or administrator-labelled connection is not a substitute.
- Every migration-to-head invocation, including a no-op upgrade, must perform the effective `mtmf_runtime` privilege postflight. A committed migration plus failed postflight is **not** a successful deployment. An explicit read-only verification tool is also available.
- Versioned migrations are **not** the mechanism for creating or granting the separately restricted control login; the approved control-role provisioning phase is independent.
- The public service receives only its restricted runtime credentials; it never gets administrator, owner or migrator credentials.

Existing manual role provisioning and verification commands, subject to the documented environment prerequisites:

```bash
uv run python scripts/mtmf-provision-roles.py
uv run python scripts/mtmf-provision-roles.py --verify
```

These commands are **implemented for the existing role topology**; control-role-specific modes are not available until the separate control-plane implementation lands. Use [Database Architecture](DATABASE.md) for the current migration/role setup and required environment variables.

### 3.2 Protected root creation

The installation-only database bootstrap establishes, in one serialized transaction:

1. The unique ROOT Tenant and ROOT Principal.
2. A designated active **LOCAL** root Identity belonging to that Principal.
3. The protected Principal/Identity memberships in the root Tenant and the canonical root registry.
4. Root-related stewardship/continuity constraints and durable audit evidence.

The implementation uses the owner-only `mtmf.bootstrap_root` stored function and the protected `mtmf.root_registry`. Built-in policy is installed by its approved migration/seed path, not invented from a username, operator token or root login.

**Repeat invocation:** a complete matching root registry is verified and returned without creating another root. An incompatible or partial state **fails closed**. Root is not recreated or silently transferred. Root objects cannot be deleted, deactivated or demoted through ordinary application paths.

The root Identity is a protected domain record, **not an instruction to log in using the Keycloak master administrator**. The local development initializer creates this structural foundation; production credential enrollment and recovery require independent deployment procedures.

### 3.3 Ordinary development startup

The currently supported development launcher is:

```bash
# Use only the locally configured MTMF development environment.
uv run python scripts/mtmf-dev-stack.py up
uv run python scripts/mtmf-dev-stack.py preflight
uv run python scripts/mtmf-dev-stack.py status
uv run python scripts/mtmf-dev-stack.py down
```

`up` prepares the canonical local issuer transport, starts the MTMF-owned PostgreSQL and Keycloak dependencies, performs issuer probes, runs the one-shot initializer, then starts the restricted HTTP service. Realm/client provisioning and required secrets are documented **preconditions**, not automatically inferred from a bare host.

The initializer can create a missing ordinary development Keycloak user **only on explicit opt-in**; otherwise it verifies an existing exact username. It reads Keycloak's authoritative immutable `sub` and binds that value, never a guessed subject derived from the username. Repeat startup verifies existing user/MTMF state; it does not reset credentials or recreate the Tenant.

See [Development Setup](DEVELOPMENT_SETUP.md) for issuer, certificates, password-file requirements, host mapping, existing-volume recovery, and exact environment selectors. These are **development** instructions, not a production root enrollment procedure.

## 4. Dedicated SYSTEM-operator installation (approved design; not yet implemented)

The following is the **approved target behavior**. On the current baseline, do not run imaginary control provisioning flags, claim that a SYSTEM operator already exists, or use the ordinary development Keycloak administrator as one.

### 4.1 Why a separate operator boundary is necessary

Global Application/entitlement administration cannot be implemented by simply granting more database functions to `mtmf_runtime`. A compromised public service can send arbitrary runtime-credential SQL and forge application-supplied fields. Instead, the approved model separates trust:

```text
Human operator authenticates interactively with approved IdP
    |
    v
Ephemeral operator client (dedicated UID; genuine signed user token)
    |
    v
Private AF_UNIX operator socket + exact SO_PEERCRED UID check
    |
    v
Isolated control worker (independent token verification)
    |
    v
Persisted Identity/binding + ACTIVE SYSTEM assignment snapshot
    |
    v
Existing Authorizer evaluates server-selected exact Action
    |
    v
Same control transaction: restricted stored function revalidates,
mutates entitlement, records audit and replay, then commits
```

The ordinary service cannot access the socket, worker secret, owner credentials, or private database wrappers. No privileged public HTTP endpoint, arbitrary SQL dispatch, generic operator impersonation or TCP fallback is authorized.

### 4.2 What a valid SYSTEM operator requires

A successful one-time installation binds an independently verified external user `(issuer, subject)` to an active non-root **FEDERATED** MTMF Identity and Principal, then creates an explicitly authorized and audited SYSTEM assignment to the protected Role:

```text
urn:mtmf:iam:roles:system:application-administrator
```

The assignment is **not** Tenant membership, Tenant stewardship, or a root credential. The Role must match the approved protected built-in policy. If the Role seed is absent or differs from its approved definition, installation **stops**; it must not synthesize a substitute Role or permission manifest.

Installation records durable provenance and an approval reference. Revoked or drifted assignments are not automatically restored. Production enrollment requires a separately authorized human installation ceremony; a development environment flag cannot authorize a production operator.

### 4.3 Restricted database access and exact execution limits

The control worker's dedicated `mtmf_control_exec` role may execute **only five** approved private functions: entitlement grant, revoke and get, operator-authorization snapshot, and pre-Tenant subject-history/entitlement read. The worker cannot directly change protected tables, invoke owner-only installation primitives, change assignments, or join the migrator/owner roles.

- The schema migration installs owner-owned, PUBLIC-denied functions **without depending on the control login**.
- A separate short-lived authorized administrator creates/verifies the restricted login.
- A separately authorized owner installation step grants the exact five function EXECUTEs and verifies the **effective** privilege graph before the worker starts.
- Normal `mtmf_runtime` privileges remain exactly their previously approved allowlist.
- Token/issuer verification and any remote IdP communication happen **before** the one PostgreSQL transaction. SQL revalidates stored actor/target facts and atomically writes mutation, audit and replay; it does not implement a second permission engine.

These constraints are security boundaries, not tunable defaults. The full immutable SQL/protocol detail is available in the [approved control-plane execution contract](pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md).

### 4.4 Development-only opt-in operator fixture

In the approved canonical development profile, the exact selector `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true` enables a **future** one-shot operator installation workflow. Unset or `false` leaves the ordinary development flow active without installing a new operator, control worker or privileged sockets. Any other selector value is invalid.

Once implemented, an opted-in installation will:

1. Reject non-development mode, changed issuer/client/project, missing secrets or unverified platform mappings **before** privileged side effects.
2. Start and verify the canonical Keycloak/PostgreSQL base services.
3. Apply the unconditional role-independent migration and pass runtime postflight.
4. Separately create or verify `mtmf_control_exec`; install/verify exactly the reviewed grants.
5. Create **only when genuinely absent**, or else verify without changes, the fixed development operator user `mtmf-dev-operator` with an operator-supplied restricted password file and Keycloak-confirmed immutable `sub`.
6. Install the exact operator binding/assignment and append-only creation provenance once, under short-lived installation authority.
7. Exit every administrator/migrator/Keycloak-master installer before the long-lived worker and normal service start.
8. Verify actual identities, mounts, sockets, privileges and negative controls before reporting control infrastructure ready.

An existing Keycloak username without matching audited MTMF fixture is an **adoption conflict**; the installer stops instead of silently taking control. Repeat, unchanged bootstrap is **verify-only**, with no password reset, Role regrant, new event or inflated success audit.

**Opt-out is not revocation.** After a previous opt-in installation, setting the selector to `false` stops future control startup/install actions but does **not** delete or mutate already installed control role/grants/fixture. Removing that durable authority requires a separately authorized operation. Fresh opt-out creates no such objects.

### 4.5 Interactive login is deliberately separate from startup

Ordinary `up` must **never** open a browser, start a callback listener, or obtain an operator token automatically. An explicitly invoked operator session uses the approved confidential OIDC client and **Authorization Code + PKCE S256**, with fresh state/nonce and a **temporary loopback callback** at:

```text
http://127.0.0.1:28400/callback
```

Only the ephemeral operator-client container may receive that browser callback. The control worker itself has **no TCP listener**. The client secret stays in an owner-restricted ephemeral mount; the user access token is independently checked by the worker. A genuine **client-credentials** token from the same development client is **not** an operator token and must be rejected.

On success, cancellation, timeout or error, the callback port/container/secret mount are torn down. A startup infrastructure check alone never proves that interactive operator login works. No saved proof from an old browser session authorizes a new session.

### 4.6 Deployment portability and proof

The approved developer topology is Linux-based and can run under **native Linux, WSL2 Linux, or a Podman-managed Linux VM**. WSL2 is **not** a universal requirement.

Every actual environment must prove worker-observed distinct peer UIDs (`SO_PEERCRED`), socket ownership/modes, effective DB grants, secret isolation, and host-loopback-only OAuth forwarding. A successful verification on one machine does not certify another. If the platform collapses peer identities, exposes a secret to the ordinary service, or cannot forward the exact callback safely, **stop** rather than change socket permissions, networking or OAuth parameters.

## 5. Pre-Tenant admission is not bootstrap authority

The separate pre-Tenant path evaluates a verified Application service token **and** a genuine signed user token to determine whether the user could be eligible for a *first* ordinary Tenant. The control worker must verify both tokens itself; the caller cannot select `application_id`, issuer/subject, Role, Action, identity, or entitlement by sending claims.

The approved private response can say only:

- `CANDIDATE`: new exact global subject, ACTIVE entitlement and preliminary available quota.
- `EXISTING_SUBJECT`: subject already bound; existing-Tenant resolution occurs elsewhere.
- `NO_ENTITLEMENT`: no eligible ACTIVE entitlement or quota.
- An opaque error for revoked-only/conflicting history, invalid proof, or infrastructure failure.

A candidate is **not** an authorization, a quota reservation or a Tenant. Historical subject revocation is not treated as a fresh new user. The admission socket remains **isolated test-harness-only** during the current control-plane implementation. The future atomic first-Tenant transaction and public onboarding HTTP API are separate unfinished capabilities. No first-Tenant writes may be inferred from admission success.

## 6. Recovery: choose the correct boundary

Recovery is never a generic `root=true` flag, password shortcut, or permission to re-run an installer against ambiguous state.

| Situation | Safe response | Forbidden shortcut |
| --- | --- | --- |
| Fresh, empty canonical root database | One owner-authorized serialized root bootstrap | Multiple root Principals/Tenants |
| Already bootstrapped, exact valid root registry | Read-only verification / idempotent outcome | Recreate root or change canonical IDs |
| Partial/corrupt root foundation | **STOP**; inspect and obtain authorized remediation | Guess replacement IDs, delete/rebootstrap root |
| Designated local root Identity unusable but a valid replacement exists | Separate owner-authorized `recover_root_identity` procedure with validated replacement and durable audit | Treat Keycloak `mtmf-admin` or arbitrary external user as root |
| Lost Keycloak development administrator access | Follow the explicit development credential/account recovery procedure in [Development Setup](DEVELOPMENT_SETUP.md); retain independently verified working administrator | Reset/adopt a disabled account automatically, or delete data volumes for convenience |
| Ordinary development user absent, creation disabled | STOP or explicitly enable the documented development-only create workflow with valid secret custody | Fabricate Keycloak `sub` from a username |
| Keycloak creation may have succeeded but result was uncertain | STOP for authoritative inspection/correlation; follow the existing documented ordinary-user recovery rules | Blind second create, guessed subject, silent cross-system rollback |
| Future SYSTEM operator exists with matching audited ACTIVE assignment | Verify exact subject, Principal/Identity, Role and provenance; do not change | Rotate password/regrant/audit again on restart |
| Future SYSTEM operator username exists without approved assignment, or assignment is revoked/drifted | **STOP**; separately authorized operator decision and remediation | Adopt, reactivate, impersonate or self-grant |
| Control role/grants are partial, elevated or unexpectedly reachable from runtime | **STOP**; retain safe stopped state and request approved remediation | Widen privileges, run worker anyway, or weaken verification |
| Operator authentication expired or callback invalid | Tear down ephemeral session; perform a new genuine login when requested | Reuse stale attestation, password grant or service token |
| Unknown outcome of a privileged write | **STOP**; inspect durable replay/audit/transaction state before resubmission | Blind retry or fabricate success audit |
| Production operator or root credentials lost | Incident response and independently authorized installation/recovery ceremony | Use development fixture, application runtime or Keycloak master user as production recovery authority |

### 6.1 Root Identity recovery: what exists, and what does not

The owner-only PostgreSQL `mtmf.recover_root_identity` primitive exists. It requires a replacement Identity that **already** belongs to the canonical root Principal, is LOCAL, is not deleted and has root-Tenant membership. It changes the designated root Identity under serialization and records a root-Identity recovery audit event. It does **not** create a new root Principal/Tenant, issue a login credential, verify a human approval, restore a lost Keycloak password, or provide a public recovery endpoint.

A general self-service/public production root recovery workflow is **not implemented**. Only an authorized deployment operator using a separately controlled owner/installation procedure may invoke the primitive according to approved runbooks. On uncertain approval or inconsistent state, stop. There is no automatic "last administrator" takeover.

### 6.2 Secret and installation custody

- Keep PostgreSQL admin/migrator, Keycloak administrator, root recovery and future control-worker credentials in **separate** approved custody.
- Use restricted secret files/mounts where prescribed; never place a plaintext password in Git, process arguments, public service configuration, logs, metrics, traces or a shared application volume.
- One-shot installers exit before normal services; an MTMF developer-stack reset must affect **only explicitly identified MTMF resources**. Normal `down` is not data destruction.
- A future control-credential rotation stops the worker, rotates the separately held secret, proves the old secret no longer authenticates, then redeploys and re-verifies effective restrictions.
- Production initialization, operator enrollment and recovery require a distinct approved ceremony; canonical development defaults are not production authority.

## 7. How to tell whether an installation is ready

**A local ordinary MTMF service is ready** only after its existing initializer and runtime privilege checks pass and the service health/readiness probe succeeds. That status does **not** imply a SYSTEM operator or root human login is ready.

**A future privileged control-plane infrastructure is ready** only after verified deployment identity/secret/socket isolation and exact effective control/runtime database privileges. **An operator session is ready** only after a fresh genuine browser login and authorization verification. A pre-Tenant candidate read alone does not make first-Tenant provisioning ready.

Record the actual environment, role/privilege checks, signed-token evidence, negative cases and failures. When feature implementation is still pending, mark it **not available**, not "passed by design".

## 8. Where to read more

- [Development environment setup](DEVELOPMENT_SETUP.md) — working local commands, issuer trust, account and password-file setup, ordinary fixture recovery.
- [Root administration and Tenant Stewardship](ROOT_AND_STEWARDSHIP.md) — detailed continuity guarantees and domain semantics.
- [Security Model](SECURITY_MODEL.md) — highest-authority security invariants.
- [Database Architecture](DATABASE.md) — PostgreSQL roles, migrations and effective privilege verification.
- [Onboarding Architecture](ONBOARDING_ARCHITECTURE.md) — how authenticated Application/user pairs become eligible for Tenant resolution and future first-Tenant provisioning.
- [Configuration Architecture](CONFIGURATION_ARCHITECTURE.md) and [Multi-IdP Architecture](MULTI_IDP_ARCHITECTURE.md) — approved **future** configuration/provider models; not current runtime instructions.
- [Approved control execution and static deployment contract](pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md) and [versioned deployment manifest](pr-artifacts/pr-24p/PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md) — frozen technical values for implementers and security reviewers; not evidence that the future control plane is deployed.
