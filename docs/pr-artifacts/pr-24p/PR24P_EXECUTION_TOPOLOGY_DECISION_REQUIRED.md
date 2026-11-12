# PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED

**PR:** roadmap **PR 24P** — Operator and Pre-Tenant Privileged Execution Prerequisite
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Plan version:** 2026-11-12 (rev 2: independent-review Findings A–C) · `DESIGN PROPOSED`
**Prepared by:** coding agent (Phase 0, documentation only)
**Baseline reconciled at:** `8712418a3d2de212791ae75a6235d3e00fced450` (= `origin/main`, PR 23 merged)
**Status:** **`PR24P_BLOCKED_TOPOLOGY_APPROVAL`** — `STOP-P24P-TOPOLOGY` is **ACTIVE**

## 0. Amendment history and independent-review disposition

This revision addresses three findings from independent review while staying
in documentation-only Phase 0. **No topology field is approved by this
amendment, and no code, migration, role, grant, socket, or deployment resource
is created.**

| Finding | Defect addressed | Amendment in this document |
| --- | --- | --- |
| **A** | The pre-Tenant branch named a “private admission interface” but did not define its exact trust model, wire contract, limits, or response semantics; only the operator socket was frozen. | New **§5A** freezes the second private interface (`admission.prepare`), its separate socket/UID trust contract, framing/limits, exact request/response literals, no-write read path, ingress-compromise bounds, and the fail-closed `PrivilegedOnboardingTransactionPort` contract (§5A.6). Field 3, Field 7, Field 12 and §8 now reference it. |
| **B** | The authorization snapshot carried only bare IDs plus permission rows, so the control process could not verify persisted Identity/Principal/binding/Role lifecycle, origin, canonical-root exclusion, or builtin/approved marker facts. | New **§6A** replaces the snapshot description with an exact persisted-domain-identity schema (Identity, Principal, ExternalSubjectBinding, Role, PermissionSet, Permission, assignment, target), sufficient to reconstruct the existing internal aggregates and perform every `authorize_global_system` check without a second read. |
| **C** | “Policy evaluation” and “SQL revalidation” duties overlapped: both Python and SQL appeared to check assignment/target/Action, and the transaction/lock boundary between the snapshot and the mutation wrapper was not pinned. | New **§6B** freezes a non-overlapping responsibility table, the exact check order, the lock order across snapshot + wrapper, the single-transaction boundary, and the rule that SQL never returns ALLOW and Python never trusts stale unlocked state. Field 10 now references it. |

All other approved architectural invariants and proposals in this record are
preserved unchanged. The frozen operator protocol (§5), fingerprint (§6) and
SQL signatures (§7) are preserved verbatim; §5A/§6A/§6B are **additive** and
must be approved together with the existing twelve fields.

> **This document is a decision request, not an approval.** Nothing in this
> repository, in the PR 21 Action approval, in `docs/ROADMAP_V01.md`, in the
> execution plan that commissioned this artifact, or in any chat/session
> message is a topology approval. The coding agent has implemented **no**
> migration, SQL function, role, grant, socket, listener, deployment, or
> authorization code for PR 24P. See
> [PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md](PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md)
> and [PR24P_STOP_AND_DEVIATION_REPORT.md](PR24P_STOP_AND_DEVIATION_REPORT.md).

---

## 1. Why this decision is required

PR 24P owns exactly two privileged execution boundaries that do not exist
today:

1. **Operator boundary** — independently authenticated human operator →
   explicit global SYSTEM-scoped Role assignment → global-target exact-Action
   evaluation → narrowly authorized, single-transaction, audited privileged
   execution.
2. **Pre-Tenant boundary** — independently verified Application service
   credential **and** user token → authoritative per-Application onboarding
   entitlement → distinct, non-Role admission decision → a private executor
   transaction interface for the future PR 22B composite.

Both require a *deployment and trust topology* — a process boundary, a
transport, a database role, a secret custody model, and a compromised-runtime
threat model. The roadmap (line 309 of `docs/ROADMAP_V01.md`),
`docs/ONBOARDING_ARCHITECTURE.md` §19.3, and the PR 21 operator-boundary record
all state that this topology must be **explicitly human-approved** before any
executor is implemented or anything is granted. Therefore this artifact
presents the exact proposal and stops.

## 2. What is grounded today (and what is absent)

Phase 0 read the implementation fresh. Full evidence and commands are in
[PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md](PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md).
Summary relevant to this decision:

| Piece | State at `8712418` | Citation |
| --- | --- | --- |
| Ordinary `Authorizer.authorize` | Tenant-bound `AuthorizationRequest`; cross-Tenant only via positively resolved `TenantManagementGroup` delegation | `packages/mtmf-core/src/mtmf_core/authorization/authorizer.py:52,79`; `.../authorization/context.py:65-102`; `.../authorization/guards.py` |
| Global / Tenant-independent SYSTEM target authorization | **ABSENT** — no global target type, no non-Tenant session, `Role` has no scope field | `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md` §3 |
| Effective Role resolution | Tenant-bound `IdentityRoleAssignment` / `GroupRoleAssignment` only | `packages/mtmf-core/src/mtmf_core/application/effective_roles.py:125` |
| Verified ordinary actor | `AuthenticatedActorContextService` (requires an existing Tenant context) | `packages/mtmf-core/src/mtmf_core/application/authentication.py` |
| Pre-Tenant verified subject (PR 23) | `PreTenantSubjectVerificationService`, read-only, non-authorizing | `packages/mtmf-core/src/mtmf_core/application/pre_tenant_subject.py`; `.../authentication/contracts.py:186` |
| PR 22A entitlement primitives | owner-only `SECURITY INVOKER`: `grant(uuid,uuid,uuid,text,bigint,uuid)`, `revoke(uuid,uuid,text,uuid)`, `get(uuid)`, `find_by_application(uuid)` | `.../sql/v014/02_onboarding_entitlement_functions.sql`, `03_onboarding_entitlement_grants.sql` |
| PR 23 participants | owner-only `SECURITY INVOKER`: `onboarding_subject_prepare(text,text,uuid,uuid,uuid)`, `onboarding_initial_steward_attach(uuid,text,text,uuid,uuid)` | `.../sql/v015/02_onboarding_subject_and_steward_functions.sql`, `03_..._grants.sql` |
| Runtime allowlist | exactly **78** EXECUTE signatures at revision `0015` | `.../persistence/postgres/roles.py::expected_runtime_signatures`; live count 78 |
| PostgreSQL roles | `mtmf_owner` (NOLOGIN), `mtmf_migrator` (LOGIN, member of owner), `mtmf_runtime` (restricted LOGIN) — **no control role** | live catalog query (see reconciliation report) |
| Operator sign-in / SYSTEM assignment / privileged adapter | **ABSENT** (no `system_operator`, `mtmf_control_exec`, `authorize_global`, or control-plane package anywhere) | repository-wide grep |
| Development region/client | realm `mtmf-dev`, client `mtmf-evidence-same-client`, audience `mtmf-same-client-api` | `dev/keycloak/expected-client-policy.json` |
| Deployment isolation | Only `compose.yaml` (PostgreSQL) and `Dockerfile.service`; **no** separate control process/UID/socket/secret mount exists, so compromised-runtime isolation is **not yet demonstrated** | `compose.yaml`; `Dockerfile.service` |

## 3. How to record a decision

The decision is valid **only** if it is written, named, and covers **all
twelve** fields in §4 plus the frozen protocol/signatures in §5–§7. A partial,
implied, or "looks fine" approval keeps `STOP-P24P-TOPOLOGY` active.

Required decision material (fill in §9 and the per-field blocks):

- named human decision ID;
- date;
- approving party;
- exact approved text / document version;
- reference or evidence (meeting record, signed file, ticket);
- any conditions or amendments;
- the deployment-specific host values in §8.

If **any** field is `REJECTED` or `AMEND`, the agent stops and returns a
revised plan for further approval. The agent will not reinterpret amendments,
pick a fallback design, or invent a substitute.

---

## 4. The twelve fields (all `PROPOSED — NOT APPROVED`)

### Field 1 — Separate operator/private control process and separation from public `mtmf-service`

**PROPOSED.** A dedicated, separately installable `mtmf-control-plane` process
with its own UID, isolated mount namespace, isolated network attachment, and
its own private entrypoint. It must not import or start
`mtmf_service.app.create_app`, must not reuse the `mtmf-service` database pool,
and must expose no public FastAPI listener. The normal public `mtmf-service`
process must never host privileged execution.

**Supporting evidence.** `compose.yaml` defines only PostgreSQL; `Dockerfile.service`
builds the public HTTP service; no `packages/mtmf-control-plane/` exists.
`mtmf_runtime` is a restricted LOGIN.

**Threat assumptions.** Assumes the deployment can give the control process a
*distinct* process identity and filesystem/network namespace from the public
service. If both run as the same host UID with mutually readable secrets and
socket paths, the compromised-runtime model fails and the agent must STOP.

**Required deployment.** A new workspace distribution and a dedicated
non-root container/UID, no public ports, no shared service env file, no shared
secret volume. Exact UID/GID in §8.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 2 — Administrative `AF_UNIX` transport and `SO_PEERCRED`/UID ACL topology (no fallback)

**PROPOSED.** Linux `AF_UNIX` `SOCK_STREAM` owned by `mtmf-control-plane`, under
a fixed dedicated runtime directory whose owner/group/mode are fixed by the
approved deployment manifest. `SO_PEERCRED` must match the **single approved
administrative UID**; unknown or missing peer credentials are rejected. The
`mtmf_runtime` UID and every application-facing service UID are excluded from
the group/ACL. No TCP fallback, wildcard listener, localhost shortcut, Podman
socket proxy, or SSH-agent forwarding. If the OS/container cannot provide
verifiable peer credentials or ownership isolation, STOP rather than weaken
the boundary.

**Supporting evidence.** No socket or listener exists today; no client
transport contract enumerates a peer-credential model.

**Threat assumptions.** Assumes rootless Podman/WSL2 preserves distinct peer
UIDs across the mount boundary. If peer mapping collapses identities, the agent
must STOP (`STOP-DEPLOYMENT`).

**Required deployment.** Socket absolute path, owner UID/GID, mode, allowed
admin UID, directory mount. Values in §8.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 3 — Trusted future ingress for pre-Tenant proof (gateway compromise limits)

**PROPOSED.** A *different*, dedicated ingress identity (not the operator Unix
UID) is required for pre-Tenant requests. PR 24P may ship a private in-process
contract plus a **test-only isolated ingress harness**, but ships **no** callable
public pre-Tenant socket or route. PR 24 must route the public endpoint through
a trusted ingress **directly** to the private worker, never through a
`mtmf_runtime` process holding a privilege-capability token. The gateway's
compromise authority is bounded by the same service/user/entitlement
verification the worker repeats. If no such gateway is approved, `STOP-INGRESS`
prevents pre-Tenant exposure.

The **exact** second-interface trust model, socket/peer-UID separation, framing,
limits, request/response literals and read path are frozen in **§5A**. They are
part of this field's approval; approving the concept without the §5A literals
is not approval.

**Supporting evidence.** The public service is the only HTTP surface; there is
no gateway-to-executor transport. `PreTenantSubjectVerificationService` verifies
the token pair itself, which is what makes gateway forwarding safe only if the
worker re-verifies.

**Threat assumptions.** Assumes the gateway can authenticate the Application
service credential and forward raw tokens without becoming an authorization
oracle, and that it never gains operator authority. The gateway must not be
able to supply `application_id`, actor IDs, entitlement IDs, Role/Action, or an
`approved`/`root` flag; §5A forbids those fields.

**Required deployment.** Gateway identity, ingress transport, and its network
placement (PR 24), or an explicit "test harness only in PR 24P" statement. The
dedicated ingress UID/GID and admission-socket path/mode are recorded in §8;
they must differ from the operator admin UID, the control worker UID, and the
`mtmf_runtime` UID.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 4 — Development operator OIDC issuer/client/user-token verification; production gated

**PROPOSED.** One *genuine signed user-class* access token from the existing
approved **development** `mtmf-dev` Keycloak trust profile and expected-client
policy. Verify JWKS, signature, issuer, audience, temporal validity, user class,
exact signed client ID/`azp` (`mtmf-evidence-same-client`, audience
`mtmf-same-client-api`), fresh realm/client attestation, and a persisted exact
`(issuer, subject)` ACTIVE binding to an active FEDERATED Identity and Principal.
The operator token is obtained over a separately authenticated administrative
session; never proxied as a service credential. No new production IdP, password
grant, Keycloak admin impersonation, root login, token exchange, or
request-body claims. The canonical root Identity is excluded. This is **not** a
production operator sign-in claim.

**Supporting evidence.** `dev/keycloak/expected-client-policy.json`
(`mtmf-evidence-same-client`, audience mapper `mtmf-same-client-api`),
`dev/keycloak/expected-realm-security.json`; PR 14 verifier and attestation in
`packages/mtmf-service/src/mtmf_service/authentication/`. If this exact token
class cannot be produced under the approved profile, STOP-AUTH-PROFILE.

**Threat assumptions.** Assumes the dev realm can issue a standalone
interactive-user token for an operator subject with a persisted binding, and
that the verifier is safe to use outside a Tenant session.

**Required deployment.** Existing `mtmf-dev` Keycloak + committed baselines;
no regeneration.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 5 — Global SYSTEM assignment, bootstrap authority, audit, revocation, no automatic root grant

**PROPOSED.** A new explicit database association `mtmf.system_operator_assignment`
binding one active *Identity*, its canonical *Principal*, and a SYSTEM-defined
**approved Role** (`urn:mtmf:iam:roles:system:application-administrator` only in
PR 24P). It is **not** Tenant membership and confers no Tenant Role or
stewardship. A one-time, owner-controlled **installation ceremony** creates the
initial assignment with an externally approved operator/identity/role and an
append-only event, using an explicit `approval_correlation_id` and
`approved_by` installation-decision reference. It is not a runtime self-grant,
not an environment-variable bootstrap, not a dev initializer, and not derived
from root. Revocation is an installation-only ACTIVE→REVOKED transition;
regrant uses a new UUID and a new decision. Dynamic grant management is
deferred. No automatic root assignment at any point.

**Supporting evidence.** `Role` has no scope field; existing assignments are
Tenant-bound (`v005`, `0013`-era SQL); `mtmf.builtin_role` protects built-in
Role definitions only; no operator assignment table exists.

**Threat assumptions.** Assumes the installation ceremony is performed by a
human with separate authority. The DB cannot attest the *human* approving party;
it records the approved installation reference. This is an explicit trust
assumption.

**Required deployment.** An installation-only reviewed script/function run in
the `mtmf_migrator`/`SET ROLE mtmf_owner` installation context; no runtime or
control-login EXECUTE.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 6 — Global target model and `Authorizer` reuse without a fake Tenant session

**PROPOSED.** Strictly typed `GlobalApplicationTarget(application_id)` and
`GlobalEntitlementTarget(application_id, entitlement_id)`, distinct from
`Tenant`/`SessionContext`. A separate internal request type
`GlobalSystemAuthorizationRequest` plus `Authorizer.authorize_global_system(request)`
— **never** a change to the default behavior of `authorize`. It consumes
verified/locked facts assembled only inside the trusted control process:
`VerifiedSystemOperator`, exactly one approved global SYSTEM Role aggregate +
assignment record, the global target, and a trusted server-selected exact
`Action`. The Role aggregate and operator facts are reconstructed **only** from
the persisted-domain-identity snapshot frozen in **§6A**; no display metadata,
extension, Tenant membership, or second query is used. It reuses the existing
compiled Permission engine with DENY precedence; no new permissive evaluator,
no `TenantManagementGroup` substitution, no union with Tenant permissions, no
`root=true`.

**Supporting evidence.** `Authorizer.authorize` and
`DefaultAuthorizationPolicyResolver`/`CompiledPolicy` at
`packages/mtmf-core/src/mtmf_core/authorization/`; Tenant binding in
`authorization/context.py`.

**Threat assumptions.** Assumes policy compilation can operate on an explicit
global Role aggregate that is *not* attached to a Tenant. If the current
`Role`/`PermissionSet` model cannot be compiled without fabricated Tenant
facts, the agent must STOP-POLICY-ENGINE and report the exact missing primitive
rather than build a second evaluator.

**Required deployment.** None beyond the package; this is a code-contract
decision.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 7 — Exact DB roles, per-function allowlist, owner-owned `SECURITY DEFINER` wrappers, no direct DML

**PROPOSED.** A dedicated non-superuser LOGIN `mtmf_control_exec`, *not* a
member of `mtmf_owner`, `mtmf_migrator`, or `mtmf_runtime`, with no table or
sequence grants, no `BYPASSRLS`/`CREATEROLE`/`CREATEDB`/`SUPERUSER`, safe
`search_path`, and PUBLIC EXECUTE prohibited. Exactly **five** owner-owned
`SECURITY DEFINER SET search_path = ''` private entrypoints (signatures frozen
in §7) granted only to `mtmf_control_exec`. The snapshot wrapper performs no
writes (it may take the assignment row lock) and returns persisted facts only;
the mutation wrappers lock replay/target/
entitlement, revalidate persisted authorization, invoke the existing v014
functions with the verified operator Principal, append audit/replay atomically,
return a bounded JSON result, and never accept SQL text, function names, Role
URNs, `root=true`, Tenant context, or arbitrary Actions. `mtmf_control_exec`
cannot execute v014/v015 owner-only mutations directly. The runtime allowlist
stays exactly **78**. Which wrapper performs which check, and the one
transaction that spans them, are frozen in **§6B**.

**Supporting evidence.** `roles.py` (`provision_roles`, role verifiers,
`expected_runtime_signatures` = 78), `scripts/mtmf-provision-roles.py`;
v014/v015 grants revoked from PUBLIC and not granted to runtime; live role
catalog has no control role.

**Threat assumptions.** The DB cannot verify a remote JWT; the control process
is the trusted JWT boundary and the wrapper independently rechecks persisted
facts as defense in depth. This limitation must be recorded as residual risk.
The SQL side never performs general policy evaluation and never returns ALLOW;
its exact-Action check is a deny-only equality guard (see §6B).

**Required deployment.** Extend approved role provisioning to create
`mtmf_control_exec` without altering `mtmf_runtime`; secret delivered only by
private mount. If the existing provisioning topology cannot create and verify
this distinctly, STOP-ROLE-PROVISIONING.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 8 — Immutable operator/entitlement provenance, atomic audit schema, duplicate/no-op classification

**PROPOSED.** `system_operator_execution` (immutable operation identity,
fingerprint, exact Action, target, outcome `CREATED|REVOKED|NO_OP`, result,
completion time) and `system_operator_execution_audit` (append-only immutable
event bound to the operation with canonical operator Identity/Principal, exact
Action, target, safe lifecycle before/after, outcome, fixed executor DB role,
timestamp). UPDATE/DELETE prohibited by owner-owned triggers even under nominal
write roles. Exactly one mutation-outcome audit per newly committed operator
change; no fabricated success audit for DENY/no-op; no token, secret, free-form
untrusted body, unsafe subject/email, or raw permission explanation. Refusal/
transport telemetry is safe, external to the DB transaction, and cannot
authorize. `grant` returning false for an existing/conflicting target is
**CONFLICT** with no success row; `revoke` of an already-terminal entitlement is
**NO_OP** only when the exact target is authorized and the fingerprint is valid.

**Supporting evidence.** PR 19C `VerifiedMutationProvenance` and atomic `v012`
audit (`application/mutation_provenance.py`) — application-verified provenance,
not PostgreSQL cryptographic user attestation; v014 event history is
append-only.

**Threat assumptions.** Assumes durable *denial* audit is not required in PR
24P; if it is, that needs a new privileged path and STOP-AUDIT-POLICY.

**Required deployment.** PostgreSQL `0016` tables with owner-only permissions.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 9 — Replay fingerprint/nonce and concurrency semantics

**PROPOSED.** Canonical non-nil `operation_id` UUID plus a fixed bounded
canonical payload. Worker-generated SHA-256 fingerprint over the exact field set
in §6; the operator cannot supply or override it. Unique
`(operator_identity_id, operation_id)` ledger row locked/inserted atomically
with the mutation and audit. Identical completed request returns the prior
persisted result after re-verifying operator proof/current assignment, without
another mutation; changed fingerprint rejects; revoked assignment or changed
target state is rechecked before any new mutation; no generic automatic retries
of SQL errors. Reads create no mutation replay state: the §6A snapshot is
read-only and only the mutation wrapper writes the ledger (§6B).

**Supporting evidence.** No durable replay ledger exists for operator
operations; PR 22B owns the separate first-Tenant quota/replay ledger.

**Threat assumptions.** Assumes the fingerprint encoding (length-prefixed
fields, exact bytes, no case folding) is the sole canonicalization and that
`jsonb` result storage does not reorder security-relevant fields.

**Required deployment.** Unique constraint/index plus row lock inside the
wrapper's transaction.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 10 — Single PostgreSQL transaction, lock order, no network I/O under locks, PR 22B one-transaction feasibility

**PROPOSED.** One control-process-owned PostgreSQL connection/transaction
spanning decision recheck + exact mutation + audit + replay result. All IdP/
JWKS/attestation I/O completes **before** `BEGIN`. Declared lock order:
assignment → identity/principal/binding revalidation → operation/replay key →
target Application → active entitlement (§6B);
non-overlapping input validation before locks; no deadlock retries. The wrapper
may call owner-owned v014 functions without an independent `COMMIT`. For PR 22B,
one closed owner-executed composite must call PR 23 B1+B2 plus registration/
subscription/quota/replay under the same transaction. PR 24P implements **no**
multi-transaction choreography and **no** runtime escalation.

The **exact** split between Python policy evaluation and SQL persisted-state
revalidation, the check order, the fact that the snapshot locks only the
assignment row (not the target/replay rows or the other operator facts), and the
single `BEGIN`→snapshot→
Authorizer→wrapper→`COMMIT` boundary are frozen in **§6B**. In particular, the
snapshot must not lock the target or replay key, so the declared order is
preserved across the two wrapper calls; the mutation wrapper owns the replay
and target locks.

**Supporting evidence.** v014/v015 functions are non-committing and owner-only;
`PostgresMtmfSpi`/UnitOfWork boundaries exist; the plan's §B5 requires a typed
fail-closed `PrivilegedOnboardingTransactionPort` with no default
implementation.

**Threat assumptions.** Assumes the existing v014 lock acquisition order is
compatible with the declared order. If not, STOP-LOCK-ORDER and record the
actual SQL paths rather than adding retries. A concurrent assignment revocation
either commits before the snapshot lock (request denied) or waits behind the
in-flight transaction (the operation was authorized before revocation
committed); there is no state where a mutation commits after an effective
revocation it did not observe.

**Required deployment.** Statement/lock timeouts consistent with existing
runtime policy; no network calls under the transaction.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 11 — Secret custody and rotation; explicit host Podman/WSL2/Linux namespaces and privileges

**PROPOSED.** The `mtmf_control_exec` credential is delivered only through an
owner-only secret file or Podman secret mount to the isolated control process —
never via `mtmf-service` env, logs, repository, `mtmf_runtime` container mount,
process arguments, public API, shell history, or a shared volume. The control
process runs as a non-root UID without privileged host socket mounts. Rotation:
stop the isolated executor, rotate the DB secret, redeploy, verify the old
secret fails and the normal runtime is unaffected. The control process also
holds, separately, the existing restricted-runtime read credential for PR 23
`PostgresMtmfSpi` reads; the two pools are never transactionally mixed.

**Supporting evidence.** `.env.example` documents only admin/migrator/runtime
identities; `scripts/mtmf-provision-roles.py` handles migrator/runtime
passwords; there is no control secret.

**Threat assumptions.** Host/WSL2 secret-mount semantics must be verified;
if secrets are mutually readable by the runtime UID, STOP.

**Required deployment.** Secret mount path, perms, and rotation runbook; host
resource identifiers in §8.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

### Field 12 — Compromised-runtime assumptions, proof tests, residual risk

**PROPOSED.** Assume an attacker controls MTMF HTTP service code and knows its
OAuth and `mtmf_runtime` credentials, can send arbitrary public API requests
and runtime-permitted database commands, and can fabricate request headers and
DTOs. The attacker must **not** be able to: connect to the control Unix socket,
connect to the separate pre-Tenant admission socket, read the control secret,
access control-process memory, invoke private wrappers, authenticate as
`mtmf_control_exec`, or use PUBLIC/inherited/schema privileges or a
`SECURITY DEFINER` proxy to reach privileged functions. These must be proven
with **real deployed principals/namespaces**, not unit-test monkeypatches
(ISO-01…ISO-08). A compromised *trusted control-plane process* is explicitly
privileged and remains residual risk subject to isolation, credential rotation,
logging, and human approval; the project will not claim containment it cannot
prove. A compromised *trusted ingress* may submit arbitrary token pairs and
cause load, but obtains no write, operator authority, secret, or Tenant/Role
data because §5A re-verifies both tokens and bounds the response.

**Supporting evidence.** No isolation topology exists yet; the agent cannot
claim PASS. The current dev deployment (single Compose PostgreSQL + service
image) does not demonstrate distinct runtime/control UIDs or secret separation.

**Threat assumptions.** Network/mount/UID isolation is real, not simulated.

**Required deployment.** The full §8 values plus a runnable negative-control
harness; otherwise ISO-03/ISO-04 are `BLOCKED_ENV`, never PASS.

**Decision (human, required):** ☐ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** ______________________________________
**Approver / date / decision ID:** ______________________________________________

---

## 5. Frozen private operator protocol v1 (proposed — for approval, verbatim)

Single length-prefixed message: `uint32` big-endian unsigned frame length, then
UTF-8 JSON, at most **16,384 bytes**. Socket read deadline **5 seconds**, one
request per connection, no unsolicited output. Reject duplicate JSON keys,
unknown keys, embedded NUL, noncanonical UUID strings, non-integer `v`,
non-integer quota, negative/zero quota, malformed UTF-8, and any request above
the size limit. Only these operation-dependent key sets are allowed:

```text
entitlement.grant:
  v=1, operation="entitlement.grant",
  operation_id=<canonical nonnil UUID>,
  operator_access_token=<nonempty approved user access token, <=8192 bytes>,
  application_id=<canonical UUID>,
  entitlement_id=<canonical fresh UUID>,
  quota_total=<positive signed 64-bit integer>,
  reason=<UTF-8 string 1..512 codepoints, exactly trimmed>

entitlement.revoke:
  v=1, operation="entitlement.revoke",
  operation_id=<canonical nonnil UUID>,
  operator_access_token=<approved user access token>,
  application_id=<canonical UUID>,
  entitlement_id=<canonical UUID>,
  reason=<UTF-8 string 1..512 codepoints, exactly trimmed>

entitlement.get:
  v=1, operation="entitlement.get",
  operation_id=<canonical nonnil UUID, tracing only>,
  operator_access_token=<approved user access token>,
  application_id=<canonical UUID>,
  entitlement_id=<canonical UUID>

health.private:
  v=1, operation="health.private" ONLY; expected admin peer UID;
  no operator token, role, state/secret disclosure or network calls.
```

**No other fields.** In particular: no `role_urn`, `actor_identity_id`,
`actor_principal_id`, `action_urn`, `target_tenant_id`, `sql`, `approved`,
`root`, `callback`, or client-provided `fingerprint`. The worker chooses the
server-approved Action and resolves actor IDs after token verification.

Response envelope:

```text
success read/mutation:
  {"v":1,"operation_id":"<canonical uuid>","outcome":"CREATED|REVOKED|NO_OP|FOUND",
   "application_id":"<uuid>","entitlement_id":"<uuid>","entitlement":{...}}
failure:
  {"v":1,"operation_id":"<uuid-or-null>","error":"INVALID|UNAUTHENTICATED|
      FORBIDDEN|CONFLICT|UNAVAILABLE"}
```

`entitlement` is the existing detached v014 approved JSON projection with no
secrets; on a denied/hidden target it is never included. `health.private` yields
only `{"v":1,"healthy":true}` or closes. There are no HTTP status codes. The
worker never includes underlying SQLSTATE, subject, actor, or exception text.

## 5A. Frozen private pre-Tenant admission protocol v1 (proposed — for approval, verbatim)

This is the **second** private interface. It is not the operator interface and
must not share its socket, peer UID, handler, operation namespace, response
envelope, or database privileges with the operator path. It is the only
interface permitted to evaluate first-Tenant *candidacy*, and it never
provisions, reserves quota, or authorizes an operator Action.

### 5A.1 Trust contract

- **Separate transport.** A second `AF_UNIX` `SOCK_STREAM` owned by
  `mtmf-control-plane`, at its own deployment-recorded path/mode (§8), with a
  **single approved dedicated ingress UID**. `SO_PEERCRED` must equal that UID
  exactly. Missing/unknown peer credentials, `root`/UID 0, group-only access,
  the administrative operator UID, the control worker UID, and the
  `mtmf_runtime` UID are rejected. The operator socket rejects the ingress UID;
  the admission socket rejects the operator and runtime UIDs. There is no TCP
  fallback, no shared listener, and no localhost shortcut.
- **Ingress is transport-authenticated, not claim-trusted.** The ingress may
  supply only the two raw tokens and a tracing request ID (§5A.3). It may not
  supply or override `application_id`, `issuer`, `subject`, identity/principal
  IDs, entitlement IDs, Tenant IDs, Role/Action, `approved`, `root`, or a
  fingerprint. The worker independently derives every value.
- **Independent double verification.** The worker runs the approved
  attestation + JWKS/signature/issuer/audience/class/`azp`/temporal checks and
  the PR 23 `PreTenantSubjectVerificationService` itself, exactly as for the
  genuine-token tests. The ingress is never an authorization oracle.
- **No callable public interface in PR 24P.** PR 24P ships the handler as a
  private typed port. Only an isolated test harness may bind the admission
  socket, under the dedicated test ingress UID, with genuine signed tokens and
  real PostgreSQL. The production manifest must not create the admission
  socket, publish a route, or give any `mtmf_runtime` process a proxy to it.
  PR 24 may expose it only through the separately approved trusted ingress.
- **Compromise bounds.** A compromised ingress can submit arbitrary token pairs
  and cause load/telemetry noise; it obtains no write, no operator authority, no
  control secret, no privileged wrapper access, and no Tenant/Role/assignment
  data. A compromised worker remains the documented residual risk (§Field 12).

### 5A.2 Framing and limits

Same framing rules as §5: one `uint32` big-endian length-prefixed UTF-8 JSON
message per connection, read deadline **5 seconds**, no unsolicited output, no
pipelining, reject duplicate keys, unknown keys, embedded NUL, noncanonical UUID
strings, non-integer `v`, malformed UTF-8, and any over-limit frame. The frame
limit is **32,768 bytes** (two `<=8192`-byte tokens plus the fixed envelope),
not the operator path's 16,384. Tokens are never echoed, logged, or retained.

### 5A.3 Exact request (no other fields)

```text
admission.prepare:
  v=1, operation="admission.prepare",
  request_id=<canonical nonnil UUID, tracing only>,
  service_access_token=<nonempty approved Application service token, <=8192 bytes>,
  user_access_token=<nonempty approved interactive user token, <=8192 bytes>
```

No other fields. In particular: no `application_id`, `issuer`, `subject`,
`actor_identity_id`, `actor_principal_id`, `entitlement_id`, `tenant_id`,
`role_urn`, `action_urn`, `quota_total`, `sql`, `approved`, `root`, `callback`,
or client-provided fingerprint. `request_id` is tracing only and creates no
durable replay state.

### 5A.4 Exact response (bounded, non-authorizing)

```text
success:
  {"v":1,"request_id":"<canonical uuid>",
   "outcome":"CANDIDATE|EXISTING_SUBJECT|NO_ENTITLEMENT",
   "eligible_for_first_tenant":true|false,
   "application_id":"<uuid>","entitlement_id":"<uuid-or-null>"}
failure:
  {"v":1,"request_id":"<uuid-or-null>",
   "error":"INVALID|UNAUTHENTICATED|FORBIDDEN|CONFLICT|UNAVAILABLE"}
```

| Outcome | Meaning | `eligible_for_first_tenant` | `entitlement_id` |
| --- | --- | --- | --- |
| `CANDIDATE` | Verified new global subject + ACTIVE entitlement + preliminary quota available (computed from `quota_consumed < quota_total`). **Non-authorizing observation only.** | `true` | the ACTIVE entitlement UUID |
| `EXISTING_SUBJECT` | Exact `(issuer, subject)` already resolves to an active global Identity/Principal. Existing-Tenant resolution belongs to PR 22B/24. | `false` | `null` |
| `NO_ENTITLEMENT` | Verified new subject but entitlement absent/REVOKED/expired/exhausted. | `false` | `null` |
| `CONFLICT` (error) | Revoked-only or conflicting subject history; never silently rebind. | — | — |

The response never contains a token, subject, Identity/Principal ID, Tenant ID,
membership, Role, Permission, assignment, registration, subscription, quota
counter, Action ALLOW, or SQLSTATE. `application_id` is the Application resolved
from the verified service credential, never a request value. No quota is
consumed or reserved by this response.

### 5A.5 Exact read path and boundary

```text
verify SO_PEERCRED == dedicated ingress UID
 -> decode exact request (no DB)
 -> fresh realm/client attestation + verify service AND user tokens (no DB)
 -> PR 23 PreTenantSubjectVerificationService.verify(service_token, user_token)
      using the restricted-read mtmf_runtime UoW (no Tenant/Role/membership)
 -> if existing valid subject: EXISTING_SUBJECT (no entitlement read)
 -> else control-role-only mtmf.control_pre_tenant_entitlement_read(application_id)
      read-only, no lock held beyond the statement, no write
 -> CANDIDATE | NO_ENTITLEMENT | CONFLICT
 -> typed VerifiedPreTenantAdmission (candidate only)
 -> response
```

- All attestation/JWKS/token I/O completes **before any database access**.
- The PR 23 restricted-read UoW and the control-role read are separate
  credentials/connections and are **never** transactionally mixed; PR 24P opens
  **no** privileged write transaction on this path.
- No Identity/Principal/binding, Tenant, membership, registration,
  subscription, quota, replay, or audit-success row is written. No `COMMIT` of
  any mutation. `request_id` is not a replay ledger.
- The admission handler **must not read `system_operator_assignment`**, and the
  operator handler **must not use an Application entitlement** to authorize an
  operator Action. The two evidence types never cross.
- The only entitlement read is the frozen
  `control_pre_tenant_entitlement_read(application_id)` (§7); the operator
  `control_entitlement_get(...)` is not callable from this handler.
- `CANDIDATE` cannot invoke the future composite: PR 24P's
  `PrivilegedOnboardingTransactionPort.execute_approved_composite` remains
  unimplemented and fail-closed. PR 22B must repeat every authoritative check
  under its own serialized transaction and owns the quota/replay ledger.
- Stale entitlement state between the preliminary read and a future PR 22B
  transaction is acceptable **only** because the candidate is non-authorizing;
  PR 22B must reject a changed/revoked entitlement during its locked recheck
  (PT-I07).

### 5A.6 Private executor port (PR 24P: unimplemented, fail-closed)

The separate admission interface ends at a typed port. PR 24P freezes exactly
this contract and provides **no implementation and no default**:

```python
class PrivilegedOnboardingTransactionPort(Protocol):
    def execute_approved_composite(
        self,
        verified_proof: VerifiedPreTenantAdmission,
        checked_request: CheckedFirstTenantRequest,
    ) -> FirstTenantCompositeResult: ...
```

- `VerifiedPreTenantAdmission` is the frozen §A1 type (`verified_subject`,
  `entitlement_id`, `eligible_for_first_tenant`, `checked_at`). A call with
  `eligible_for_first_tenant=False` or a non-candidate proof is rejected before
  any DB access.
- `CheckedFirstTenantRequest` and `FirstTenantCompositeResult` are frozen,
  typed, **PR 22B-owned** DTOs. They are not `dict`, kwargs, JSON blobs,
  callables, SQL text, function names, or arbitrary operation dispatchers, and
  PR 24P does not invent their tenant/registration/subscription/quota fields.
- PR 24P supplies a single fail-closed placeholder that raises a typed
  "not implemented" error before opening a connection or transaction. There is
  no environment flag, config switch, plugin loader, or test double that enables
  a real composite. Tests may inject a recording stub to prove it is not called.
- When PR 22B implements it, the implementation is exactly one closed
  owner-executed `SECURITY DEFINER` composite on one transaction, calling the
  existing v015 B1/B2 participants and owning quota/replay/registration/
  subscription/activation/audit; it is not a Python callback bridge and not a
  second policy engine.
- Neither the operator socket nor the admission handler may call an
  implementation of this port in PR 24P; the operator path is never an
  onboarding executor, and the admission path is never an operator executor.

## 6. Frozen canonical mutation fingerprint (worker-generated, SHA-256 — proposed, verbatim)

Encode each field as a 4-byte unsigned big-endian byte length plus exact bytes;
concatenate fields in this exact order:

```text
ASCII "mtmf.pr24p.operator.v1"
UTF-8 operation literal
16-byte verified operator Identity UUID
16-byte verified Principal UUID
UTF-8 verified issuer
UTF-8 verified subject
16-byte Application UUID
16-byte Entitlement UUID
8-byte signed big-endian quota (grant)  |  zero-length field (revoke)
UTF-8 reason
```

All text is exact and never case-folded; the reason was already rejected unless
trimmed. **The operation UUID is the replay-ledger key, not part of this
fingerprint.** A precisely 32-byte fingerprint is passed to the reviewed
wrapper. The operator cannot provide or override it. A read creates no mutation
replay state.

The authorization snapshot schema is frozen in **§6A**; the split of duties
between Python policy evaluation and SQL persisted-state revalidation, and the
transaction/lock boundary, is frozen in **§6B**. The entitlement read returns
`entitlement_id`, `application_id`, `state`, `quota_total`, `quota_consumed`,
or an explicit absence marker; never an Action ALLOW.

## 6A. Frozen persisted-domain-identity authorization snapshot (proposed — verbatim)

`mtmf.control_operator_authorization_snapshot(...)` performs **no writes** (it
may take the assignment row lock) and returns exactly this bounded JSON object
and no other fields. UUIDs are canonical strings; timestamps are UTC RFC 3339;
enum values are the persisted numeric or string values with the documented
meaning shown here.

```text
{
  "v": 1,
  "operator": {
    "identity": {
      "id": "<uuid>",
      "principal_id": "<uuid>",
      "origin": 1|2,                 // 1=LOCAL, 2=FEDERATED
      "deletion_status": 1|2,        // 1=DELETED, 2=NOT_DELETED
      "canonical_root": false
    },
    "principal": {
      "id": "<uuid>",
      "deletion_status": 1|2,
      "canonical_root": false
    },
    "binding": {
      "id": "<uuid>",
      "issuer": "<exact persisted issuer>",
      "subject": "<exact persisted subject>",
      "identity_id": "<uuid>",
      "lifecycle": 1                   // 1=ACTIVE only
    }
  },
  "assignment": {
    "id": "<uuid>",
    "identity_id": "<uuid>",
    "principal_id": "<uuid>",
    "role_urn": "urn:mtmf:iam:roles:system:application-administrator",
    "state": 1,                        // 1=ACTIVE only
    "created_at": "<utc>",
    "revoked_at": null
  },
  "role": {
    "urn": "urn:mtmf:iam:roles:system:application-administrator",
    "name": "<persisted role name>",
    "description": "<persisted role description>",
    "defining_tenant_id": null,        // SYSTEM Role: no defining Tenant
    "builtin": true,
    "approved_role": true
  },
  "permission_sets": [
    {"id": "<uuid>", "role_urn": "<role urn>", "effect": "allow"|"deny", "position": 0}
  ],
  "permissions": [
    {"id": "<uuid>", "permission_set_id": "<uuid>", "urn": "<permission urn>", "position": 0}
  ],
  "target": {
    "kind": "APPLICATION"|"ENTITLEMENT",
    "application_id": "<uuid>",
    "entitlement_id": null|"<uuid>"
  },
  "checked_at": "<utc>"
}
```

**Why this schema (Finding B).** These are the persisted **domain identity**
records required to reconstruct the existing aggregates — `Identity`,
`Principal`, `ExternalSubjectBinding`, `Role`, `PermissionSet`, `Permission` —
and to perform every §A3 check without a second query:

- `Identity.origin` / `deletion_status`, `Principal.deletion_status`, the exact
  active `(issuer, subject) -> identity` binding, and the canonical-root flags
  from `mtmf.root_registry` establish that the operator is an active, non-root,
  FEDERATED Identity of the claimed Principal.
- The `Role` record's persisted `defining_tenant_id` (NULL) and SYSTEM URN
  establish the SYSTEM definition namespace; the persisted `builtin_role`
  marker and the exact-URN `approved_role` validation establish that the
  aggregate is the exact approved SYSTEM Role, not a Tenant Role or an
  unapproved clone. `builtin`/`approved_role` are validation flags derived from
  those persisted facts, not new mutable authorization inputs.
- `permission_sets` carry the **effect** (effect belongs to the PermissionSet,
  never to the Permission); `permissions` carry the Permission URN and both
  structural positions. This is sufficient to reconstruct existing internal
  `Role` objects for `Authorizer.authorize_global_system` without a second
  policy engine. Ordering is deterministic but never authorization precedence.
- The `assignment` record is the new persisted global association; it is not
  Tenant membership and carries no Tenant facts.

**Snapshot rules.**

- The wrapper resolves and validates the exact ACTIVE
  `(issuer, subject) -> identity`, `identity -> principal`, identity origin
  FEDERATED, both non-deleted, neither canonical root, and the ACTIVE
  assignment for the exact Identity + Principal + approved SYSTEM Role. Failure
  is `MT050`; malformed input is `MT049`.
- It **locks only the `system_operator_assignment` row** (`FOR UPDATE`) so a
  concurrent revocation is serialized. The Identity/Principal/binding/Role/
  PermissionSet/Permission facts are read and validated in the same statement
  but are **not** locked here; the mutation wrapper re-locks and revalidates the
  identity/principal/binding facts before writing (§6B.2 step 8). It must not
  lock or write the replay key, Application, or entitlement; those locks belong
  to the mutation wrapper. It must not read Tenant membership, stewardship,
  entitlements, or quota. The `application_id_value` / `entitlement_id_value`
  arguments are validated as canonical non-nil IDs and echoed in `target`; they
  are **not** used to read or validate target rows in the snapshot.
- The approved SYSTEM Role, PermissionSet and Permission rows are installation-
  seeded, immutable built-in policy protected by `builtin_role`; installation/
  migration is not concurrent with control traffic. They are deliberately not
  locked. If a future design permits online builtin-policy mutation during
  serving, the agent must STOP-LOCK-ORDER rather than silently add or reorder
  locks.
- It returns **no** `allowed`, decision, capability token, or Action ALLOW; a
  Role existing is not an authorization result. It performs no writes and
  creates no replay state.
- The exact `assignment.role_urn`, `role.urn`, and approved Role URN must agree
  with the single PR 24P approved Role. A different/unknown/mismatched Role is
  a fail-closed integrity error, never a silent non-match.
- The control process requires `snapshot.operator.binding.issuer` /
  `.subject` to equal the verified operator proof's exact `(issuer, subject)`
  (case-sensitive, no normalization), and requires the snapshot Identity to
  equal `VerifiedSystemOperator.identity_id` and the Principal to equal
  `principal_id`. Any mismatch is a fail-closed integrity failure.
- Display metadata (`Identity.name`, `Principal.name`) and every `extension`
  field are excluded and must never affect authorization. `Role.name` and
  `Role.description` are included only because the persisted `Role` aggregate
  carries them; they are not authorization inputs.
- The transient `issuer`/`subject` values exist only for exact binding
  verification. The control process never logs or persists them; the durable
  audit stores canonical operator Identity/Principal IDs and no token or raw
  subject.
- The control process rejects any missing, unknown, duplicate, non-ACTIVE,
  mismatched, naive-timestamp, or root-marked field as a fail-closed
  infrastructure/integrity failure. It never converts a malformed snapshot into
  ALLOW.

## 6B. Frozen policy-evaluation vs SQL-revalidation responsibilities and transaction boundary (proposed — verbatim)

### 6B.1 Non-overlapping responsibility table

| # | Check | Owner | Timing | Authority |
| --- | --- | --- | --- | --- |
| 1 | Peer UID admission; bounded/canonical request decode | Transport/control process | Before any DB | Sole |
| 2 | Fresh realm/client attestation; JWKS, signature, issuer, audience, signed `azp`, token class, temporal validity | Control process (approved verifier/attestor) | Before `BEGIN` | Sole for token authenticity |
| 3 | Exact `(issuer, subject)` → ACTIVE FEDERATED Identity, Identity→Principal, both non-deleted/non-root; ACTIVE global assignment; exact approved SYSTEM Role + `builtin_role` + PermissionSet/Permission records | SQL `control_operator_authorization_snapshot` | Inside the one transaction; assignment row locked | Sole for persisted facts |
| 4 | Proof unexpired at admission and again immediately before the mutation call; target kind matches Action; exact Action is one of the approved global pairs; compiled Permission evaluation with exact/wildcard specificity and DENY precedence | Python `Authorizer.authorize_global_system` on the §6A snapshot | Inside the same transaction, **no DB I/O** | Sole general policy engine |
| 5 | Target Application/entitlement existence, lifecycle eligibility, entitlement belongs to that Application, correct current state; **re-lock and revalidate the operator identity/principal/binding**; replay key uniqueness/fingerprint; mutation + audit + replay result | SQL mutation wrapper | Inside the same transaction; identity/principal/binding `FOR SHARE`, then replay→Application→entitlement locked | Sole for target/replay/revalidated-operator state |
| 6 | Exact-Action **deny-only** equality guard: the exact Permission URN for the fixed operation is present in an `ALLOW` PermissionSet owned by the approved Role. The guard does not inspect wildcard matches, specificity, or DENY precedence; Python owns those. | SQL mutation wrapper | Inside the same transaction, after locks | Defense in depth only; can reject, never authorize |
| 7 | Detached result/response envelope; append-only audit read-back | Control process | After `COMMIT` | Presentation only |

**Forbidden overlaps (fail-closed):**

- SQL must not implement wildcard Permission matching, specificity ordering,
  DENY precedence, or a general policy engine. Its check is the narrow
  persisted-data equality guard in row 6 and cannot broaden the Python decision.
- Python must not treat the pre-`BEGIN` restricted-read actor resolution or the
  snapshot as final target/replay state; only the mutation wrapper's locked
  revalidation is authoritative for those facts.
- Python must not issue its own SQL or open a second connection inside the
  transaction; the snapshot and mutation wrapper run on the **same** control
  connection and transaction.
- No wrapper may return ALLOW, a capability token, or a decision; only the
  `Authorizer` returns an `AuthorizationDecision`.

### 6B.2 Exact execution and transaction boundary

```text
1. verify SO_PEERCRED == approved administrative UID; decode exact operation
   (no DB)
2. fresh attestation + JWKS/signature/issuer/audience/azp/class/temporal
   verification of the operator user token (no DB)
3. read-only restricted mtmf_runtime UoW: exact (issuer,subject) -> active
   FEDERATED Identity + active Principal; construct VerifiedSystemOperator
   (no Tenant, Role, assignment, or write). This UoW is closed before step 4.
4. control connection: BEGIN (READ COMMITTED)
5. control_operator_authorization_snapshot(...): lock assignment FOR UPDATE;
   read and validate identity/principal/binding/role policy facts; return §6A
   JSON
6. Authorizer.authorize_global_system(VerifiedSystemOperator, snapshot Role +
   assignment, typed global target, server-selected exact Action): check proof
   unexpired; exact Action/target pair; existing compiled policy semantics.
   DENY/error -> ROLLBACK, no mutation, no audit success.
7. re-check proof unexpired immediately before the mutation call
8. control_entitlement_{grant|revoke|get}(...): lock and revalidate
   identity/principal/binding FOR SHARE; lock (grant/revoke) operation/replay
   key -> Application -> entitlement; revalidate assignment and exact-Action
   guard; invoke existing v014 with verified operator Principal; write mutation +
   append-only audit + replay result atomically; return bounded JSON
9. COMMIT exactly once
10. build detached response; no further DB reads required for the result
```

- **No external I/O** (IdP, JWKS, KMS, network, socket read, telemetry emission)
  between `BEGIN` and `COMMIT`. Token-expiry checks in steps 6/7 are local time
  comparisons only.
- **Lock order is exactly:** operator assignment (`FOR UPDATE`, step 5) →
  identity/principal/binding (`FOR SHARE`, step 8 revalidation) → operation/
  replay key → target Application → active entitlement (step 8). The snapshot
  must not acquire the target/replay locks, and the wrapper's operator-fact
  revalidation must precede the replay/target locks; a plain MVCC read is not a
  lock and must not be used to pre-authorize target state. A concurrent
  revocation or identity soft-delete either commits before the relevant lock
  (denied) or waits behind the in-flight transaction; the wrapper never mutates
  against operator facts it has not revalidated under lock.
- **Isolation:** default READ COMMITTED with explicit row locks; no
  SERIALIZABLE, no automatic deadlock retries. Any lock timeout, deadlock, or
  SQL error aborts the whole transaction.
- Any error/timeout/interruption before `COMMIT` rolls back **all** effects,
  including audit and replay. A lost response after commit is reconciled by
  `operation_id` + fingerprint with fresh operator proof and current
  authorization (§Field 9); the committed mutation is never re-run.
- The pre-`BEGIN` restricted read uses the separate `mtmf_runtime` credential
  and is never mixed transactionally with the control connection.
- For the future PR 22B composite, the **same** boundary applies: one closed
  owner-executed `SECURITY DEFINER` composite performs every B1/B2, quota,
  replay, registration, subscription, activation and audit effect in this one
  transaction. PR 24P implements no multi-transaction choreography and the
  `PrivilegedOnboardingTransactionPort` remains unimplemented/fail-closed.

### 6B.3 Approval is required for the split

Approving the topology without approving §6A/§6B leaves `STOP-SIGNATURE` and
`STOP-LOCK-ORDER` active. These sections may not be reformulated during
implementation.

## 7. Frozen private SQL signatures for revision `0016` (proposed — verbatim)

Owner-owned; granted only to `mtmf_control_exec`:

```sql
mtmf.control_entitlement_grant(
  operator_identity_id_value uuid,
  operator_principal_id_value uuid,
  operator_issuer_value text,
  operator_subject_value text,
  application_id_value uuid,
  entitlement_id_value uuid,
  quota_total_value bigint,
  reason_value text,
  operation_id_value uuid,
  request_fingerprint_value bytea
) RETURNS jsonb

mtmf.control_entitlement_revoke(
  operator_identity_id_value uuid,
  operator_principal_id_value uuid,
  operator_issuer_value text,
  operator_subject_value text,
  application_id_value uuid,
  entitlement_id_value uuid,
  reason_value text,
  operation_id_value uuid,
  request_fingerprint_value bytea
) RETURNS jsonb

mtmf.control_entitlement_get(
  operator_identity_id_value uuid,
  operator_principal_id_value uuid,
  operator_issuer_value text,
  operator_subject_value text,
  application_id_value uuid,
  entitlement_id_value uuid
) RETURNS jsonb

mtmf.control_operator_authorization_snapshot(
  operator_identity_id_value uuid,
  operator_principal_id_value uuid,
  operator_issuer_value text,
  operator_subject_value text,
  application_id_value uuid,
  entitlement_id_value uuid
) RETURNS jsonb

mtmf.control_pre_tenant_entitlement_read(
  application_id_value uuid
) RETURNS jsonb
```

Arguments are **data supplied by the trusted control process after JWT
verification**, not cryptographic DB authentication evidence. The wrapper
independently checks that the ACTIVE exact `(issuer, subject)` binding resolves
to `operator_identity_id_value`, that the Identity belongs to
`operator_principal_id_value`, that both are active and non-root, and that a
still-ACTIVE `system_operator_assignment` grants the exact Role. Its exact-Action
check is the deny-only equality guard in §6B.1 row 6; it never returns ALLOW.
The `GET` wrapper is read-only; mutation wrappers reuse v014 and write atomic
audit/replay.

**Reserved SQLSTATEs (proposed):** `MT049` malformed/unacceptable private-control
input or wrong canonical actor/target; `MT050` denied/missing SYSTEM assignment
or exact Action mismatch; `MT051` replay fingerprint conflict/concurrent state
conflict. All fail closed, never map to ALLOW, never disclosed through the
protocol. If these are already allocated on the branch, the agent stops
(`STOP-00`) rather than renumbering.

## 8. Deployment-specific values the approving human must record (not agent-selectable)

These are factual host resources. They cannot be responsibly invented in a
portable plan. **Any missing value keeps `STOP-P24P-TOPOLOGY` active.**

| Value | Required decision / recorded value |
| --- | --- |
| Canonical administrative UID allowed by the **operator** socket `SO_PEERCRED` | ______________________________ |
| Dedicated control worker UID / GID | ______________________________ |
| Runtime (`mtmf-service`) UID / GID (explicitly excluded from both sockets) | ______________________________ |
| Operator Unix socket absolute mount path | ______________________________ |
| Operator Unix socket owner / group / mode | ______________________________ |
| Dedicated **pre-Tenant ingress** UID / GID allowed by the admission socket `SO_PEERCRED` | ______________________________ |
| Admission Unix socket absolute mount path | ______________________________ |
| Admission Unix socket owner / group / mode | ______________________________ |
| Isolated control DB secret mount path + permissions | ______________________________ |
| Podman/Compose project name for the control plane | ______________________________ |
| Control-network attachment (and absence of published ports) | ______________________________ |
| Host platform confirmation (WSL2/rootless Podman version, peer-credential behaviour) | ______________________________ |
| Rotation/runbook owner | ______________________________ |

## 9. Top-level decision record (to be completed by the human)

```text
Decision ID:        ______________________________________
Date (UTC):         ______________________________________
Approving party:    ______________________________________
Plan/version approved: MTMF PR 24P detailed execution plan, version 2026-11-12 (rev 2, Findings A–C)
Exact approved text reference / evidence: ______________________________________
Conditions / amendments: ______________________________________
All 12 fields approved verbatim?   YES / NO
Operator protocol §5 approved verbatim? YES / NO
Pre-Tenant admission protocol §5A (including §5A.6 executor port) approved verbatim? YES / NO
Fingerprint §6 approved verbatim?  YES / NO
Authorization snapshot §6A approved verbatim? YES / NO
Policy/SQL responsibility + transaction boundary §6B approved verbatim? YES / NO
SQL signatures §7 approved verbatim? YES / NO
Deployment values §8 complete (including ingress UID + admission socket)? YES / NO
```

## 10. What this document is not

- Not an approval. Every field above is `PROPOSED — NOT APPROVED`.
- Not an implementation authorization. No migration, role, grant, wrapper,
  socket, listener, package, or deployment is created by this artifact.
- Not a claim that the PR 21 Action/Role approval, GitHub merge/review, or a
  request to "execute the plan" clears the topology gate.
- Not a substitute for PR 24 or PR 22B; it does not complete v0.1 onboarding.

## 11. Consequence of the decision

- **All 12 approved verbatim + operator protocol §5 + admission protocol §5A +
  fingerprint §6 + snapshot §6A + responsibility/transaction split §6B +
  signatures §7 approved + deployment values supplied:** the agent resumes
  Parts A–E in order, stopping again at any of the named sub-gates
  (AUTH-PROFILE, POLICY-ENGINE, SEED, ROLE-PROVISIONING, SIGNATURE,
  LOCK-ORDER, AUDIT-POLICY, TRANSACTION, DEPLOYMENT, PRIVILEGE).
- **Any field rejected/amended, or any frozen literal (including §5A/§6A/§6B)
  changed:** the agent records the differences, returns a revised plan, and
  stays blocked. Findings A–C must be approved as frozen text; accepting only
  the concept is not approval.
- **No decision recorded:** status remains `PR24P_BLOCKED_TOPOLOGY_APPROVAL`.
