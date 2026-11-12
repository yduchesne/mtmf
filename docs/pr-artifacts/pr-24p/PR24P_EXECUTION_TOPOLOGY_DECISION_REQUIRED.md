# PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED

**PR:** roadmap **PR 24P** — Operator and Pre-Tenant Privileged Execution Prerequisite
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Plan version:** 2026-11-12 · `DESIGN PROPOSED`
**Prepared by:** coding agent (Phase 0, documentation only)
**Baseline reconciled at:** `8712418a3d2de212791ae75a6235d3e00fced450` (= `origin/main`, PR 23 merged)
**Status:** **`PR24P_BLOCKED_TOPOLOGY_APPROVAL`** — `STOP-P24P-TOPOLOGY` is **ACTIVE**

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

**Supporting evidence.** The public service is the only HTTP surface; there is
no gateway-to-executor transport. `PreTenantSubjectVerificationService` verifies
the token pair itself, which is what makes gateway forwarding safe only if the
worker re-verifies.

**Threat assumptions.** Assumes the gateway can authenticate the Application
service credential and forward raw tokens without becoming an authorization
oracle, and that it never gains operator authority.

**Required deployment.** Gateway identity, ingress transport, and its network
placement (PR 24), or an explicit "test harness only in PR 24P" statement.

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
`Action`. It reuses the existing compiled Permission engine with DENY
precedence; no new permissive evaluator, no `TenantManagementGroup`
substitution, no union with Tenant permissions, no `root=true`.

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
in §7) granted only to `mtmf_control_exec`. Wrappers lock assignment/target/
replay, revalidate persisted authorization, invoke the existing v014 functions
with the verified operator Principal, append audit/replay atomically, return a
bounded JSON result, and never accept SQL text, function names, Role URNs,
`root=true`, Tenant context, or arbitrary Actions. `mtmf_control_exec` cannot
execute v014/v015 owner-only mutations directly. The runtime allowlist stays
exactly **78**.

**Supporting evidence.** `roles.py` (`provision_roles`, role verifiers,
`expected_runtime_signatures` = 78), `scripts/mtmf-provision-roles.py`;
v014/v015 grants revoked from PUBLIC and not granted to runtime; live role
catalog has no control role.

**Threat assumptions.** The DB cannot verify a remote JWT; the control process
is the trusted JWT boundary and the wrapper independently rechecks persisted
facts as defense in depth. This limitation must be recorded as residual risk.

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
of SQL errors. Reads create no mutation replay state.

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
JWKS/attestation I/O completes **before** `BEGIN`. Declared lock order: operator
assignment → operation/replay key → target Application → active entitlement;
non-overlapping input validation before locks; no deadlock retries. The wrapper
may call owner-owned v014 functions without an independent `COMMIT`. For PR 22B,
one closed owner-executed composite must call PR 23 B1+B2 plus registration/
subscription/quota/replay under the same transaction. PR 24P implements **no**
multi-transaction choreography and **no** runtime escalation.

**Supporting evidence.** v014/v015 functions are non-committing and owner-only;
`PostgresMtmfSpi`/UnitOfWork boundaries exist; the plan's §B5 requires a typed
fail-closed `PrivilegedOnboardingTransactionPort` with no default
implementation.

**Threat assumptions.** Assumes the existing v014 lock acquisition order is
compatible with the declared order. If not, STOP-LOCK-ORDER and record the
actual SQL paths rather than adding retries.

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
read the control secret, access control-process memory, invoke private wrappers,
authenticate as `mtmf_control_exec`, or use PUBLIC/inherited/schema privileges
or a `SECURITY DEFINER` proxy to reach privileged functions. These must be
proven with **real deployed principals/namespaces**, not unit-test monkeypatches
(ISO-01…ISO-08). A compromised *trusted control-plane process* is explicitly
privileged and remains residual risk subject to isolation, credential rotation,
logging, and human approval; the project will not claim containment it cannot
prove.

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

The authorization snapshot contains exactly: `identity_id`, `principal_id`,
`application_id`, `entitlement_id`, `role_urn`, `assignment_id`, and a sorted
list of approved Role Permission/PermissionSet records (`permission_urn`,
`effect`, `set_position`, `permission_position`) sufficient to reconstruct
existing internal `Role` objects for `Authorizer.authorize_global_system`
without a second policy engine. The entitlement read returns `entitlement_id`,
`application_id`, `state`, `quota_total`, `quota_consumed`, or an explicit
absence marker; never an Action ALLOW.

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
still-ACTIVE `system_operator_assignment` grants the exact Role/Action. The `GET`
wrapper is read-only; mutation wrappers reuse v014 and write atomic audit/replay.

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
| Canonical administrative UID allowed by `SO_PEERCRED` | ______________________________ |
| Dedicated control worker UID / GID | ______________________________ |
| Runtime (`mtmf-service`) UID / GID (explicitly excluded) | ______________________________ |
| Unix socket absolute mount path | ______________________________ |
| Unix socket owner / group / mode | ______________________________ |
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
Plan/version approved: MTMF PR 24P detailed execution plan, version 2026-11-12
Exact approved text reference / evidence: ______________________________________
Conditions / amendments: ______________________________________
All 12 fields approved verbatim?   YES / NO
Protocol §5 approved verbatim?     YES / NO
Fingerprint §6 approved verbatim?  YES / NO
SQL signatures §7 approved verbatim? YES / NO
Deployment values §8 complete?     YES / NO
```

## 10. What this document is not

- Not an approval. Every field above is `PROPOSED — NOT APPROVED`.
- Not an implementation authorization. No migration, role, grant, wrapper,
  socket, listener, package, or deployment is created by this artifact.
- Not a claim that the PR 21 Action/Role approval, GitHub merge/review, or a
  request to "execute the plan" clears the topology gate.
- Not a substitute for PR 24 or PR 22B; it does not complete v0.1 onboarding.

## 11. Consequence of the decision

- **All 12 approved verbatim + signatures/protocol/fingerprint approved +
  deployment values supplied:** the agent resumes Parts A–E in order, stopping
  again at any of the named sub-gates (AUTH-PROFILE, POLICY-ENGINE, SEED,
  ROLE-PROVISIONING, SIGNATURE, LOCK-ORDER, AUDIT-POLICY, TRANSACTION,
  DEPLOYMENT, PRIVILEGE).
- **Any field rejected/amended, or any frozen literal changed:** the agent
  records the differences, returns a revised plan, and stays blocked.
- **No decision recorded:** status remains `PR24P_BLOCKED_TOPOLOGY_APPROVAL`.
