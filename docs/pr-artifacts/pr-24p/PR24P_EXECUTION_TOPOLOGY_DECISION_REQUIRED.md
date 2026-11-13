# PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED

**PR:** roadmap **PR 24P** — Operator and Pre-Tenant Privileged Execution Prerequisite
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Plan version:** 2026-11-12 (rev 4: independent-review Findings A–D + Amendment E development bootstrap) · `GATE A APPROVED` against merged architecture commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; Gate B approved via `MTMF-PR24P-GATE-B-2026-11-13-01`
**Prepared by:** coding agent (Phase 0, documentation only)
**Baseline reconciled at:** `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` (= `origin/main`, rev 3 merged via PR #76); original Phase 0 baseline `8712418a3d2de212791ae75a6235d3e00fced450`
**Status:** **Gate A and Gate B APPROVED** (`MTMF-PR24P-GATE-A-2026-11-13-01`, `MTMF-PR24P-GATE-B-2026-11-13-01`); `STOP-P24P-TOPOLOGY` clears on PR #78 merge; Gate C NOT EXECUTED

## 0. Amendment history and independent-review disposition

**Subsequent human decision (2026-11-13).** The user explicitly answered
**yes** to approving *without amendments* Gate A of the precise architecture
merged by PR #77 at commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`. The normative text below
is the originally proposed, now Gate A-approved architecture snapshot.
Historical "proposed/not approved" language below describes the earlier
Phase-0 state and does not authorize Gate B, privileged implementation,
operator deployment or Gate C readiness. See
[PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md](PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md)
for the attributable Gate A record and **subsequently approved**, unamended Gate B static manifest (original PR #78 proposal commit `14123a74e05871a3eaa81b17fd383cdd83a6a7f6`). Historical pre-decision statements below remain provenance, not current approval status.

This revision addresses findings from independent review while staying in
documentation-only Phase 0. **No topology field is approved by this amendment,
and no code, migration, role, grant, socket, or deployment resource is
created.**

| Finding | Defect addressed | Amendment in this document |
| --- | --- | --- |
| **A** | The pre-Tenant branch named a “private admission interface” but did not define its exact trust model, wire contract, limits, or response semantics; only the operator socket was frozen. | New **§5A** freezes the second private interface (`admission.prepare`), its separate socket/UID trust contract, framing/limits, exact request/response literals, no-write read path, ingress-compromise bounds, and the fail-closed `PrivilegedOnboardingTransactionPort` contract (§5A.6). Field 3, Field 7, Field 12 and §8 now reference it. |
| **B** | The authorization snapshot carried only bare IDs plus permission rows, so the control process could not verify persisted Identity/Principal/binding/Role lifecycle, origin, canonical-root exclusion, or builtin/approved marker facts. | New **§6A** replaces the snapshot description with an exact persisted-domain-identity schema (Identity, Principal, ExternalSubjectBinding, Role, PermissionSet, Permission, assignment, target), sufficient to reconstruct the existing internal aggregates and perform every `authorize_global_system` check without a second read. |
| **C** | “Policy evaluation” and “SQL revalidation” duties overlapped: both Python and SQL appeared to check assignment/target/Action, and the transaction/lock boundary between the snapshot and the mutation wrapper was not pinned. | New **§6B** freezes a non-overlapping responsibility table, the exact check order, the lock order across snapshot + wrapper, the single-transaction boundary, and the rule that SQL never returns ALLOW and Python never trusts stale unlocked state. Field 10 now references it. |
| **D** | Revoked-only external subject history was indistinguishable from a new subject in the proposed pre-Tenant admission read; §5A also mentioned unsupported entitlement expiration. | Freeze three-argument history-aware read, historical precedence, internal result, handler mapping, and remove unsupported expiry reference; no implementation or approval. See **§5A.7**. |
| **E** | Field 5 prohibited a development initializer from creating a SYSTEM operator; local deterministic bootstrap cannot be automated without an approved narrow exception. | Amend Field 5 only for an opt-in, canonical-development, one-shot **dedicated operator** fixture; new §5B freezes identity/provenance, installation order, idempotency, deployment isolation, negative tests and production exclusion; §8/§9/§11 explicitly require separate human approval. No code or deployment is changed. |

**PR #77 independent OAuth-contract review fixup (documentation only).**
The four documented callback findings are resolved as proposed text:
valid Keycloak `iss`/`session_state` handling, achievable browser-code
secrecy, no reuse of stale interactive-login evidence, and explicit
dual-use confidential-client risk. This is not an implementation or
a new approval. See §5B.6A and the PR #77 review-fixup evidence report.

**Amendment E portability independent-review fixup (documentation only).**
Review of commit `b291315` found two P1 design gaps: a pre-implementation
approval gate wrongly required post-deployment evidence, and the containerized
operator had no portable host-browser OAuth callback path. This revision freezes
the ordered Gate A/B/C boundary (§3/§9/§11) and exact on-demand callback
contract (§5B.6A), without implementation, host certification or approval.

**Amendment E portable-development clarification (documentation proposal; no approval).**
Native Linux, WSL2 Linux, and Podman-managed Linux VMs on Windows/macOS are
candidate execution environments under ONE Linux socket/UID security contract.
Worker-observed peer credentials, mounts and privilege verification are
required for each deployment; example UIDs are neither host facts nor approval.
`STOP-P24P-TOPOLOGY` remains active.

**Amendment E targeted fixup (documentation): role/migration order + §8A reference.**
This fixup corrects two review defects without creating a new amendment: it makes
future migration `0016` explicitly role-independent and stages control-role
creation/grants after migration, and it corrects the §9 development-profile
approval reference from §8 to §8A. No implementation or approval is added.

All other approved architectural invariants and proposals in this record are
preserved unchanged. The frozen operator protocol (§5), fingerprint (§6), and
**four unchanged operator SQL signatures** are preserved verbatim; the fifth
(pre-Tenant) signature is replaced by §5A.7/§7. §5A/§5A.7/§5B/§6A/§6B are
**additive** and must be approved together with the existing twelve fields.

> **Historical Phase-0 statement, superseded for Gate A only:** no
> architecture approval existed when this proposal was prepared. Human
> approval was subsequently given for Gate A on 2026-11-13; **Gate B is
> NOT approved** and the implementation STOP remains active. The
> coding agent has implemented **no**
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

**Gate A was explicitly approved on 2026-11-13** for the immutable PR #77
merged proposal; Gate B implementation authorization is **PENDING**. The
instructions below describe the approval contract, not a new request to
repeat Gate A. Nothing in this record claims Gate C verification.

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
- the portable deployment-manifest *contract* in §8, and the separately
  approved static target manifest values required by Gate B. Live peer,
  socket, and credential-attestation results are **Gate C**, not a
  pre-implementation §9 prerequisite.

The pre-Tenant subject-history and entitlement read (§5A.7, the fifth §7
signature) is part of the frozen contract and must be approved verbatim;
approving the admission concept without it is not approval.

The development-only installer exception is separately frozen in §5B. Human
approval must explicitly cover its operator identity, one-shot provenance,
opt-in conditions, fixture lifecycle, isolation proofs, and the required §8 host
values. Approval of the production topology alone does not imply approval of the
development fixture, and vice versa.

**Ordered approval and acceptance gates (no implicit authorizations):**

- **Gate A — architecture decision:** a named human approves all twelve
  fields, §§5/5A/5A.7/5B/5B.6A/6/6A/6B/7, the portable manifest schema,
  and the required future acceptance controls. An agreement with a design
  direction or a GitHub merge is not Gate A.
- **Gate B — target deployment manifest / implementation authorization:**
  following Gate A, a named human approves a complete static, versioned
  deployment profile containing required Linux container IDs/GIDs, socket
  paths/ownership/modes, secret mounts, OIDC callback forwarding contract,
  networks and trust boundaries. An A+B record authorizes implementation
  **only**, not a claim of deployed privilege isolation or readiness.
- **Gate C — deployment acceptance:** after authorized implementation, the
  actual worker, sockets, mapped peers, secrets, database grants and genuine
  browser-based operator login pass the independent deployed tests. Gate C
  permits privileged readiness only if every mandatory probe passes.

Once A+B approves a reusable profile, a new developer machine may reuse
the *same exact static manifest* without another discretionary human
approval, provided fresh automatic Gate C attestation proves the profile's
effective-ID, mount, socket, callback and privilege predicates. A changed
manifest, different security constraints or failed proof requires STOP and
an explicit human amendment. This is not automatic authority selection.

If **any** field is `REJECTED` or `AMEND`, the agent stops and returns a
revised plan for further approval. The agent will not reinterpret amendments,
pick a fallback design, or invent a substitute.

---

## 4. The twelve fields (Gate A approved by `MTMF-PR24P-GATE-A-2026-11-13-01`; Gate B pending)

**Status annotation:** the original `**PROPOSED.**` wording in the frozen
field bodies is preserved as part of the exact merged source approved by
the human. It describes the not-yet-implemented design, not a still-pending
Gate A decision. Checkmarks and provenance entries below record the later
human decision; operational deployment remains unapproved.

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
service. If the public runtime and worker are indistinguishable at the actual Linux
security boundary, or their protected sockets/secrets are mutually readable,
the compromised-runtime model fails and the agent must STOP. One rootless
Podman host owner is a residual trusted host actor, not proof of isolation.

**Required deployment.** A new workspace distribution and a dedicated
non-root container/UID, no public ports, no shared service env file, no shared
secret volume. Exact UID/GID in §8. The proposed one-shot development
installation in §5B is a separate short-lived process and must never be part of
`mtmf-service` startup or the persistent worker.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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

**Threat assumptions.** Assumes the Linux execution environment (native Linux,
WSL2, Podman-managed Linux VM, or separately approved Linux VM) preserves
worker-observed distinct `SO_PEERCRED` UIDs across socket mounts. Host labels,
configured container UIDs and `id -u` alone are not proof. An unmapped,
unknown, collapsed or unmeasurable peer UID is `STOP-DEPLOYMENT`.

**Required deployment.** Socket absolute path, owner UID/GID, mode, allowed
admin UID, directory mount. Values in §8.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
is not approval. Amendment D's historical subject-state check and its
`ACTIVE`/`REVOKED_ONLY`/`NEVER_SEEN`/`CONFLICT` precedence are frozen in
**§5A.7** and are also part of this field.

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
no regeneration. The only proposed portable browser-to-ephemeral-operator
Authorization Code callback transport and secret-custody path is frozen in
§5B.6A; it is a development-only login transport, not a control TCP endpoint.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
not an environment-variable source of authority, and not derived from root. In
production, it is never installed by a development initializer or by an
environment flag; it requires the separately approved owner-controlled human
installation ceremony. The sole proposed exception is the explicitly opt-in,
canonical-MTMF-development, one-shot fixture in §5B: it may create or verify
exactly one dedicated non-root operator and its exact approved SYSTEM Role
assignment under owner installation authority, with immutable
development-fixture provenance and strict fail-closed reconciliation. The §5B
exception is NOT APPROVED until the human explicitly approves it alongside this
field, and cannot be generalized to production or ordinary runtime.
Revocation is an installation-only ACTIVE→REVOKED transition;
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

Development-only exception: the exact fixture, process identity, installation
sequencing, provenance and isolation requirements in §5B are normative proposed
constraints; §8 host values and §9 approval remain mandatory. The present source
contains no such installer, Role-assignment table or worker.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
transaction that spans them, are frozen in **§6B**. The fifth entrypoint is the
pre-Tenant history/entitlement read frozen in **§5A.7**; it is not an operator
wrapper and cannot return ALLOW. Migration `0016` installs the five functions
without requiring or granting `mtmf_control_exec`; the separate approved
installation phase grants the five EXECUTEs only after migration and role
provisioning (§5B.4/§7).

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

---

### Field 11 — Secret custody and rotation; verified Linux execution namespaces and privileges

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

**Threat assumptions.** Verify POSIX permissions and secret mounts inside
the actual Linux execution environment. Do not assume Windows/macOS-host-shared
filesystem mounts preserve Linux Unix sockets or owner-only permissions.
If secrets are readable by the ordinary runtime, STOP.

**Required deployment.** Secret mount path, perms, and rotation runbook; host
resource identifiers in §8. For development, §5B fixes the one-shot installer
versus worker/runtime secret-custody separation; the exact secret mount and
rotation data still require §8 approval.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
harness; otherwise ISO-03/ISO-04 are `BLOCKED_ENV`, never PASS. Development-mode
bootstrap does not relax the real compromised-runtime UID/socket/secret/role
negative controls, which §5B.6 requires before readiness.

**Decision (human, required):** ☑ APPROVED ☐ REJECTED ☐ AMEND
**Approved text / amendment / conditions:** Verbatim architecture at merged commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`; no amendments. Gate B not approved.
**Approver / date / decision ID:** MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval); 2026-11-13 UTC; `MTMF-PR24P-GATE-A-2026-11-13-01`.

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
| `NO_ENTITLEMENT` | Verified new subject with no ACTIVE entitlement or an exhausted ACTIVE entitlement; no quota reservation and no authorization. | `false` | `null` |
| `CONFLICT` (error) | Revoked-only or conflicting subject history; never silently rebind. | — | — |

`REVOKED_ONLY` is an internal historical classification, not a fourth success
outcome; revoked-only subject history is mapped to opaque `CONFLICT`.

The response never contains a token, subject, Identity/Principal ID, Tenant ID,
membership, Role, Permission, assignment, registration, subscription, quota
counter, Action ALLOW, or SQLSTATE. `application_id` is the Application resolved
from the verified service credential, never a request value. No quota is
consumed or reserved by this response.

### 5A.5 Exact read path and boundary

```text
verify SO_PEERCRED == dedicated ingress UID
  -> strict frame/request decode (only two access tokens + request_id)
  -> approved fresh attestation + independently verify both tokens
  -> PR 23 PreTenantSubjectVerificationService.verify(...) on restricted-read UoW
       (returns verified Application/exact issuer+subject and optional existing IDs;
        no entitlement/Role/Tenant write; UoW closed)
  -> control-role-only, read-only mtmf.control_pre_tenant_admission_read(
       verified.application_id,
       verified.external_subject.issuer,
       verified.external_subject.subject)
       (always called after successful PR 23 verify, including EXISTING)
  -> strictly validate internal result and map by table R below
  -> prepare a non-authorizing detached result; emit bounded §5A.4 response
```

**Output mapping (R):**

| ID | PR 23 verified result | Privileged read `subject_history` | Entitlement fields | §5A.4 public-facing private-socket result |
| --- | --- | --- | --- | --- |
| R01 | New candidate (no existing IDs) | `NEVER_SEEN` | UUID + `quota_available=true` | `CANDIDATE`, `eligible_for_first_tenant=true`, entitlement UUID. |
| R02 | New candidate | `NEVER_SEEN` | `null` + `false` | `NO_ENTITLEMENT`, eligible false, entitlement null. |
| R03 | Existing subject | `ACTIVE` | `null` + `false` | `EXISTING_SUBJECT`, eligible false, entitlement null. |
| R04 | New candidate | `ACTIVE` | `null` + `false` | `EXISTING_SUBJECT` (a valid binding appeared between the two reads), eligible false, entitlement null. Do not claim a new candidate. |
| R05 | Any successfully verified subject | `REVOKED_ONLY` | `null` + `false` | Error `CONFLICT` (opaque; no history text). |
| R06 | Any successfully verified subject | `CONFLICT` | `null` + `false` | Error `CONFLICT` (opaque; no history text). |
| R07 | Existing subject | `NEVER_SEEN` | any | Error `CONFLICT` (inconsistent prior ACTIVE observation; do not fabricate a new candidate). |
| R08 | Any | Any state | Malformed JSON, unexpected key, impossible UUID/flag pairing, missing fields, incompatible version | Fail closed `UNAVAILABLE` (no candidate); log safe internal diagnostic only. |
| R09 | PR 23 token/attestation/binding verification failed | **Do not call privileged read** | n/a | Existing typed `INVALID`/`UNAUTHENTICATED`/`FORBIDDEN`/`UNAVAILABLE` mapping; never `CANDIDATE`. |
| R10 | Any | Database read rejects inactive/missing Application, root-registry inconsistency, or infrastructure fault | n/a | Existing opaque `UNAVAILABLE` error; never success. |

The first read and the privileged read may observe different committed states.
The `ACTIVE`-after-candidate case must be handled as R04. A candidate is **not**
an authorization to create or a stable lease; PR 22B **must** recheck all state
atomically and still rejects revoked-only subject history through B1.

Maintain §5A.4's *external envelope* exactly: `CANDIDATE | EXISTING_SUBJECT |
NO_ENTITLEMENT` and the existing opaque error enum. **Do not add `REVOKED_ONLY`
or subject-history fields to the socket response.** Return the verified
Application UUID only as already authorized by the verified service token, not
from ingress input.

- All attestation/JWKS/token I/O completes **before any database access**.
- The PR 23 restricted-read UoW and the control-role read are separate
  credentials/connections and are **never** transactionally mixed; PR 24P opens
  **no** privileged write transaction on this path.
- The historical/entitlement read is **unconditional** after a successful PR 23
  verification: it runs for both an existing subject and a new-subject
  candidate, and is the single authoritative classification and preliminary
  entitlement check.
- No Identity/Principal/binding, Tenant, membership, registration,
  subscription, quota, replay, or audit-success row is written. No `COMMIT` of
  any mutation. `request_id` is not a replay ledger.
- The admission handler **must not read `system_operator_assignment`**, and the
  operator handler **must not use an Application entitlement** to authorize an
  operator Action. The two evidence types never cross.
- The only pre-Tenant read is the frozen
  `control_pre_tenant_admission_read(application_id, issuer, subject)` (§5A.7,
  §7); the operator `control_entitlement_get(...)` is not callable from this
  handler.
- `CANDIDATE` cannot invoke the future composite: PR 24P's
  `PrivilegedOnboardingTransactionPort.execute_approved_composite` remains
  unimplemented and fail-closed. PR 22B must repeat every authoritative check
  under its own serialized transaction and owns the quota/replay ledger.
- Stale state between the preliminary read and a future PR 22B transaction is
  acceptable **only** because the candidate is non-authorizing; PR 22B must
  reject changed entitlement/subject state during its locked recheck (PT-I07,
  SH17, SH20).

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

### 5A.7 Exact subject-history and entitlement read contract (Amendment D — proposed)

This subsection is the contract for the **one fifth** proposed private SQL
entrypoint in §7. It replaces the rev 2 one-argument entitlement-only read. It
is a proposal for human approval; PR 24P implements none of it.

#### 5A.7.1 Proposed fifth signature

```sql
mtmf.control_pre_tenant_admission_read(
  application_id_value uuid,
  issuer_value text,
  subject_value text
) RETURNS jsonb
```

The function is **read-only, `STABLE`, `SECURITY DEFINER`, `SET search_path = ''`,
owner-owned**, and invocable **only** by the future `mtmf_control_exec` role;
PUBLIC and `mtmf_runtime` EXECUTE are denied. It may read approved underlying
tables through owner privileges; it may **not** insert/update/delete, lock rows
for update, reserve quota, call v015 B1/B2, emit mutation audit, perform remote
I/O, commit, or return an authorization ALLOW. The old
`control_pre_tenant_entitlement_read(uuid)` signature is superseded and must not
remain as a second active entrypoint.

The three inputs are derived exclusively inside the trusted worker:
`application_id_value` comes from PR 23's independently verified service
credential; `issuer_value` and `subject_value` come from independently verified
user claims. The §5A.3 ingress protocol **does not gain any fields** and must
never be allowed to submit these values directly as identity proof.

#### 5A.7.2 Exact internal result schema

The function returns **exactly** this JSON object, with no extra keys:

```json
{
  "v": 1,
  "subject_history": "NEVER_SEEN",
  "entitlement_id": null,
  "quota_available": false
}
```

The sample illustrates one valid shape, not fixed example values. The contract
is:

| Field | Type / permitted values | Meaning |
| --- | --- | --- |
| `v` | integer literal `1` | Internal read-result schema version. |
| `subject_history` | exactly `NEVER_SEEN`, `ACTIVE`, `REVOKED_ONLY`, or `CONFLICT` | Historical subject state for the **exact** `(issuer,subject)` key, with definitions below. |
| `entitlement_id` | canonical nonnil UUID string or `null` | ACTIVE entitlement ID **only if** history is `NEVER_SEEN`, exactly one ACTIVE entitlement exists, and `quota_available=true`. Otherwise `null`. |
| `quota_available` | JSON boolean | `true` **only if** history is `NEVER_SEEN` and an ACTIVE entitlement has `quota_consumed < quota_total`. Otherwise `false`. |

No `identity_id`, `principal_id`, `binding_id`, historical counts, revoked dates,
Tenant metadata, Application name, raw issuer/subject, quota counters, Role,
permission, free-text reason, SQLSTATE, or token may appear. No `approved`,
`allow`, or `authorized` key. The worker must not expose this internal JSON
object directly in the admission socket response.

#### 5A.7.3 Authoritative subject-history precedence (H01–H06)

Use **exact** case-sensitive equality on `(issuer_value, subject_value)`; do
not trim, lowercase, or normalize accepted text. Validate inputs as in B1:
nonnull text; `length(btrim(value)) > 0`; `length(value) <= 512`; Application
UUID present/non-nil. An input failing those checks is a fail-closed error,
never `NEVER_SEEN`.

Count **all** matching binding rows, not just current ACTIVE rows:

```sql
SELECT count(*) FILTER (WHERE lifecycle = 1),
       count(*) FILTER (WHERE lifecycle = 2)
  FROM mtmf.external_subject_identity
 WHERE issuer = issuer_value AND subject = subject_value;
```

| Priority | ACTIVE rows | REVOKED rows | Additional condition | `subject_history` | Entitlement read? |
|---|---:|---:|---|---|---|
| H01 | >1 | any | Corrupt/ambiguous, despite the ACTIVE partial unique index | `CONFLICT` | No |
| H02 | 1 | any | Exact active binding resolves to active, FEDERATED, non-root Identity and active, non-root Principal | `ACTIVE` | No |
| H03 | 1 | any | Identity/Principal missing, deleted, LOCAL, canonical root, or relationship inconsistent | `CONFLICT` | No |
| H04 | 0 | >=1 | Historical revocation without active successor | `REVOKED_ONLY` | No |
| H05 | 0 | 0 | No matching binding row in any lifecycle | `NEVER_SEEN` | Yes |
| H06 | any | any | Unexpected lifecycle/integrity condition not covered by the table or database contract | Fail closed, **no candidate** | No |

**Critical precedence:** an ACTIVE binding plus one or more older REVOKED rows
is **`ACTIVE`**, not `REVOKED_ONLY` or `CONFLICT`, provided the ACTIVE binding's
Identity/Principal is eligible. This mirrors the shipped PR 23 B1 order and
preserves legitimate re-binding only through independently approved existing
pathways. PR 23 behavior is not changed.

For H02/H03 validate within the privileged read's authoritative snapshot:
active binding `identity_id` → `mtmf.identity` (`origin=2` FEDERATED,
`deletion_status=2` NOT_DELETED) → `mtmf.principal` (`deletion_status=2`);
compare Identity and Principal IDs against the canonical `mtmf.root_registry`
and reject root. Missing/contradictory root registry fails closed; there is no
fallback to hardcoded IDs. Do not return those underlying identifiers. This
validates a newly appeared ACTIVE row even if PR 23's preceding restricted read
saw no active binding.

The read is a **single, read-only statement-snapshot classification** (one
invocation of a `STABLE` function; no network I/O inside it). No
locking/serialization guarantee is claimed. If a future SQL implementation
cannot provide the specified coherent snapshot, that implementation must STOP
rather than compose inconsistent separate reads.

#### 5A.7.4 Entitlement eligibility, exhaustion, and no expiration

Check Application existence and `ApplicationLifecycle.ACTIVE` before yielding
any success result. An unknown/inactive Application is a fail-closed condition,
**never** `NO_ENTITLEMENT`, `CANDIDATE`, or a new-subject proof. The worker has
already verified the Application binding, but this privileged read rechecks
lifecycle. Any SQL exception from this read maps to the existing opaque
`UNAVAILABLE` error; the worker does not branch on internal SQL exception text
or expose SQLSTATE. Invalid wire/input values are rejected by the worker as
`INVALID` **before** calling the SQL function. Historical contradiction is
represented by the valid internal `subject_history=CONFLICT` value and maps to
the socket `CONFLICT` error. No new SQLSTATE is introduced.

**Only when** `subject_history=NEVER_SEEN`, query
`mtmf.application_onboarding_entitlement` by the exact verified Application
UUID:

| Entitlement rows (same verified Application) | Internal `entitlement_id` | `quota_available` | Admission result |
| --- | --- | --- | --- |
| Exactly one ACTIVE (`state=1`), `0 <= quota_consumed < quota_total` | That ACTIVE UUID | `true` | `CANDIDATE` |
| Exactly one ACTIVE, `quota_consumed = quota_total` | `null` | `false` | `NO_ENTITLEMENT` |
| No ACTIVE rows (no rows or only REVOKED history) | `null` | `false` | `NO_ENTITLEMENT` |
| Multiple ACTIVE rows (corrupt/violated unique index), impossible quota values, or another inconsistent lifecycle | No successful result | n/a | Fail-closed `CONFLICT` / infrastructure error; never candidate |

An old REVOKED entitlement coexisting with an ACTIVE replacement is **not** a
conflict: the ACTIVE one controls quota eligibility. Historical subject
revocation and historical entitlement revocation are independent concepts and
must never be conflated.

**No entitlement-expiration column or time-based eligibility condition exists
in v014.** Do not invent an `expires_at` column, validity window, configuration
flag, or clock-based shortcut. If a later approved migration adds expiry, that
future PR must separately amend this contract.

#### 5A.7.5 Trust, privacy, and no-mutation consequences

- `control_pre_tenant_admission_read` is callable only by the separately
  isolated worker using its restricted control DB role; it is **not** callable
  with the `mtmf_runtime` credential or a public HTTP path. The worker
  re-verifies both tokens independently before executing it.
- The SQL function's exact issuer/subject parameters are **not cryptographic
  proof in PostgreSQL**; they are trusted process-derived data. The database
  cannot independently authenticate JWTs. This residual risk is explicit.
- No subject-history count, raw key, or binding identity leaks into the bounded
  admission response, logs, metrics, traces, mutation audit, or operator socket.
- No B1/B2, first-Tenant composite, quota reservation/consumption, Role grant,
  subscription, or mutation occurs during `admission.prepare`.
  `PrivilegedOnboardingTransactionPort` stays unimplemented and fail-closed.

#### 5A.7.6 Planned feature acceptance (specified now; NOT EXECUTED)

These are **planned obligations**, not tests written or run in this
documentation-only amendment. A future approved PR 24P implementation must use
real PostgreSQL with the intended `mtmf_control_exec` privilege boundary and
exercise the production read function, not a mock SELECT.

| Test | Historical subject fixture | Entitlement fixture | Expected internal / admission result |
|---|---|---|---|
| SH01 | No exact-key history | ACTIVE, quota available | `NEVER_SEEN`, `CANDIDATE`, eligible true. |
| SH02 | One REVOKED row only | ACTIVE, quota available | `REVOKED_ONLY`, opaque `CONFLICT`, never candidate. |
| SH03 | Multiple REVOKED rows, no ACTIVE | ACTIVE, quota available | `REVOKED_ONLY`, opaque `CONFLICT`. |
| SH04 | One valid ACTIVE row only | any | `ACTIVE`, `EXISTING_SUBJECT`, no entitlement query. |
| SH05 | One valid ACTIVE plus older REVOKED row(s) | any | `ACTIVE`, `EXISTING_SUBJECT` (B1 precedence). |
| SH06 | ACTIVE row with missing/deleted/LOCAL/root Identity or invalid Principal | any | `CONFLICT`, opaque error. |
| SH07 | Multiple ACTIVE rows in corruption/constraint-disabled fixture | any | `CONFLICT`; never choose one. |
| SH08 | No subject history | no entitlement row | `NEVER_SEEN`, `NO_ENTITLEMENT`. |
| SH09 | No subject history | only REVOKED entitlement history | `NEVER_SEEN`, `NO_ENTITLEMENT`. |
| SH10 | No subject history | ACTIVE entitlement exhausted | `NEVER_SEEN`, `NO_ENTITLEMENT`. |
| SH11 | No subject history | revoked entitlement plus ACTIVE replacement, quota available | `NEVER_SEEN`, `CANDIDATE` using replacement UUID. |
| SH12 | Exact issuer A/subject S has REVOKED-only; different issuer B/subject S has no history | ACTIVE | A → `CONFLICT`; B → `CANDIDATE` (no cross-issuer conflation). |
| SH13 | PR 23 candidate read, then matching ACTIVE binding appears before history read | any | `EXISTING_SUBJECT`, not candidate; future composite still rechecks. |
| SH14 | PR 23 candidate read, then matching binding created/revoked before history read | ACTIVE | `REVOKED_ONLY`, `CONFLICT`; no candidate. |
| SH15 | No history, but Application now inactive when privileged read executes | ACTIVE | Fail-closed opaque error, not `NO_ENTITLEMENT`/`CANDIDATE`. |
| SH16 | Any eligible case | Worker has only `mtmf_runtime` credential | EXECUTE on new function denied; runtime allowlist remains 78. |
| SH17 | Revoked-only candidate race, still no unrevoked binding inside future B1 | ACTIVE | B1 `MT048` and zero writes, regardless of prior read classification. |
| SH18 | Malformed exact-key input (`NULL`, blank, >512), bad/unknown JSON fields | any | Fail closed; no normalized/rebound subject. |
| SH19 | Subject classification `REVOKED_ONLY` / `CONFLICT` | any | No subject key, history counts, raw issuer/subject, SQLSTATE, or token in socket response/logs. |
| SH20 | Successful preliminary `CANDIDATE` | entitlement later revoked/quota exhausted | Future PR 22B locked recheck fails without partial Tenant/Identity/Role/audit. |

SH07 may require an isolated controlled database with a deliberately disabled
unique constraint; the normal development database must never be altered to
construct corrupt fixtures. If safe isolation cannot be provided, the future
test must be recorded as blocked, never PASS. SH13–SH14 require deterministic
barriers to control the two read instants, not timing sleeps. Every real-DB
mutation fixture must be rolled back/cleaned under the approved test harness.

## 5B. Development-only automated operator bootstrap (Amendment E — proposed)

This section is an unapproved, development-only installation proposal; no
startup, operator grant, or control-plane capability is implemented by this
revision.

### 5B.1 Activation and canonical development profile (E-I01)

A development-only exception may exist **only** in the canonical isolated
`mtmf` development profile, with exact `MTMF_SERVICE_DEPLOYMENT_MODE=development`,
Compose project `mtmf`, and issuer:

```text
https://keycloak.mtmf.test:28443/realms/mtmf-dev
```

A future explicit opt-in **`MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true`** may enable
the reviewed fixture orchestration. Its default is **disabled**. Only exact
`true` and `false` are valid; unset means `false`, and malformed values cause
configuration failure. **The flag is not authorization evidence** and may not
select the operator, Role, issuer, database, port, UID, or privilege level.
Installation privileges come exclusively from the short-lived installer identity
and the human-approved immutable manifest. The public `mtmf-service` must never
read the flag to unlock management behavior.

An explicit human topology decision later must approve this literal development
profile before any installer acts on it. No implicit approval arises from `up`,
a `git merge`, a passing test, an environment flag, or this plan. Non-development
deployment modes, noncanonical issuers/projects, or unapproved manifests STOP
before any privileged action.

### 5B.2 Dedicated Keycloak operator and exact SYSTEM assignment (E-I02/E-I03)

The sole proposed local SYSTEM operator username is the exact development
fixture **`mtmf-dev-operator`** in realm `mtmf-dev`. It is **not** the Keycloak
master administrator `mtmf-admin` and must be **distinct from** the current
ordinary fixture user `MTMF_DEV_USER_USERNAME`. There is **one** development
operator; no arbitrary list or user-selected Role. The operator is a Keycloak
interactive user, not a service account and not the canonical MTMF
root Identity/Principal.

Its MTMF `Principal`, `Identity`, `ExternalSubjectBinding`, and
`system_operator_assignment` are separate from ordinary dev-user and root
records. No Tenant membership, Tenant Role assignment, stewardship, or ownership
is created for this SYSTEM operator by this fixture. The Keycloak user's actual
immutable subject comes from the approved `KeycloakDevUserProvisioner`
verification path; **no literal, derived, guessed, username-derived or
environment-provided `sub` is acceptable**.

The sole Role is exactly:

```text
urn:mtmf:iam:roles:system:application-administrator
```

It must be an already approved/protected SYSTEM built-in definition with the
PR 21-approved permission manifest. Do not synthesize it, substitute a Tenant
Role, select a Role from environment variables, or repair a drifted definition.
If the approved seed is missing or mismatched, future initialization STOP-SEED,
not an on-the-fly grant.

Future fixture implementation must reuse the existing validated development
Keycloak user provisioner and its admin-REST exact-username +
authoritative-subject rules. It may **create** `mtmf-dev-operator` only if all of
the following are true: explicit bootstrap opt-in, genuinely absent exact user,
approved canonical realm/client/issuer, an owner-only development-only password
file supplied by the developer, and valid Keycloak Admin REST create/read-back
correlation. It must **never** print, commit, synthesize a default plaintext
password, reset an existing password, enable a disabled account, impersonate an
account, or auto-recover an ambiguous create result.

For a repeated startup: verify the exact Keycloak subject **and** the previously
installed MTMF binding, operator Principal/Identity and approved assignment. Do
not change them. If the username already exists but the MTMF fixture/binding/
approved creation provenance does not exist, **STOP** as an adoption/
partial-install case; no silent acquisition of authority. If creation failed
after an uncertain remote result, **STOP**, no second POST. A supplied password
file does not authorize takeover of an existing user.

Existing standard Authorization Code user sign-in (using the approved client)
remains mandatory for executing real operator requests. The precise on-demand
operator CLI callback/PKCE/client-secret procedure is frozen in §5B.6A;
bootstrap itself must not synthesize or require an interactive token. The installer may use
privileged Keycloak Admin REST to validate/create the fixture, but may not mint
an impersonated operator user token, use password grant, or bypass signed-token
verification during control-plane execution. Automated isolated genuine-token
acceptance must use a separately approved genuine user-interaction fixture and
never fabricated JWTs.

### 5B.3 Short-lived installer, fixture IDs, and audit provenance (E-I04)

The fixture runs **only** as a short-lived installation job, using the privileged
migrator with explicit `SET ROLE mtmf_owner` after approved migrations/role
topology are verified. The public service and persistent control worker never
receive the migrator, Keycloak Admin REST, root, or owner credentials.

The installation job is authorized to use **only** the previously approved,
owner-only installation path for `system_operator_assignment` and its
append-only provenance. It must not expose a general runtime Role-grant function
or grant privileges to `mtmf_runtime`/`mtmf_control_exec` beyond the
independently approved five-function allowlist.

The persisted approval provenance must distinguish fixture provenance from a
genuine human production ceremony, without spoofing an operator or signing a
human approver's name. The fixed literal source label is:

```text
dev-fixture:mtmf:pr24p:system-operator:v1
```

Store the eventual human decision ID as a separate exact
installation-decision reference once approved. The future installer may not
fabricate that ID. The proposed append-only event records the fixed source
label, canonical operator Identity/Principal, Role URN, assignment UUID, event
outcome (`CREATED` only for initial installation), correlation UUID, and
timestamp. Repeated verified bootstrap produces **no new event**, no new Role
assignment, and no inflated audit success. Do not add a general mutable
`approval_source` column by assumption; the future schema/approved installer
must map these provenance facts into its reviewed columns, or STOP-SCHEMA. The
database's inability to cryptographically attest a human approver remains a
documented trust assumption.

Use the repository's existing `_deterministic(...)` UUIDv5 helper with its
already-shipped namespace (not a new random seed) for future fixture IDs, with
these fixed, distinct name inputs after the real Keycloak `sub` is verified:

```text
pr24p:dev-operator:principal:<actual-Keycloak-sub>
pr24p:dev-operator:identity:<actual-Keycloak-sub>
pr24p:dev-operator:binding:<actual-Keycloak-sub>
pr24p:dev-operator:system-assignment:<actual-Keycloak-sub>
pr24p:dev-operator:installation-correlation:<actual-Keycloak-sub>
```

Angle-bracket text means the actual exact Keycloak subject substituted at
runtime, never the literal string `<actual-Keycloak-sub>`. This is only a
proposed fixture identity derivation, not a SQL or code instruction. The
canonical development issuer is fixed, so the namespace is issuer-specific by
policy; any future multi-issuer dev support requires a new design rather than
reusing these IDs across issuers.

### 5B.4 Exact future startup and credential custody order (E-I06)

The future order for `scripts/mtmf-dev-stack.py up` **when the approved opt-in
is enabled** is prescribed here; it is not a command to execute in this
amendment:

```text
0  PRE-FLIGHT: accept only exact MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true for
   privileged setup; mode=development, project=mtmf, canonical issuer/client,
   reviewed manifest, admin/control/migrator/runtime credential custody, and
   approved UID/socket/network/secret paths. Abort before side effects on
   noncanonical/unknown configuration.
1  START BASE: start only MTMF-owned PostgreSQL, Keycloak and canonical TLS
   forwarder; perform the launcher’s existing health/issuer probes.
2  MIGRATE + BASE FIXTURES: run the existing short-lived initializer in the
   current sequence, including migration to head 0016, mandatory runtime
   privilege postflight, and existing ordinary development fixture
   verification. Revision 0016 creates owner-owned PUBLIC-denied functions
   without requiring or creating mtmf_control_exec and without granting it
   EXECUTE. Do not install a SYSTEM operator in --migrations-only mode.
3  CONTROL LOGIN: only because exact opt-in was approved, run a separate
   short-lived cluster-administrator role-provisioning action: CREATE a new
   mtmf_control_exec LOGIN if absent and safely pristine, or verify a fully
   provisioned, already approved existing control role. Require approved
   secret custody. Never invoke the current default three-role password
   provisioning action or rotate migrator/runtime credentials.
4  CONTROL GRANTS: with the approved installation-only migrator/SET ROLE
   mtmf_owner authority, install the exact five §7 EXECUTEs on a newly
   provisioned role; scope CONNECT to the MTMF database and USAGE to the
   mtmf schema as required. Verify every effective privilege and no other
   EXECUTE, DML, role membership or PUBLIC/runtime reachability. For a
   previously installed role, verify-only; unexpected partial state STOP.
5  OPERATOR FIXTURE: only after steps 2–4 are verified, run the short-lived
   installer using the existing verified Keycloak-sub flow and owner-approved
   fixture installation path. Create the fixed mtmf-dev-operator only in a
   clean fresh state; otherwise verify exact existing immutable provenance.
   No self-grant, root impersonation, auto-adoption, auto-regrant or repair.
6  EXIT INSTALLERS: terminate every administrator/migrator/Keycloak-master
   installation context; prove admin/migrator secrets and mounts are absent
   from the long-running worker and ordinary service.
7  START ISOLATED WORKER + PUBLIC SERVICE: start non-root control worker with
   only restricted control/read credentials and approved private sockets;
   keep admission socket test-harness-only. Start unprivileged mtmf-service
   with mtmf_runtime only and no control-role credentials or socket mounts.
8  PROVE AND REPORT: run the planned real peer-UID, socket, role/grant,
   effective-privilege, genuine-token and compromised-runtime negative
   probes. Only if all required checks pass may the launcher report
   'development stack ready (privileged control plane)'; otherwise FAIL
   CLOSED with no privileged-ready claim.
```

**Role-independent migration.** Future `0016` is unconditional and independent
of the bootstrap flag and of `mtmf_control_exec` existence. Under the
already-authenticated `mtmf_migrator` / `SET ROLE mtmf_owner`, it creates the
reviewed owner-owned schema objects and exactly five §7 private functions with
PUBLIC EXECUTE revoked and no externally observable PUBLIC-callable interval. It
**must not** issue `CREATE ROLE mtmf_control_exec`, `GRANT ... TO
mtmf_control_exec`, or any other SQL requiring that role to exist; it must not
branch on the deployment profile or flag; and it must not add any
`mtmf_runtime` grant, membership, elevation or owner-only v014/v015 access. It
must pass the mandatory effective runtime privilege postflight whether the
control role is absent or previously present. Installing the five functions is
not the same as making them executable by a new control login. An ordinary
migration rerun must not strip or rotate a previously approved control role or
its grants as an incidental opt-out, but it must fail on any unexpected
effective grant surface. Implementation discovery that this cannot be
represented in the existing migration/owner model is
`STOP-MIGRATION-ROLE-COUPLING`, not a conditional migration branch or a
privileged role secret in Alembic.

**Future role/grant interface.** Control-role creation is a distinct, opt-in,
administrator-authorized action in the existing
`scripts/mtmf-provision-roles.py` model, with an explicitly named future
`--provision-control` mode and a separately named future read-only
`--verify-control` mode. Neither mode exists today; neither may be invoked in
this fixup; neither may change the current default/no-argument or `--verify`
behavior. `--provision-control` runs only after `0016` and under administrator
credentials: it creates an absent role with a restricted dedicated credential,
verifies a fully existing approved role without changing its password, and
rejects drift or partial installation. The owner-authorized job grants or
reconciles exactly the five §7 functions with an explicit initial-install versus
verify-only branch. `--verify-control` verifies exact effective role, database,
schema and function privileges without creating or repairing anything. If the
approved implementation cannot separate these duties and credentials, STOP and
seek a revised design. Cluster `CREATE ROLE` requires administrator authority;
owner-owned function grants require authenticated migrator/owner authority.
Never assume the migrator can create a cluster LOGIN; never give the worker,
service, `mtmf_runtime` or Keycloak operator administrator/migrator secrets. No
transaction spans a remote Keycloak request and PostgreSQL locks.

**Opt-out and previous state.** When `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED` is
unset or exactly `false`: run the current `up` flow including migration to head
`0016` and ordinary fixture; do not call control provisioning/verification,
install control grants, install the SYSTEM operator, start the worker, or mount
its secrets/sockets. On a fresh database, observe no new control role,
assignment, grant or worker. On a previously opted-in database, **retain the
existing role, grants and fixture without mutation**; the flag is not
revocation. Normal runtime cannot exploit them because it lacks privileged
grants, credentials and socket access. If prior control privileges cause
PUBLIC/runtime reachability, the mandatory runtime verifier must fail closed.
Actual revocation requires a distinct human-approved rotation/revocation or
explicit MTMF-only destructive reset outside normal `up`/`down`. “Standard `up`
unchanged” means unchanged service/ordinary-fixture behavior, not that schema
head remains `0015` and not that persisted control objects are dropped on
opt-out. The existing `--migrations-only` path must never auto-install an
operator fixture.

This one-command goal assumes prior developer configuration of the needed
secrets and a human-approved, verifiable UID/socket/secret topology; it is not
an unattended install on a completely unconfigured host. Existing
`mtmf_owner`/`mtmf_migrator`/`mtmf_runtime` provisioning remains the documented
prerequisite for the current initializer; this fixup does not claim a bare
PostgreSQL cluster with none of those roles can already be brought up with zero
configuration, and it does not rewrite the existing bootstrap flow.

### 5B.5 Idempotency, no-regrant policy, and failure rules (E-I05)

| ID | Precondition | Only permitted future action | Forbidden behavior |
|---|---|---|---|
| D01 | Bootstrap flag absent/false | Run existing standard dev stack with no PR 24P fixture | Implicit operator assignment or socket creation |
| D02 | Flag exact true, mode `development`, canonical issuer/project, approved values | Perform full preflight then one-shot installation | Treat flag as authority by itself |
| D03 | Flag true, non-development mode, noncanonical issuer/project, or unapproved manifest | STOP before privileged action | Fallback issuer or weaker profile |
| D04 | Canonical Keycloak operator genuinely absent, password file valid, no MTMF operator artifacts | Create exact user once; verify authoritative immutable `sub`; then install | Guess `sub`, default password, impersonate, retry uncertain POST |
| D05 | Exact operator exists with full matching, previously audited ACTIVE fixture | Validate all facts read-only; no new audit/assignment | Duplicate assignment or rolling credential reset |
| D06 | Exact username exists without approved MTMF fixture | STOP for explicit human adoption/remediation | Automatically bind/preempt existing account |
| D07 | Existing operator disabled/ambiguous/drifted, wrong `sub` or externally managed | STOP | Enable/rename/adopt/repair user |
| D08 | MTMF operator binding absent after partial Keycloak creation | STOP; report partial-install evidence | Silent self-heal or delete/recreate user |
| D09 | Operator Identity/Principal deleted, LOCAL, root, mismatch or Tenant membership unexpectedly granted by fixture | STOP | Root impersonation or alias to ordinary user |
| D10 | SYSTEM Role missing, incorrect definition, stale permission manifest | STOP-SEED | Manufacture new Role or broad Permission |
| D11 | Assignment ACTIVE and exactly matches approved fixture | Verify only | Regrant/revoke/update |
| D12 | Assignment REVOKED, terminal/conflicting, duplicated or missing provenance | STOP; manual remediation | Automatic ACTIVE transition or new grant |
| D13 | Fresh opt-in setup **before** control-role provisioning: role absent; or opt-in **after** provisioning/grants: role absent, partial, overprivileged, or grants drifted | Before provisioning, absence is expected: create via isolated approved administrator role-provisioning phase, then install and verify exactly five grants. After provisioning, absent/drifted role or grants: `STOP-ROLE-PROVISIONING` / `STOP-PRIVILEGE`. Previously installed role is verify-only; partially installed role requires explicit remediation. | Treat pre-provisioning absence as a STOP; use migrator/runtime login to CREATE ROLE; silently repair a partially installed or overprivileged role; rotate unrelated credentials; continue to worker on failed verification. |
| D14 | Podman peers collapse UIDs or runtime can reach a socket | STOP-DEPLOYMENT | Group ACL fallback, shared UID/chmod-only proof |
| D15 | Runtime sees secret, owner/migrator credential or worker memory/mount | STOP-PRIVILEGE | Start partially ready service |
| D16 | Admin create committed remotely but result cannot be correlated | STOP-AUTH-FIXTURE | Second blind create or reinterpret response |
| D17 | Bootstrap DB commit outcome unknown | STOP-TRANSACTION; explicit inspection required | Blind replay of privileged installer |
| D18 | Operator is assigned but no genuine interactive user token can be produced | STOP-AUTH-PROFILE | Enable password grant or fake token |
| D19 | Control plane probes fail | Do not claim privileged stack ready | Skip negative tests |
| D20 | All reviewed values, commands, tests approved and verified | Only then mark privileged development readiness | Infer production approval from dev success |

**Role-state phase classification (D13).** *Fresh* opt-in means the control role
is absent because it has never been provisioned; this is expected and is not a
STOP. *After provisioning/grants* means the trusted installer has created the
role and is expected to complete or verify exactly five grants; a missing,
partial, overprivileged or drifted surface is a STOP, not a transient state to
repair automatically. *Previously installed* means a complete approved prior
state exists; only read-only verification is permitted, with no password
rotation, regrant, assignment mutation or audit inflation.

Additional fixed rules:

- Fresh approved fixture with no user/binding/assignment: create the validated
  Keycloak account (if missing), then create exact MTMF objects/assignment and
  the append-only event through the installer.
- Exact existing Keycloak account with an exact valid, previously bootstrapped
  MTMF fixture (matching immutable UUIDs, binding, ACTIVE Role definition,
  assignment and source provenance): **verify-only/no write**.
- Missing user but existing MTMF fixture, different Keycloak `sub`, changed
  Principal/Identity, deleted/LOCAL/root Identity, revoked binding/assignment,
  unexpected Role, duplicate assignment, or missing provenance: **STOP**, no
  repair or regrant.
- Existing unbound Keycloak user by the same username on an initial run: **STOP**,
  no automatic adoption.
- Keycloak account disabled, duplicate, federated/externally managed, or
  drifted: **STOP**, no silent rewrite.
- Fresh Keycloak user created but PostgreSQL write fails or commit outcome is
  unknown: **STOP** with safe diagnostic; do not delete the Keycloak user or
  retry privileged writes blindly; explicit development recovery is a separate
  human action.
- Reset is permissible only through an already approved explicit MTMF-only dev
  reset that identifies exact MTMF project resources and warns about destroying
  persistent Keycloak `sub` references. A normal `up`/`down` never resets,
  revives, unrevokes, or wipes anything.

### 5B.6 Portable Linux UID/socket/namespace and compromised-runtime proofs (E-I07)

The future development deployment must use:

- Separate non-root Linux/Podman process identities for control worker,
  administrator/operator client, private admission test ingress, and ordinary
  runtime; **no UID collapsing**, validated through real `SO_PEERCRED` observed
  inside the worker under the chosen user namespaces.
- Distinct private AF_UNIX operator/admission sockets governed by the existing
  §5/§5A contracts, with only the approved peer UID admitted and no TCP or
  group-only fallback.
- Operator socket available to its approved administrative client only;
  admission socket **test harness only in PR 24P**, never public or reachable
  through `mtmf_runtime`.
- Restricted worker secret mounts: no Keycloak master admin password, no
  owner/migrator DB credential, no host Podman socket, no public-service shared
  volume containing worker secrets; no secrets on command lines/logs/repository.
- `mtmf_control_exec` restricted to exactly five approved function EXECUTEs; no
  table/sequence DML, SUPERUSER, CREATEROLE, CREATEDB, BYPASSRLS, CREATE-on-schema,
  owner/migrator membership, or other reachability. Database CONNECT and schema
  USAGE, if required, are separately scoped and verified and never count as
  extra function EXECUTEs. `mtmf_runtime` retains **78** previously approved
  signatures, unchanged.
- Strict MTMF-owned project selection: **`mtmf`** for the local developer stack.
  No resource discovery or destructive action across ATI, Digr, Darkula or
  unrelated Podman projects. Do not hardcode container network IPs; preserve
  the existing canonical Keycloak TLS/issuer.
- Readiness tests with real deployed UIDs, roles, socket permissions and mount
  namespaces, not `chmod` on a shared UID, fake credentials, or mocked
  `SO_PEERCRED`.

Exact numerical UIDs/GIDs, paths, Podman user-namespace mapping, worker secret
file mount/rotation owner and socket owner/mode are human-approved future
deployment values, not values to guess here. The developer's host-level
privileged account is a residual trust assumption; this profile protects against
compromise of the ordinary service container, not a host owner with full
Podman/container control.

**Portable development deployment contract (PROPOSED; NOT APPROVED).**
All privileged Unix sockets and `SO_PEERCRED` checks occur *inside* the Linux
execution environment. Candidate supported configurations: native Linux with
rootless Podman, WSL2 Linux with rootless Podman, and Windows/macOS with a
Podman-managed Linux VM. Any other Linux VM needs the same evidence. No
Windows/macOS host process connects directly to a privileged Unix socket.
Instead, a separate ephemeral MTMF-owned Linux operator-CLI container runs
under its own UID; host terminals may launch it. Interactive operator
authentication still requires a genuine signed token from the approved OIDC
Authorization Code flow; no device/password-flow or token bypass is inferred.

**Candidate Linux-container IDs, not measured host UIDs:** control worker
`24501`, operator CLI `24502`, admission test ingress `24503`, public runtime
`24504`. These are proposed manifest inputs ONLY; §8/§8A requires a human
to approve their actual mapping. Worker-observed `SO_PEERCRED` values for
operator and ingress must be unique, exact and never an overflow/unmapped UID.
Reject runtime, worker-self, cross-socket, missing or unknown peer credentials.
Unexpected mapping means `STOP-DEPLOYMENT`, not automatic UID selection.

**Candidate sockets (Linux-native/project-scoped volumes only):**

| Interface | Proposed worker/container path | Filesystem + peer gate |
|---|---|---|
| Operator | `/run/mtmf-control/operator/operator.sock` | Separate named volume mounted only by worker and operator CLI; exact operator UID |
| Admission | `/run/mtmf-control/admission/admission.sock` | Different named volume mounted only by worker and admission test harness; exact ingress UID |

Use two distinct socket directories with proposed worker-owned directory
mode `0710` and socket mode `0660`, each with a *different* narrow access
group for the permitted client. Group permissions enable pathname access
but never authorize a caller without exact `SO_PEERCRED` UID verification.
The worker must create these controls without privileged long-running
containers; if actual rootless Podman mappings or POSIX mounts cannot support
them, STOP. Never use mode `0777`, shared UID, TCP/localhost proxy or a
host-mounted Podman socket as a fallback. The admission socket remains
test-harness-only and not publicly callable in PR 24P.

Proposed control DB secret location: `/run/secrets/mtmf-control-db`,
worker-only restricted Linux-native mount with owner-only `0400` or `0600`
file permission as approved. Keep sockets and secrets off unverified host
shares. Retain the `mtmf` Compose project; add a project-scoped private
control network with no published worker port. Worker and required database/
Keycloak TLS-forwarder dependencies may attach to it; public `mtmf-service`
must not. Normal loopback-published dev service ports remain unchanged.

**Gate C per-installation measured evidence, not Gate A/B prerequisites:**
record the Linux environment/kernel, rootless Podman version, actual
namespace UID/GID maps, socket owner/group/mode, exact mounts, secret
permissions, network attachments and worker-observed `SO_PEERCRED` values.
Exercise allowed and rejected callers from their real containers; prove
ordinary runtime cannot read sockets or worker secrets; verify exact five
`mtmf_control_exec` function grants and 78 `mtmf_runtime` signatures.
Record real signed-token checks before privileged readiness. Passing on one
environment does not certify another. A host owner with Podman/VM control
remains outside the compromised-runtime containment claim.

Human architecture approval (Gate A) and target manifest approval (Gate B)
do not assert a tested machine. A portable Gate B manifest may be reused on
other machines *without a new human decision* only when its static profile
and security predicates are unchanged and Gate C per-machine evidence proves
exact socket/UID mappings, mounts, grants and §5B.6A callback forwarding.
On drift or failed proof, STOP and require human revision, not automatic
fallback. No deployment resource, migration, role, grant, socket or test is
authorized by this proposed text.

### 5B.6A. On-demand portable operator Authorization Code callback (proposed — frozen for approval)

**Only development sign-in path.** The dedicated ephemeral Linux
`mtmf-operator-cli` (UID from the approved manifest) obtains a real
`mtmf-dev-operator` **user-class access token** through the already-approved
Keycloak confidential OIDC client. The committed
`dev/keycloak/expected-client-policy.json` is unchanged:

| Frozen item | Required exact value |
|---|---|
| Client | `mtmf-evidence-same-client` (confidential; `client-secret`) |
| Audience on user access token | `mtmf-same-client-api` |
| Public issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| Registered redirect URI | `http://127.0.0.1:28400/callback` |
| Browser flow | Authorization Code + PKCE S256; `scope=openid`; no implicit, direct password, impersonation, device-code or exchange fallback |
| Callback host port | Host IPv4 loopback `127.0.0.1:28400` only, temporary |
| Callback container listener | Port `28400` in ephemeral CLI container; separate from operator `AF_UNIX` socket |

**Exact transport boundary and lifecycle (one interactive CLI invocation):**

1. The MTMF launcher creates a separate *ephemeral* non-root operator CLI
   container only upon an explicit operator command, **not on ordinary `up`**.
   It mounts only the operator Unix-socket volume, the public development
   CA trust and its own client-secret file (never the worker DB credential,
   Keycloak master-admin password, owner/migrator password or admission socket).
   An isolated project-scoped operator-auth network connects the CLI only
   to the canonical Keycloak TLS forwarder; no shared general application
   network, host network, Podman admin socket or permanent callback service.
2. Before opening a browser, ensure local port `28400` is free. Create a
   **single-use** callback listener on TCP port `28400` inside the ephemeral
   CLI container; for rootless Podman forwarding it may bind the container's
   private interface (`0.0.0.0:28400`), **never a host-wide interface**.
   Publish **only** `127.0.0.1:28400:28400` on the developer host via
   the approved project-scoped rootless Podman forwarding mechanism.
   This is a temporary browser login endpoint, **not** a control-worker
   TCP listener. No control-worker or admission port is published.
3. Verify from the developer-host browser context that the exact HTTP
   loopback redirect reaches this one-time CLI listener. On Windows/macOS
   Podman Machine and Windows/WSL2, forwarding across the VM/WSL boundary
   is **not assumed**; it must work on the actual environment, map only the
   exact IPv4 loopback port and have no LAN/external listener. On native
   Linux, perform the same check. Any absent, remapped or externally exposed
   forwarding path is `STOP-AUTH-PROFILE`; do not change registered URI,
   publish `0.0.0.0` on host, enable host networking or install SSH tunnels.
4. Generate fresh cryptographically random per-invocation `state` (at least
   256 bits), PKCE `code_verifier` (RFC 7636-compliant, at least 256 bits
   of entropy), S256 `code_challenge`, and OIDC `nonce` (at least 128 bits).
   Retain verifier/state/nonce in the CLI process memory only. Build an
   `response_type=code`, exact client ID, exact redirect URI,
   `scope=openid`, `code_challenge_method=S256`, challenge, state and nonce
   authorization request against the canonical HTTPS issuer.
5. Present the authorization URL for the developer to open in a real
   browser, completing existing Keycloak interactive login. Accept one
   bounded `GET /callback` at exact `Host: 127.0.0.1:28400`, with one
   matching, unconsumed `state` and **exactly one** nonempty authorization
   `code` on success. Keycloak may also return `iss` and `session_state`:
   when present, `iss` must occur once and match the canonical issuer
   **exactly**; `session_state` must occur at most once and is bounded
   opaque data (never an identity or authority input). Ignore other
   non-security extension parameters as OAuth 2.0 §4.1.2 requires, but
   reject duplicate parameter names, duplicate sensitive fields,
   malformed percent-encoding, invalid UTF-8, unexpected method/path/host,
   excessive parameter count/size and replay. The entire raw request
   line plus headers is at most 8 KiB; at most 16 query parameters and
   each percent-decoded value at most 2048 UTF-8 bytes; authorization
   `code` and `state` each must be nonempty and at most 2048 bytes.
   If `error` appears, require exactly one bounded nonempty OAuth error
   and the correct one-time `state`, permit only bounded optional
   `error_description`/`error_uri`/`iss`/`session_state` and ignore
   unrelated extensions; **do not exchange any code** and return
   a generic failure. An `error` alongside `code` is invalid. State
   mismatches, missing/duplicate code on success, or issuer mismatches
   fail closed; no alternate redirect/client configuration is permitted.
   Use one 120-second flow deadline, consume the callback only once,
   and perform exactly one code-to-token exchange only on success.
   On a valid callback, respond with HTTP `303 See Other` to relative
   `/complete`, with `Cache-Control: no-store` and
   `Referrer-Policy: no-referrer`; `/complete` is a static, no-script,
   no-token/no-code completion page with those headers and
   `Content-Security-Policy: default-src 'none'`, no CORS and no
   subresources. Permit at most one subsequent `GET /complete` in the
   short cleanup window (maximum 3 seconds), then terminate the listener.
   No response body or `Location` reflects `code`, `state` or any
   other callback parameter. Authorization codes necessarily transit
   the browser redirect URL; preventing that is **not** an invariant.
6. Exchange the code **once**, from inside the CLI, over validated
   HTTPS to the canonical token endpoint using the exact redirect URI,
   original PKCE verifier and the confidential client's **HTTP Basic**
   authentication. The client secret comes only from a separately
   provisioned owner-restricted, read-only CLI secret file
   `/run/secrets/mtmf-operator-oidc-client`, never argv/env/logs/
   browser/worker/public runtime. The **client secret**, unlike the
   support client-secret Basic and PKCE S256 as specified,
   `STOP-AUTH-PROFILE`; do not substitute a token grant or auth mode.
7. Require a genuine ID token with valid signature, issuer, client
   audience, temporal claims, exact nonce and subject corresponding to
   the obtained access-token subject. Never use the ID token as an
   operator access token. The control worker independently validates
   the genuine **access token**, signed `azp`, audience, subject binding,
   user class and SYSTEM Role under Field 4 and §§5/6A/6B before
   authorizing any control action.
8. On success, timeout, user cancellation, conflict, malformed callback,
   denied token, or any error: terminate the listener and container,
   unpublish `28400`, release the secret mount and zero/discard transient
   state and tokens to the extent the runtime permits. One-shot tokens
   are passed only over the approved private operator `AF_UNIX` request
   and are never stored on disk, printed or sent through public HTTP.

**Callback disclosure boundary.** Because standard Authorization Code
Flow places the transient code in the browser redirect request, the
code is **not** required to be absent from that one browser URL.
Do not persist, log, print, echo in HTML, reflect in the clean
completion redirect, include in a Referer to another origin, or
forward the code outside its single approved HTTPS token exchange.
Prevent HTTP server access logs from recording full query strings;
do not enable browser analytics or external content on the completion
page. The one-use code and PKCE verifier are short-lived and
in-memory only. Browser history/cache behavior is outside the CLI's
ability to erase reliably; `303` to a clean same-origin URL,
`Cache-Control: no-store`, `Referrer-Policy: no-referrer` and no
subresources reduce residual disclosure. This is a bounded
trust assumption, not a claim that the browser never sees a code.

**Confidential client dual-use risk.** The existing
`dev/keycloak/expected-client-policy.json` defines
`mtmf-evidence-same-client` with `serviceAccountsEnabled=true`
**and** `standardFlowEnabled=true`. Thus the CLI-mounted client
secret can also authenticate the client-credentials service principal.
This is a deliberate **development-only residual capability** of
the existing approved client, not an extra SYSTEM authorization.
The worker must reject service-only access tokens irrespective of
their valid signature, issuer, audience or `azp`: only genuine
user-class tokens with the exact persisted ACTIVE `(issuer, subject)`
binding, active non-root Identity/Principal and approved SYSTEM
assignment may perform operator actions. The secret must never
reach the public service, worker, admission harness, normal
initializer or other projects. Record an end-to-end negative
acceptance case in which a genuine Keycloak client-credentials token
from this exact client is rejected as an operator; if it is
accepted or the dual-use capability cannot be safely bounded,
`STOP-AUTH-PROFILE` and seek a separately approved client-policy
amendment rather than guessing one in the implementation.

**Trust and acceptance.** A loopback-published HTTP callback is allowed
**only** for interactive OAuth login; it is not an exception to Field 2's
no-TCP privileged worker boundary. It must be shown unreachable from
LAN/external interfaces and unrelated containers; no unauthenticated
token/log disclosure or persistent socket/port is allowed. The CLI's
callback listener is short-lived and restricted to the approved
operator-auth network; if a separate network/forwarder cannot be
constructed without exposing the callback, STOP rather than share the
ordinary runtime network. The rootless Podman/VM host owner remains a
trusted platform actor.

**Future tests, NOT EXECUTED:**

| ID | Required actual-platform acceptance | Failure |
|---|---|---|
| CB01 | Native Linux/WSL2/Podman Machine browser redirect to exact `127.0.0.1:28400/callback`, as individually claimed | `STOP-AUTH-PROFILE` |
| CB02 | Host publish limited to IPv4 loopback; no remote/LAN or unrelated-container callback reachability | `STOP-AUTH-PROFILE` |
| CB03 | PKCE S256, unpredictable state/nonce, one code exchange, 120-second expiry, replay rejection; real Keycloak `code`/`state`/`iss`/`session_state` response and OAuth error handled correctly; duplicates/issuer mismatch denied | `STOP-AUTH-PROFILE` |
| CB04 | Client secret and tokens only in authorized CLI memory/mounts; unavoidable one-time browser URL carries `code` but no code leaks to logs, HTML, clean completion `Location`, Referer, other network paths or persistent storage; redirection strips visible query | `STOP-PRIVILEGE` |
| CB05 | Genuine Keycloak user flow yields signed access token with issuer/audience/azp, exact subject binding and approved Role; genuine service-credentials token from same dual-use client is denied as operator | `STOP-AUTH-PROFILE` |
| CB06 | State/nonce/issuer mismatch, duplicate code/state, invalid OAuth error, redirect mismatch, bad Basic/PKCE, occupied port and missing VM forwarding all deny with no fallback | `STOP-AUTH-PROFILE` |
| CB07 | Session timeout/failure/success removes port publish, container and temporary secret mount | `STOP-AUTH-PROFILE` |
| CB08 | Standard `up` and opt-out never auto-open a browser, start callback listener or expose port `28400` | `STOP-DEPLOYMENT` |

CB01–CB08 are **future feature acceptance** after Gate A+B, never
pre-implementation approval evidence. Eliminate cached or historical
interactive-login **attestation reuse** entirely: there is no
environment fingerprint, reuse token, or stale CB01–CB08 PASS shortcut.
Each unattended `up` must independently recheck the deployable Gate C
properties: actual manifest match, mapped peer IDs, socket/mount
access restrictions, exact DB privileges, issuer/client attestation,
and absence of unintended privileged transport. Without an
operator command it must not open the browser or callback port.
Report only `development control-plane infrastructure ready; operator
interactive login not verified on this startup`, **not** the stronger
`privileged operator ready` state. On every explicitly invoked
operator session, perform a new genuine browser Authorization Code
flow with CB01–CB08 applicable negative controls before claiming
`privileged operator ready` for that authenticated session.
On failure or token expiration, discard the session and return to
the infrastructure-only state. No interactive login is required
simply to run unattended infrastructure startup, and no previous
session's genuine token/evidence authorizes a new session.
Bootstrap never logs in as an operator automatically.

### 5B.7 Production prohibition and residual trust model (E-I08)

No production build, environment, image, config parsing path, or startup script
may activate this development fixture. On any non-development deployment mode,
an explicit opt-in `true` is an error **before** touching Keycloak/PostgreSQL.
An issuer/client other than the canonical dev issuer/client is an error, not a
dynamically supported alternative. The flag is never sufficient without the
reviewed manifest and actual isolated deployment topology.

The production operator assignment still requires the separately approved human
installation ceremony from Field 5: an authorized human decision ID, exact
verified Identity and Role, immutable append-only audit, and revocation through
an installation-only procedure. No production automatic bootstrap, auto-grant,
or dev fixture label is acceptable. The database cannot cryptographically attest
a human approver; the trusted installer/fixture process remains the authority
boundary and residual risk.

### 5B.8 Planned acceptance obligations (NOT EXECUTED)

These are **planned**, not executed. A future approved implementation must use
real PostgreSQL, genuine runtime/control credentials, actual rootless Podman
containers with distinct UIDs/mounts, and genuine signed local Keycloak user
tokens with the approved realm/client; mocked authorizers or fabricated JWTs are
not acceptance evidence.

| ID | Required scenario | Future required evidence |
|---|---|---|
| E01 | Missing/false bootstrap flag | Test both fresh opt-out and opt-out after prior opt-in: existing dev stack runs unchanged; no new control mutation or worker; prior persisted role/grants/fixture may remain. |
| E02 | Exact true + canonical dev mode/issuer/profile | Pre-provision role absence accepted (not STOP), then migration/postflight, administrator role creation, owner grants, fixture, and all preflight gates. |
| E03 | True on non-dev mode/noncanonical issuer | STOP before DB, Keycloak or container privilege changes. |
| E04 | Fresh isolated Keycloak + PostgreSQL, valid password file | Dedicated `mtmf-dev-operator` created once; actual `sub` verified from Keycloak REST response. |
| E05 | Repeated `up` against unchanged fixture | Verify-only existing role/grants/fixture; same IDs, one ACTIVE assignment, one immutable creation event; no write, password reset, regrant or audit inflation. |
| E06 | Existing same username without matching MTMF fixture | STOP; no automatic takeover. |
| E07 | Disabled/ambiguous/drifted/federated Keycloak operator | STOP; no account repair. |
| E08 | Different user subject from previous fixture | STOP; no cross-subject binding. |
| E09 | Deleted/LOCAL/root operator Identity or inactive Principal | STOP; no assignment. |
| E10 | Approved SYSTEM Role seed missing/drifted | STOP-SEED; no policy synthesis. |
| E11 | Assignment previously REVOKED | STOP; no regrant or alternate UUID. |
| E12 | Partial Keycloak create vs PostgreSQL failure | No blind retry or auto rollback of Keycloak; stable diagnostic/provenance. |
| E13 | Real standard-flow signed operator token | Exact issuer/audience/client/subject ACTIVE binding and SYSTEM authorization succeed for allowed Action; denied Action remains DENY. |
| E14 | Service-only token or forged user claims | Operator request denied; no DB mutation. |
| E15 | Runtime UID tries operator Unix socket | Peer rejected under real container user-namespace mapping. |
| E16 | Runtime UID tries admission socket and worker DB secret | Both unavailable; no public proxy or shared secret mount. |
| E17 | Runtime DB role invokes any of five control functions or protected DML | Permission denied; exact 78-signature runtime allowlist intact and exact post-grant least-privilege surface. |
| E18 | Control DB role tries direct table DML or `SET ROLE mtmf_owner` | Permission denied; exactly five reviewed EXECUTEs and no additional reachability. |
| E19 | One-shot initializer exited, long-lived containers inspect | Neither public service nor control worker holds installer, Keycloak master-admin, owner or migrator credentials. |
| E20 | Restart/reset/transport failures | No premature readiness; partial-install state STOPs; MTMF-only resource scope; opt-out is not revocation; explicit destructive reset gate; no other project touched. |

The future acceptance topology also requires the canonical `./build.sh --qa`,
`--sec`, `--rust`, `--integration`, `scripts/mtmf-provision-roles.py --verify`,
and the deployed negative-control harness. Runtime versions and hardware must be
recorded when benchmarking is actually approved; no benchmark is run by this
documentation revision.

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

Owner-owned functions; the migration installs them without a control-role
dependency, and a separately approved installation phase grants them only to
`mtmf_control_exec`:

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

mtmf.control_pre_tenant_admission_read(
  application_id_value uuid,
  issuer_value text,
  subject_value text
) RETURNS jsonb
```

Revision `0016` installs the exact five owner-owned `SECURITY DEFINER` functions
with PUBLIC EXECUTE revoked and **no `mtmf_control_exec` role dependency or
grant in the migration itself**. The separately approved deployment/install
phase, after `0016` has migrated and the control LOGIN has been provisioned,
grants exactly these five EXECUTEs to `mtmf_control_exec` and then verifies its
full effective privilege surface. The worker cannot start until that
verification succeeds. An absent role before first installation is expected; an
absent or drifted role after installation is a STOP. This distinction applies to
development and to the separate, human-controlled production installation
ceremony; it does not expand runtime privileges or authorize production
auto-bootstrap.

Arguments are **data supplied by the trusted control process after JWT
verification**, not cryptographic DB authentication evidence. The operator
wrapper independently checks that the ACTIVE exact `(issuer, subject)` binding
resolves to `operator_identity_id_value`, that the Identity belongs to
`operator_principal_id_value`, that both are active and non-root, and that a
still-ACTIVE `system_operator_assignment` grants the exact Role. Its
exact-Action check is the deny-only equality guard in §6B.1 row 6; it never
returns ALLOW. The `GET` wrapper is read-only; mutation wrappers reuse v014 and
write atomic audit/replay.

The fifth, pre-Tenant signature verifies historical subject state and
preliminary entitlement/quota on one exact verified Application and
`(issuer, subject)` key (§5A.7), is callable only by the future
`mtmf_control_exec`, and is **never** operator authorization or an Action
ALLOW. The other four proposed signatures, their argument ordering, the
reserved SQLSTATEs and the privilege model are unchanged.

**Reserved SQLSTATEs (proposed):** `MT049` malformed/unacceptable private-control
input or wrong canonical actor/target; `MT050` denied/missing SYSTEM assignment
or exact Action mismatch; `MT051` replay fingerprint conflict/concurrent state
conflict. All fail closed, never map to ALLOW, never disclosed through the
protocol. If these are already allocated on the branch, the agent stops
(`STOP-00`) rather than renumbering.

## 8. Deployment-specific values the approving human must record (not agent-selectable)

These are **Gate B static deployment-manifest choices**, not claims about
an already deployed Linux host. Gate A approves the fields and their policy;
Gate B records a concrete reusable deployment manifest (including approved
UID/GID identities, socket paths/modes, network and secrets) before
implementation authorization. Live mapped-peer, kernel/Podman observations,
socket/mount outcomes and signed-token tests are **Gate C evidence** after
authorized implementation. A fresh machine may reuse the same approved
manifest if Gate C verifies it conforms; machine-specific evidence is not
a new discretionary approval. Any absent Gate A/B human decision still
keeps `STOP-P24P-TOPOLOGY` active.

| Value | Gate B-approved static value (NOT a claim of deployed conformance) |
| --- | --- |
| Canonical operator CLI peer UID / GID | `24502:24502`; supplementary operator group `24602`; only exact peer UID `24502` accepted |
| Dedicated control worker UID / GID | `24501:24501`; supplementary socket groups `24602`, `24603` |
| Public runtime UID / GID | `24504:24504`; no control socket groups, mounts, worker secrets or privileged listener |
| Operator Unix socket absolute path | `/run/mtmf-control/operator/operator.sock`; project-scoped `control-operator-socket` volume |
| Operator socket ownership and permissions | directory `24501:24602:0710`; socket `24501:24602:0660`; exact operator peer UID `24502` |
| Admission ingress UID / GID | `24503:24503`; supplementary admission group `24603`; only exact peer UID `24503` accepted |
| Admission Unix socket absolute path | `/run/mtmf-control/admission/admission.sock`; project-scoped `control-admission-socket` volume |
| Admission socket ownership and permissions | directory `24501:24603:0710`; socket `24501:24603:0660` |
| Isolated worker DB secret | logical ID `mtmf-pr24p-control-db`; only worker mount `/run/secrets/mtmf-control-db` owner UID `24501`, effective `0400`; role `mtmf_control_exec` |
| Canonical Compose project | `mtmf` only; unrelated projects untouched |
| Network isolation | `control-private` worker/required Postgres/Keycloak TLS dependencies only; `operator-auth` ephemeral CLI/Keycloak forwarder only; no public worker port |
| Approved Linux execution modes | rootless Podman within native Linux, WSL2 Linux or Podman-managed Linux VM; each requires later Gate C verification of real namespaces, peer identity and restrictions |
| Rotation/runbook owner | MTMF development deployment operator (human administering the `mtmf` Podman project) |
| On-demand OAuth callback | `127.0.0.1:28400:28400` temporary loopback forward; `http://127.0.0.1:28400/callback`; ephemeral CLI; client secret `/run/secrets/mtmf-operator-oidc-client` with effective `0400` and UID `24502`; PKCE S256; state/nonce; 120-second bound; teardown |
| Normative exact manifest reference | `mtmf-pr24p-development-gateb-v1` §§B1–B5 in `PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md` at immutable PR #78 source commit `14123a74e05871a3eaa81b17fd383cdd83a6a7f6` |

### 8A. Development-profile approval items (Amendment E)

These fixed non-secret values are **Gate A-approved architecture and Gate B-approved static-manifest values**. The user approved the exact versioned static profile without amendments on 2026-11-13. Real machine-specific mapping and
callback reachability are automatically measured at Gate C, never guessed
from `id -u` or accepted from the host OS label.

| Development-profile approval item | Gate B-approved static value |
|---|---|
| Profile ID | `mtmf-pr24p-local-development-v1` — APPROVED |
| Deployment mode | `development` only |
| Canonical Compose project | `mtmf` |
| Canonical issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| Fixed Keycloak operator username | `mtmf-dev-operator` |
| Fixed SYSTEM Role | `urn:mtmf:iam:roles:system:application-administrator` |
| Bootstrap opt-in selector | `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true`; unset/false disables; never auto-bootstrap in production |
| Operator password-file custody | secret `mtmf-pr24p-operator-password`; initializer UID `24505` only, file `/run/mtmf-operator-install/dev-operator-password`, effective `0400` |
| Worker, CLI, ingress, runtime, initializer, role-provisioner UIDs/GIDs | `24501:24501`, `24502:24502`, `24503:24503`, `24504:24504`, `24505:24505`, `24506:24506`, respectively; mappings must be verified at Gate C |
| Socket paths, groups, modes | Approved verbatim at §8 and manifest §§B1–B2 |
| Control DB / client secret and rotation | worker-only control secret and CLI-only OIDC client secret; logical names/mounts and human rotation owner as approved in §§B3–B4 |
| Fixture decision/provenance | Gate A `MTMF-PR24P-GATE-A-2026-11-13-01` plus Gate B `MTMF-PR24P-GATE-B-2026-11-13-01`; immutable fixture provenance `dev-fixture:mtmf:pr24p:system-operator:v1` |
| Operator OAuth manifest | approved §B4 `operator-auth` network, exact redirect and temporary host-loopback forwarding; actual behavior verified at Gate C |

**Portable static profile (APPROVED / NOT YET MEASURED):** Linux-container
UIDs `24501` (worker), `24502` (operator CLI), `24503` (admission harness),
`24504` (runtime); paths `/run/mtmf-control/operator/operator.sock`,
`/run/mtmf-control/admission/admission.sock`; secret file
`/run/secrets/mtmf-control-db`; two separate MTMF-project socket volumes
(proposed directory/socket modes `0710`/`0660`, distinct approved groups),
private control network without published worker ports. Exact static GIDs, ownership, custody and decision ID are approved in §§B1–B6 of the referenced manifest; effective machine-specific maps, mounts, platform behavior and observed credentials remain **UNVERIFIED — GATE C REQUIRED**.

Portable architecture (Gate A) and one reusable static manifest (Gate B)
may be approved once. Each installation must then prove worker-observed
peers, mounts, callback routing and effective privileges (Gate C); a
passing instance never authorizes a nonconforming one. A candidate number
is not an approved host value and a fresh machine does not require
human reapproval when it passes the unchanged manifest predicates.

**Callback static profile APPROVED, deployed reachability NOT VERIFIED:** one ephemeral operator CLI container
and dedicated operator-auth network, temporary host-loopback mapping
`127.0.0.1:28400:28400`, registered redirect
`http://127.0.0.1:28400/callback`, restricted client secret at
`/run/secrets/mtmf-operator-oidc-client`, PKCE S256, state and nonce,
120-second maximum flow. No persistent callback port and no worker TCP
listener. §5B.6A is authoritative; browser-to-container VM forwarding
must be verified independently for each claimed execution platform.

## 9. Human architecture/manifest decision (Gate A+B) and later deployment acceptance (Gate C)

**Human authorization has been explicitly given for Gate A and, separately,
Gate B** (decisions `MTMF-PR24P-GATE-A-2026-11-13-01` and
`MTMF-PR24P-GATE-B-2026-11-13-01`, both 2026-11-13 UTC). Gate A approves
the architecture at the immutable PR #77 merge commit; Gate B approves the
unaltered static manifest §§B1–B5 at the immutable PR #78 source commit
`14123a74e05871a3eaa81b17fd383cdd83a6a7f6` and authorizes resuming
PR 24P implementation once this decision record merges. The post-implementation Gate C evidence
belongs to the acceptance report, not to a pre-implementation YES/NO
question. Neither an accepted documentation fixup nor a GitHub PR merge
automatically completes either human gate.

```text
GATE A — HUMAN ARCHITECTURE DECISION (required before Gate B)
Decision ID:        MTMF-PR24P-GATE-A-2026-11-13-01
Date (UTC):         2026-11-13
Approving party:    MTMF project owner (linked GitHub @yduchesne; explicit ChatGPT approval)
Approved document/revision/commit: PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md, rev 4, PR #77 merged commit 4b48f5a14bbadf99b5b30be99a256cf3d47304b4
Exact approved text reference / evidence: User explicitly replied "yes" in ChatGPT to unamended Gate A question for merged PR #77; documented by assistant, no cryptographic signature.
Conditions / amendments: None to approved architecture. At the time of this Gate A decision, Gate B was pending; it was subsequently separately approved without amendment. Gate C remains untested.
All 12 topology fields approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Operator protocol §5 approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Pre-Tenant admission protocol §5A, §5A.6 and §5A.7 approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Amendment D historical-subject read and fifth §7 signature approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Fingerprint §6 approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Authorization snapshot §6A approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Policy/SQL split §6B approved verbatim? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
All five private SQL signatures and reserved SQLSTATEs §7 approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Development-only fixture Field 5/§5B, no-regrant, exact Role/provenance approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Portable Linux execution boundary §5B.6 approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Portable OAuth callback §5B.6A (exact existing redirect and no worker TCP) approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Manifest schema/static constraints in §8/§8A + Gate C test obligations approved? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)
Production automatic bootstrap independently prohibited? YES (approved MTMF-PR24P-GATE-A-2026-11-13-01)

GATE B — HUMAN STATIC DEPLOYMENT MANIFEST / IMPLEMENTATION AUTHORIZATION
Decision ID:         MTMF-PR24P-GATE-B-2026-11-13-01
Approving party:     MTMF project owner (connected GitHub @yduchesne)
Date (UTC):          2026-11-13
Evidence:            In this ChatGPT conversation, "I approve this PR without amendment", explicitly linking PR #78
Gate A decision ID:  MTMF-PR24P-GATE-A-2026-11-13-01
Approved manifest:   mtmf-pr24p-development-gateb-v1, §§B1–B5 of PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md at original PR #78 head 14123a74e05871a3eaa81b17fd383cdd83a6a7f6
§8 static identities, socket, secret, network values: YES — unamended
§8A dedicated dev operator, secret custody and fixture: YES — unamended
§5B.6A callback manifest and OAuth isolation: YES — unamended
Manifest reuse policy / per-machine Gate C: YES — unamended
Resume existing PR 24P Parts A–E subject to STOP gates: YES — authorized after PR #78 merges
Gate C deployed acceptance: NOT EXECUTED
Recorder: assistant attribution of explicit user decision; not cryptographically signed
```

**GATE C — NOT EXECUTED; post-implementation deployed acceptance, not a
pre-implementation human checkbox.** The future acceptance report must
record actual target environment, kernel/Podman/user-namespace maps, worker
`SO_PEERCRED`, both socket and mount/access probes, the five control grants,
78 runtime signatures, genuine browser→loopback→CLI Authorization Code flow,
correct token handling, and negative controls. Only a passing Gate C allows
the privileged-ready claim. On failure remain `STOP-DEPLOYMENT`,
`STOP-PRIVILEGE` or `STOP-AUTH-PROFILE` as applicable. An approved and
unchanged static manifest may be reused by another machine after its own
successful Gate C evidence; no additional human decision is required unless
the manifest or security predicates need to change.

## 10. What this document is not

- This document records Gate A/B human approvals and preserves earlier proposal text as history; it is **not** a claim of implemented deployment or Gate C acceptance.
- Not an implementation authorization. No migration, role, grant, wrapper,
  socket, listener, package, or deployment is created by this artifact.
- Not a claim that the PR 21 Action/Role approval, GitHub merge/review, or a
  request to "execute the plan" clears the topology gate.
- Not a substitute for PR 24 or PR 22B; it does not complete v0.1 onboarding.

## 11. Consequence of the decision

- **Gate A and Gate B are explicitly approved**, with no amendments to the frozen architecture or static manifest. The precise Gate B implementation policy is frozen at original PR #78 head `14123a74e05871a3eaa81b17fd383cdd83a6a7f6`, §§B1–B5 of the manifest.
- **After PR #78 merges, clear only `STOP-P24P-TOPOLOGY` and resume the existing `dev/pr24p-part-deux` PR 24P branch**, reconciling the then-current `main` source and preserving prior work. Complete Parts A–E in the existing approved order and STOP at any named sub-gate (AUTH-PROFILE, POLICY-ENGINE, SEED, ROLE-PROVISIONING, SIGNATURE, LOCK-ORDER, AUDIT-POLICY, TRANSACTION, DEPLOYMENT, PRIVILEGE, and other specified controls).
- **Gate C is distinct and NOT EXECUTED.** Real worker-observed `SO_PEERCRED`, namespace, socket/mount access, control/runtime privilege, signed-token, and on-demand browser callback evidence must be gathered after implementation. No unsupported host/VM can claim privileged readiness; an unchanged static manifest may be reused on another machine only with its own passing Gate C evidence.
- Preserve the approved sequence: unconditional role-independent migration `0016` with runtime postflight first; separately provision restricted control role; install precisely five owner EXECUTE grants; validate effective permissions; install/verify one-shot operator fixture; then start isolated worker. Production automatic bootstrap remains forbidden.
- A changed frozen literal, a static trust-policy amendment, a failed/unverifiable Gate C predicate, missing secrets/mappings, or any other unforeseen state must **STOP** and return for human decision. Gate A/B approval is not authority to improvise.

**Terminal decision status:** `GATE_A_APPROVED — GATE_B_APPROVED — PR24P_IMPLEMENTATION_AUTHORIZED_AFTER_PR78_MERGE — GATE_C_PENDING`.
