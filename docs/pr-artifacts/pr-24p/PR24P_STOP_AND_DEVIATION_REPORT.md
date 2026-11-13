# PR24P_STOP_AND_DEVIATION_REPORT

**PR:** roadmap **PR 24P**
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Status:** Gate A and Gate B **APPROVED** (decisions `MTMF-PR24P-GATE-A-2026-11-13-01` and `MTMF-PR24P-GATE-B-2026-11-13-01`); existing PR 24P may resume after PR #78 merges; Gate C pending
**STOP code:** **`STOP-P24P-TOPOLOGY`** — historical Phase-0 stop; cleared for resumed implementation once PR #78 approval record is merged
**Decision record revision:** **4** (Findings A–D retained; Amendment E with portability review callback/approval-gate fixup proposed, documentation only)
**Baseline SHA:** `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` (= `origin/main`, rev 3 merged via PR #76); historical Phase 0 baseline `8712418a3d2de212791ae75a6235d3e00fced450`

## 1. Stop condition

| Item | Detail |
| --- | --- |
| Condition | The original Phase-0 stop required approval of all twelve fields. That requirement is now satisfied at Gate A by `MTMF-PR24P-GATE-A-2026-11-13-01`; the remaining blocker is Gate B static manifest/implementation authorization. |
| Governing authority | `docs/ROADMAP_V01.md` §PR 24P; `docs/ONBOARDING_ARCHITECTURE.md` §19.3; `docs/pr-artifacts/pr-21/PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md` §3–4; the PR 24P execution plan §4. |
| Expected invariant | Privileged execution, its DB role/grants, its transport, and its secret custody may only be implemented after a recorded human decision approving the exact topology and frozen protocol/signatures. |
| Observed result | Historical Phase-0 STOP predated approvals. Gate A is now approved against immutable merged PR #77 architecture. Gate B is separately approved without amendments against original PR #78 head `14123a74e05871a3eaa81b17fd383cdd83a6a7f6`. Gate C has not executed. |
| Classification | **Not a code defect and not an environment failure.** Deliberate, policy-mandated blocking gate. Failure class: *none applicable* — the plan classifies this as a mandatory pre-implementation stop, not a regression. |
| Current SHA | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` (branch `dev/pr24p-part-deux`); original Phase 0 SHA `8712418a3d2de212791ae75a6235d3e00fced450` is historical evidence |
| Specific file/function involved | No production file or function was touched. The stop is triggered by the absence of an approval for the not-yet-created `packages/mtmf-control-plane/`, `sql/v016/`, and `system_operator_assignment` artifacts. |
| Command/topology | Phase-0 only: `git fetch/rev-parse/status/log`, `scripts/mtmf-postgres.py up`, `scripts/mtmf-provision-roles.py`, `./build.sh --qa`, `--sec`, `--rust`, `--integration`, `scripts/mtmf-provision-roles.py --verify`, and read-only catalog queries on `127.0.0.1:25432/mtmf`. |

## 2. Evidence

See [PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md](PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md).

- Baseline `8712418` matches the plan's reference; PR 23 F1/F2 fixup `a68177e`
  is present; Alembic head `0015`; runtime allowlist exactly **78**; only
  `mtmf_owner`/`mtmf_migrator`/`mtmf_runtime` exist (no `mtmf_control_exec`).
- `--qa`: 2490 passed / 90.30% coverage. `--sec`: 0 findings.
  `--rust`: PASS. `--integration`: 646 passed / 94 skipped.
  `--verify`: PASS.
- No `system_operator`, `control_plane`, `authorize_global`,
  `mtmf_control_exec`, or `operator_contracts` implementation exists anywhere.

## 2A. Amendment record — independent-review Findings A, B, C, D, E

**Amendment status:** applied to the decision record; **no approval, no
implementation, no topology change**. `STOP-P24P-TOPOLOGY` remains active.

| Finding | Required correction | Amendment applied |
| --- | --- | --- |
| **A** | Define the second private admission interface and its exact trust/protocol contract. | `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md` **§5A**: separate admission `AF_UNIX` socket and dedicated ingress UID; `SO_PEERCRED` exact-UID rules; independent double token verification; 32,768-byte frame; exact `admission.prepare` request (`v`, `operation`, `request_id`, service token, user token only); bounded `CANDIDATE|EXISTING_SUBJECT|NO_ENTITLEMENT` / error envelope; no-write read path via PR 23 + control-role-only entitlement read; no callable public socket in PR 24P; ingress-compromise bounds; and the exact fail-closed `PrivilegedOnboardingTransactionPort` contract (§5A.6). Field 3, Field 7, Field 12 and §8 now reference it. |
| **B** | Correct the authorization snapshot to carry persisted domain identities. | **§6A**: exact snapshot schema carrying persisted `Identity` (id, principal, origin, deletion status, canonical-root flag), `Principal`, `ExternalSubjectBinding` (issuer/subject/lifecycle), `Role` (urn, SYSTEM definition, builtin/approved markers), `PermissionSet` effects, `Permission` URNs/positions, the global assignment, and the typed target — sufficient to reconstruct the internal aggregates and perform every `authorize_global_system` check without a second read. Display names and `extension` excluded. |
| **C** | Freeze policy-evaluation versus SQL-revalidation responsibilities and the transaction boundary. | **§6B**: non-overlapping responsibility table (Python owns token authenticity and general policy evaluation; SQL owns persisted actor/assignment/role facts, locked target/replay state, audit, and a deny-only exact-Action equality guard; SQL never returns ALLOW); exact 10-step execution order; lock order assignment (snapshot) → identity/principal/binding revalidation (wrapper) → replay → Application → entitlement; snapshot locks only the assignment row; single `BEGIN`/`COMMIT`; no external I/O under transaction; no deadlock retries. |
| **D** | Revoked-only external subject history was indistinguishable from a new subject in the proposed pre-Tenant admission read; §5A also mentioned unsupported entitlement expiration. | **§5A.7** replaces the one-argument entitlement read with the exact three-argument `control_pre_tenant_admission_read(application_id, issuer, subject)` proposal; freezes `NEVER_SEEN`/`ACTIVE`/`REVOKED_ONLY`/`CONFLICT` precedence (ACTIVE + older REVOKED remains ACTIVE), the internal result schema, R01–R10 handler mapping, entitlement/exhaustion rules, and the current no-expiration invariant. The obsolete expiry wording is removed. Documentation proposal only; no implementation or approval. |
| **E** | Field 5 previously forbade initializer provisioning; local deterministic bootstrap cannot be automated without an approved narrow exception. | **§5B** permits only an explicitly opt-in, one-shot, canonical-dev, dedicated non-root `mtmf-dev-operator` fixture with the exact approved SYSTEM `application-administrator` Role, immutable `dev-fixture:mtmf:pr24p:system-operator:v1` provenance, strict no-regrant reconciliation, real UID/socket/secret isolation, and production exclusion. Field 5 retains the production human-ceremony prohibition. No code or human approval. |

**Preserved unchanged:** the twelve topology fields' substantive proposals, the
operator protocol §5, fingerprint §6, **four unchanged operator SQL signatures**
in §7, SQLSTATE reservations, no-`mtmf_runtime`-grant rule, runtime allowlist
78, root exclusion, admission-marker zero grants, and PR 22B composite
deferral. The fifth §7 signature is replaced by the §5A.7 pre-Tenant admission
read.

**Findings not implemented as code:** correct. This remains Phase 0; any code
would violate `STOP-P24P-TOPOLOGY`.

## 2B. Amendment E proposed development bootstrap

Amendment E is a **documentation-only proposal**, not an implementation. It adds
the canonical development profile (`mtmf` project, issuer
`https://keycloak.mtmf.test:28443/realms/mtmf-dev`), one dedicated non-root
`mtmf-dev-operator`, the exact SYSTEM
`urn:mtmf:iam:roles:system:application-administrator` Role, and the fixed
`dev-fixture:mtmf:pr24p:system-operator:v1` provenance under an explicit
`MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true` opt-in.

It does **not** bypass the production human installation ceremony and creates no
ordinary dev-user or root SYSTEM authority. Actual UID/GID, socket, secret-mount,
namespace, and fixture decision values remain **UNRESOLVED — HUMAN APPROVAL
REQUIRED**. `mtmf_runtime` retains 78 signatures; no control role, grant, socket,
container, database, or token exists. The future development profile is
summarized in
[PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md](PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md),
but §5B of the decision record is authoritative.

## 2C. Amendment E independent-review fixup — migration/control-role sequencing

This fixup corrects two defects in the unapproved Amendment E proposal, without
changing approval state or implementation:

1. **Migration/role ordering contradiction.** §5B.4 previously provisioned
   `mtmf_control_exec` before the one-shot migration, while D13 treated an
   absent role as an immediate STOP, falsely blocking a fresh installation.
   The frozen correction makes future `0016` **role-independent, unconditional
   and PUBLIC-denied**: the migration installs the five owner-owned private
   functions and passes the 78-signature runtime postflight with the control
   role absent or present, and issues no `CREATE ROLE`/control grant. Only
   after migration does the opt-in installation phase use administrator
   authority to create/verify the restricted LOGIN, then owner authority to
   grant and verify exactly five EXECUTEs, then install the operator fixture.
2. **Opt-out persistence.** On a previously opted-in database, disabling the
   flag **retains** the role/grants/fixture and does not revoke, drop, repair or
   rotate them; the flag is not revocation. A fresh opt-out creates no new
   control objects and never starts the worker. Actual revocation is a separate
   human-approved action.
3. **D13 phase awareness.** Role absence is expected only before first
   provisioning; absent/partial/overprivileged/drifted state after provisioning
   is `STOP-ROLE-PROVISIONING`/`STOP-PRIVILEGE`; a complete prior installation
   is verify-only.
4. **Approval reference.** The §9 development-profile line now correctly cites
   §8A, not §8.

This remains **documentation only**: no implementation, feature test, service
start, database mutation, role/grant, secret, socket, container, or benchmark.
`STOP-P24P-TOPOLOGY` remains active.

## 2D. Amendment E portable Linux development clarification (documentation only)

Platform-neutral execution clarifies §5B.6 and Fields 1/2/11: privileged
`AF_UNIX` sockets and `SO_PEERCRED` run inside a Linux execution environment.
Native Linux, WSL2 and Linux VMs used by Podman on Windows/macOS are
candidates subject to identical worker-observed peer, mount and privilege
tests. A host label or common rootless Podman owner does not establish
runtime/worker separation.

Proposed candidate container UIDs `24501`–`24504`, separate socket volumes
and paths, worker-only secret and private network are NOT approved or
measured. An ephemeral Linux operator CLI is the socket caller, not the
host OS. Each deployment needs approved §8/§8A values and per-installation
conformance evidence. No fallback to TCP, chmod/same UID or host Podman
socket is permitted. All §9 answers remain unanswered.

This update modifies only PR 24P documentation. No service, migration,
role, grant, secret, socket, container, test or benchmark is run or created.
`STOP-P24P-TOPOLOGY` remains active.

## 2E. Portable topology independent-review P1 fixup — approval and OAuth

Documentation-only correction of the two P1 findings recorded in
[PR24P_PORTABLE_TOPOLOGY_INDEPENDENT_REVIEW_REPORT.md](PR24P_PORTABLE_TOPOLOGY_INDEPENDENT_REVIEW_REPORT.md):

1. **Circular approval:** §3, §8, §8A, §9 and §11 now separate
   Gate A architecture approval, Gate B human-approved reusable static
   deployment manifest/implementation authorization, and Gate C
   post-implementation real deployment tests. Gate C is never a
   pre-implementation YES/NO approval condition. An unchanged approved
   manifest can be reused on another developer machine after automated
   actual-machine Gate C attestation, without another human decision.
   Any changed static trust policy or failed attestation STOPs.
2. **Portable Keycloak callback:** Field 4 and §5B.6A freeze the
   ephemeral Linux operator-CLI Authorization Code + PKCE S256 flow;
   approved confidential client, exact registered redirect
   `http://127.0.0.1:28400/callback`, temporary Podman host-loopback
   port forward, genuine browser flow, CLI-only client-secret file,
   state/nonce/timeout/cleanup and strict STOP conditions. No TCP
   operator/control-worker endpoint is added. §5B.6A specifies CB01–CB08
   as future tests; none has executed.

The development profile repeats these frozen facts, and the new
[PR24P_PORTABLE_TOPOLOGY_CALLBACK_AND_APPROVAL_FIXUP_REPORT.md](PR24P_PORTABLE_TOPOLOGY_CALLBACK_AND_APPROVAL_FIXUP_REPORT.md)
records their documentation reconciliation. The source still lacks the
worker, operator CLI, control role, migration `0016` and real
Podman/Keycloak acceptance. No code, role, grant, database operation,
socket, credential, container, test or benchmark is created or run.
**All §9 Gate A/B human decisions remain unanswered.**
`STOP-P24P-TOPOLOGY` remains ACTIVE.

## 2F. PR #77 callback review fixup — four documentation corrections

The review recorded at
[PR #77 discussion](https://github.com/yduchesne/mtmf/pull/77#issuecomment-6857722638)
identified four doc-only issues. The revised §5B.6A and development
profile now freeze: (1) valid `iss`/`session_state` and OAuth error
responses with duplicate rejection and safe extension handling;
(2) unavoidable browser delivery of a one-time authorization code,
with no-store/no-referrer clean completion and no code reflection/logging;
(3) **no** reuse of historical interactive-login proof—unattended
startup reports only infrastructure readiness, while each operator
session requires a genuine new login; and (4) the explicit
`serviceAccountsEnabled=true` dual-use capability of the
existing confidential Keycloak client, with service-token
negative authorization acceptance and restricted CLI secret custody.

The updated CB01–CB08 evidence remains NOT EXECUTED. The four-file
documentation-only fixup creates no privileged implementation,
roles, grants, migrations, sockets, secrets, tokens or benchmarks.
All Gate A/B human approvals and deployment values remain unresolved.
See
[PR24P_PR77_OAUTH_CALLBACK_REVIEW_FIXUP_REPORT.md](PR24P_PR77_OAUTH_CALLBACK_REVIEW_FIXUP_REPORT.md).
`STOP-P24P-TOPOLOGY` remains ACTIVE.

## 2G. Human Gate A approval after PR #77 merge (2026-11-13)

The MTMF project owner explicitly replied **yes** to the question
"Do you approve the Gate A architecture specified in the merged PR #77
decision record, without amendments?" The decision is transcribed as
`MTMF-PR24P-GATE-A-2026-11-13-01` against merge commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`.
All twelve §4 field decisions and the frozen contracts in §§5–7 are
approved under Gate A. The user was **not** asked to approve a particular
Gate B manifest, so **Gate B remains unapproved**. Neither a completed
container/secret/socket deployment nor Gate C test evidence is claimed.
The candidate manifest and approval provenance are in
[PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md](PR24P_GATE_A_APPROVAL_AND_GATE_B_MANIFEST_PROPOSAL.md).
No PR 24P implementation has been resumed; `STOP-P24P-TOPOLOGY`
remains ACTIVE until an approved Gate B static manifest authorizes it.

## 3. Zero unapproved changes

Phase 0 changed **documentation only**, inside `docs/pr-artifacts/pr-24p/`:

- `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md`
- `PR24P_BASELINE_AND_SCOPE_RECONCILIATION.md`
- `PR24P_STOP_AND_DEVIATION_REPORT.md` (this file)
- `PR24P_PRE_TENANT_ADMISSION_CONTRACT.md` (stale function-name correction)
- `PR24P_AMENDMENT_D_SUBJECT_HISTORY_REVIEW_REPORT.md` (new evidence report)
- not-executed placeholders for the remaining required artifact filenames

No migration, SQL, role, grant, package, socket, listener, deployment, test,
roadmap, or normative document was modified. No secrets were added. No
production module was changed. **No unit/integration, genuine-token, deployed
isolation, or feature test has executed or passed for this amendment; prior
baseline gate results describe the unimplemented base only.**

**Amendment E actual documentation delta:**

- `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md` (rev 4, Field 5, §5B, §8A, §9, §11)
- `PR24P_STOP_AND_DEVIATION_REPORT.md` (this file)
- `PR24P_OPERATOR_AUTHORIZATION_CONTRACT.md` (proposal cross-reference)
- `PR24P_PRIVILEGE_AND_ISOLATION_REPORT.md` (proposal cross-reference)
- `PR24P_GENUINE_TOKEN_AND_RUNTIME_COMPROMISE_ACCEPTANCE.md` (proposal cross-reference)
- `PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md` (new proposal)
- `PR24P_AMENDMENT_E_DEVELOPMENT_BOOTSTRAP_REVIEW_REPORT.md` (new evidence report)

Earlier Amendment D artifacts remain historical, committed evidence. No files
outside `docs/pr-artifacts/pr-24p/` were touched.

**Amendment E targeted fixup actual documentation delta (this change):**

- `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md` (§5B.4, D13, §5B.8, Field 7, §7, §9, §11)
- `PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md` (startup sequence, migration/role/opt-out section, E rows)
- `PR24P_STOP_AND_DEVIATION_REPORT.md` (this fixup record)
- `PR24P_AMENDMENT_E_FIXUP_ROLE_MIGRATION_REVIEW_REPORT.md` (new evidence report)

Prior Amendment E and A–D deltas above remain historical. No files outside
`docs/pr-artifacts/pr-24p/` were touched.

**Current branch baseline:** `901a0a48a433edc57bd7397b57fef9c31361485a`
(Amendment E) on `dev/pr24p-part-deux`; `origin/main` is
`28d5de85ccf63c9ffb5bdc8298156e6038cbdadd`. The earlier `8712418...` baseline is
historical Phase 0 evidence.

**Rollback status:** nothing to roll back. This amendment's repository delta is
the PR 24P documentation set only. The local development database was
started/provisioned earlier for baseline evidence (MTMF-owned Compose project
only); this is ephemeral and outside the repository.

**Secret exposure status:** none. No operator token, control-role credential,
private key, or certificate was created, requested, or logged. `.env.example`
placeholders were exported into the shell for the local gates; no `.env` file
was written or committed.

## 4. Sub-gates that remain un-evaluated

Because the top-level topology gate fired, these conditional sub-gates could
not legitimately be evaluated in Phase 0 and are recorded as un-triggered:

`STOP-00`, `STOP-INGRESS`, `STOP-PROTOCOL`, `STOP-AUTH-PROFILE`,
`STOP-POLICY-ENGINE`, `STOP-SEED`, `STOP-ROLE-PROVISIONING`,
`STOP-SIGNATURE`, `STOP-LOCK-ORDER`, `STOP-AUDIT-POLICY`,
`STOP-TRANSACTION`, `STOP-AUTH-FIXTURE`, `STOP-DEPLOYMENT`,
`STOP-PRIVILEGE`, `STOP-TEST`, `STOP-UNKNOWN`.

One *observation* is recorded, not elevated to a STOP: the
`expected_runtime_signatures()` docstring in
`packages/mtmf-core/src/mtmf_core/persistence/postgres/roles.py` says "44
repository functions" while the map contains 43 (total still correctly 78).
Pre-existing documentation-only defect; no action taken in Phase 0.

## 5. Human approval received; remaining implementation obligations

The project owner's **Gate A** approval is recorded as
`MTMF-PR24P-GATE-A-2026-11-13-01`, against immutable PR #77 merged
architecture `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`.

The owner subsequently explicitly stated **"I approve this PR without
amendment"** and linked PR #78 in this ChatGPT conversation. That
separate **Gate B** decision is recorded as
`MTMF-PR24P-GATE-B-2026-11-13-01`, approving the exact static
`mtmf-pr24p-development-gateb-v1` §§B1–B5 manifest at original PR #78 head
`14123a74e05871a3eaa81b17fd383cdd83a6a7f6`, **without changes**.

Upon merging PR #78, the `STOP-P24P-TOPOLOGY` **approval blocker is cleared**.
The coding agent must resume the **already in-progress**
`dev/pr24p-part-deux` PR 24P branch from its existing Phase-0 STOP checkpoint,
reconcile it against current `main`, and implement approved Parts A–E subject
to all explicit sub-gates. No implementation, role, grants, DB migration,
socket, container, token, secret or benchmark is executed by recording the
approval. No new replacement PR 24P is to be created.

**Gate C remains NOT EXECUTED:** deploy and verify actual worker-observed
UID/GID maps and `SO_PEERCRED`, volume/socket/secret restrictions, effective
control/runtime SQL grants, genuine user-vs-service token discrimination,
Keycloak browser callback, audit/replay and all negative controls. Any
nonconforming platform, unapproved static change or failed predicate must STOP.

## 6. Final status

**`GATE_A_APPROVED — GATE_B_APPROVED — PR24P_IMPLEMENTATION_AUTHORIZED_AFTER_PR78_MERGE — GATE_C_PENDING`.**

Not `DONE` and not privileged-ready. PR 22B and PR 24 remain dependent on
successful PR 24P implementation and acceptance.

## 7. 2026-11-13 post-PR78 resumption — STOP-SEED

**DISPOSITION:** `STOP-SEED` (mandatory approved-seed availability stop).

**Observed after reconciling `dev/pr24p-part-deux` to `origin/main` `9f8190e` and migrating the real MTMF database to `0016`:**

```sql
select urn from mtmf.role where urn = 'urn:mtmf:iam:roles:system:application-administrator';
-- (0 rows)
select role_urn from mtmf.builtin_role where role_urn = 'urn:mtmf:iam:roles:system:application-administrator';
-- (0 rows)
select count(*) from mtmf.permission p
  join mtmf.permission_set ps on ps.id = p.permission_set_id
 where ps.role_urn = 'urn:mtmf:iam:roles:system:application-administrator';
-- 0
```

The PR 21-approved `application-administrator` Role is approved **design**, not an installed seed. The PR 24P resumption plan expressly forbids inventing or synthesizing that Role/PermissionSet/Permission seed in migration `0016`. Without the protected builtin Role, the snapshot/exact-Action guard and the dedicated operator fixture cannot validly install or execute.

**Required invariant:** the approved SYSTEM Role must already exist in `mtmf.role` and `mtmf.builtin_role` with its PR 21-approved permission manifest before any operator assignment/fixture. **No seed was created.**

**Implemented safely before the stop:** additive `0016` schema/five private functions (owner-owned, PUBLIC-denied, no control-role dependency), role-independent migration postflight, `mtmf_control_exec` provisioning/verification modes, core operator/admission contracts and global authorization path, and an isolated `mtmf-control-plane` package skeleton/protocol. Unit QA passed with coverage above the gate; no operator fixture, successful grant/revoke integration, Gate C, or acceptance was claimed.

**Not run/not claimed:** operator fixture installation, real operator grant/revoke/get vertical slice, admission socket/harness live acceptance, Gate C UID/socket/secret/browser proofs, `--integration`/`--sec`/`--rust` final feature gates (to be run at the final feature SHA when the STOP is cleared), and any PR22B composite.

**Smallest human decision needed:** provide/record the separately approved implementation/seed path for the PR 21 `application-administrator` builtin Role and its exact manifest, or explicitly authorize a reviewed seed migration/PR. Do not synthesize it as part of PR 24P without that decision.
