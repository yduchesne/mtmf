# PR24P_STOP_AND_DEVIATION_REPORT

**PR:** roadmap **PR 24P**
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Status:** **`PR24P_BLOCKED_TOPOLOGY_APPROVAL`**
**STOP code:** **`STOP-P24P-TOPOLOGY`** (mandatory Phase-0 STOP)
**Decision record revision:** **3** (independent-review Findings A–D addressed, documentation only)
**Baseline SHA:** `8712418a3d2de212791ae75a6235d3e00fced450` (= `origin/main`, PR 23 merged)

## 1. Stop condition

| Item | Detail |
| --- | --- |
| Condition | None of the twelve process/transport/DB-role/actor/transaction/secret/threat-model fields in the PR 24P execution topology has an explicit human approval. |
| Governing authority | `docs/ROADMAP_V01.md` §PR 24P; `docs/ONBOARDING_ARCHITECTURE.md` §19.3; `docs/pr-artifacts/pr-21/PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md` §3–4; the PR 24P execution plan §4. |
| Expected invariant | Privileged execution, its DB role/grants, its transport, and its secret custody may only be implemented after a recorded human decision approving the exact topology and frozen protocol/signatures. |
| Observed result | No decision record exists. The topology proposal is still `PROPOSED — NOT APPROVED`. |
| Classification | **Not a code defect and not an environment failure.** Deliberate, policy-mandated blocking gate. Failure class: *none applicable* — the plan classifies this as a mandatory pre-implementation stop, not a regression. |
| Current SHA | `8712418a3d2de212791ae75a6235d3e00fced450` |
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

## 2A. Amendment record — independent-review Findings A, B, C, D

**Amendment status:** applied to the decision record; **no approval, no
implementation, no topology change**. `STOP-P24P-TOPOLOGY` remains active.

| Finding | Required correction | Amendment applied |
| --- | --- | --- |
| **A** | Define the second private admission interface and its exact trust/protocol contract. | `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md` **§5A**: separate admission `AF_UNIX` socket and dedicated ingress UID; `SO_PEERCRED` exact-UID rules; independent double token verification; 32,768-byte frame; exact `admission.prepare` request (`v`, `operation`, `request_id`, service token, user token only); bounded `CANDIDATE|EXISTING_SUBJECT|NO_ENTITLEMENT` / error envelope; no-write read path via PR 23 + control-role-only entitlement read; no callable public socket in PR 24P; ingress-compromise bounds; and the exact fail-closed `PrivilegedOnboardingTransactionPort` contract (§5A.6). Field 3, Field 7, Field 12 and §8 now reference it. |
| **B** | Correct the authorization snapshot to carry persisted domain identities. | **§6A**: exact snapshot schema carrying persisted `Identity` (id, principal, origin, deletion status, canonical-root flag), `Principal`, `ExternalSubjectBinding` (issuer/subject/lifecycle), `Role` (urn, SYSTEM definition, builtin/approved markers), `PermissionSet` effects, `Permission` URNs/positions, the global assignment, and the typed target — sufficient to reconstruct the internal aggregates and perform every `authorize_global_system` check without a second read. Display names and `extension` excluded. |
| **C** | Freeze policy-evaluation versus SQL-revalidation responsibilities and the transaction boundary. | **§6B**: non-overlapping responsibility table (Python owns token authenticity and general policy evaluation; SQL owns persisted actor/assignment/role facts, locked target/replay state, audit, and a deny-only exact-Action equality guard; SQL never returns ALLOW); exact 10-step execution order; lock order assignment (snapshot) → identity/principal/binding revalidation (wrapper) → replay → Application → entitlement; snapshot locks only the assignment row; single `BEGIN`/`COMMIT`; no external I/O under transaction; no deadlock retries. |
| **D** | Revoked-only external subject history was indistinguishable from a new subject in the proposed pre-Tenant admission read; §5A also mentioned unsupported entitlement expiration. | **§5A.7** replaces the one-argument entitlement read with the exact three-argument `control_pre_tenant_admission_read(application_id, issuer, subject)` proposal; freezes `NEVER_SEEN`/`ACTIVE`/`REVOKED_ONLY`/`CONFLICT` precedence (ACTIVE + older REVOKED remains ACTIVE), the internal result schema, R01–R10 handler mapping, entitlement/exhaustion rules, and the current no-expiration invariant. The obsolete expiry wording is removed. Documentation proposal only; no implementation or approval. |

**Preserved unchanged:** the twelve topology fields' substantive proposals, the
operator protocol §5, fingerprint §6, **four unchanged operator SQL signatures**
in §7, SQLSTATE reservations, no-`mtmf_runtime`-grant rule, runtime allowlist
78, root exclusion, admission-marker zero grants, and PR 22B composite
deferral. The fifth §7 signature is replaced by the §5A.7 pre-Tenant admission
read.

**Findings not implemented as code:** correct. This remains Phase 0; any code
would violate `STOP-P24P-TOPOLOGY`.

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

## 5. Smallest decision required

A single recorded human decision that:

1. approves **all twelve** topology fields in
   [PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md](PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md) §4,
   **verbatim or with an explicit revised plan**;
2. approves the frozen operator protocol (§5), the **pre-Tenant admission
   protocol (§5A)**, the **subject-history/entitlement read (§5A.7 and the
   revised fifth §7 signature)**, the canonical fingerprint (§6), the
   **persisted-domain-identity authorization snapshot (§6A)**, the
   **policy-vs-SQL responsibility and transaction boundary (§6B)**, and the
   exact five private SQL signatures plus reserved SQLSTATEs (§7);
3. supplies the deployment-specific host values in §8 (operator admin UID,
   control UID/GID, runtime UID/GID, operator socket path/owner/mode, **ingress
   UID/GID and admission socket path/owner/mode**, secret mount, Podman project,
   control network, host platform confirmation, rotation owner);
4. records decision ID, date, approving party, exact approved text/version,
   evidence reference, and any conditions in §9.

Until that exists, the correct response to a request to "implement PR 24P" is
`PR24P_BLOCKED_TOPOLOGY_APPROVAL`, not code.

## 6. Final status

**`PR24P_BLOCKED_TOPOLOGY_APPROVAL`.**

Not `DONE`. Not `PARTIAL_BLOCKED` due to a test failure — blocked *before*
implementation by the mandatory human topology gate. No dependent PR (PR 22B,
PR 24) may start privileged execution before this approval and PR 24P
acceptance.
