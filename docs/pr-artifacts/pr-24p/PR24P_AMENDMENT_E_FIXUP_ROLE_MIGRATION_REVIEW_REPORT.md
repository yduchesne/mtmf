# PR24P_AMENDMENT_E_FIXUP_ROLE_MIGRATION_REVIEW_REPORT

**Status:** **`AMENDMENT_E_FIXUP_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`**
**PR:** roadmap **PR 24P**
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**STOP status:** `STOP-P24P-TOPOLOGY` remains **ACTIVE**
**Implementation:** NOT STARTED · **Feature tests:** NOT EXECUTED · **Benchmark:** NOT RUN · **Human approval:** PENDING

> Documentation-only fixup evidence. This report does not authorize or prove any
> migration, role, grant, operator fixture, socket, worker, or deployment.

## Branch/base SHA and clean-start proof

| Item | Observed value |
| --- | --- |
| Repository root | `/home/yduchesne/Dev/Github/yduchesne/mtmf` |
| Branch | `dev/pr24p-part-deux` |
| Branch tip before fixup | `901a0a48a433edc57bd7397b57fef9c31361485a` (Amendment E) |
| `origin/main` | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| `origin/dev/pr24p-part-deux` before fixup | `901a0a48a433edc57bd7397b57fef9c31361485a` |
| Merge base | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| `git status --porcelain` before edits | empty (clean) |
| Migration head in reviewed source | `0015` |
| Current PostgreSQL roles in reviewed source | `mtmf_owner`, `mtmf_migrator`, `mtmf_runtime` only |
| Runtime allowlist | exactly **78** signatures |
| Previous Phase 0 baseline | `8712418a3d2de212791ae75a6235d3e00fced450` (historical) |

## Exactly changed paths

```text
docs/pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md
docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md
docs/pr-artifacts/pr-24p/PR24P_STOP_AND_DEVIATION_REPORT.md
docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_E_FIXUP_ROLE_MIGRATION_REVIEW_REPORT.md
```

No code, SQL, migration, Compose/YAML, Dockerfile, script, test, environment
template, certificate, credential, or deployment file changed.

## Old/new migration, grant, and D13 wording

### Startup ordering (§5B.4 / profile)

**Old:** step 2 provisioned/verified `mtmf_control_exec` through a one-shot
administrator context *before* step 3 ran migration to the approved head and
postflight, then installed the operator fixture in that same phase.

**New:** step 2 runs the existing initializer and migrates to head `0016` (with
mandatory runtime postflight) **before** step 3 creates/verifies the control
LOGIN, step 4 installs/verifies the exact five owner grants, and step 5 installs
the operator fixture. Steps 6–8 exit installers, start the isolated worker/public
service, and prove/report only after all positive and negative checks pass.

### Role-independent migration (§5B.4 / §7)

**Old §7 lead-in:** “Owner-owned; granted only to `mtmf_control_exec`.”
**New §7 lead-in:** “Owner-owned functions; the migration installs them without a
control-role dependency, and a separately approved installation phase grants
them only to `mtmf_control_exec`.”

New normative paragraph: revision `0016` installs the five owner-owned
`SECURITY DEFINER` functions with PUBLIC revoked and **no `mtmf_control_exec`
role dependency or grant in the migration itself**. It must not `CREATE ROLE`,
`GRANT ... TO mtmf_control_exec`, branch on the flag/profile, or add any runtime
grant. It must pass the runtime postflight whether the role is absent or present.
The later approved installation phase grants exactly five EXECUTEs and verifies
the full effective surface before the worker may start.

### D13 (§5B.5)

**Old:** “`mtmf_control_exec` role absent/privileged/grants drifted →
STOP-ROLE-PROVISIONING; work around with migrator or runtime pool.”

**New:** fresh pre-provision absence is expected and is not a STOP; the isolated
approved administrator phase creates the role, then owner authority installs and
verifies exactly five grants. After provisioning, absent/partial/overprivileged/
drifted role or grants are `STOP-ROLE-PROVISIONING`/`STOP-PRIVILEGE`. A
previously installed role is verify-only; partial state requires explicit human
remediation. Using migrator/runtime to `CREATE ROLE`, silently repairing, or
rotating unrelated credentials is forbidden.

### §9 approval reference

**Old:** `§8 development-profile values complete, verified and approved? YES / NO`
**New:** `§8A development-profile values complete, verified and approved? YES / NO`

## Six-plus state model

| State | Role/fixture state | Required behavior |
| --- | --- | --- |
| S01 fresh opt-out | Control role absent; no fixture | Migrate `0016`, verify 78 runtime signatures, run ordinary stack; no role/grant/operator/worker. |
| S02 fresh opt-in before migration | Three legacy roles; control absent | Run migration/postflight; pre-provision absence is expected, not D13 STOP. |
| S03 opt-in after migration, before role creation | Five private functions owner-owned; control absent | Separate administrator `--provision-control` creates restricted LOGIN; never migrator/runtime. |
| S04 opt-in after role creation, before grants | Restricted LOGIN exists; grants not installed | Owner-authorized initial grant of exactly five signatures, then control verification; not readiness. |
| S05 opt-in after grants, before fixture | Exactly five effective EXECUTEs | Installation-only fixture creates/validates operator when pristine. |
| S06 opt-in complete prior state | Exact role/grants/fixture present | Verify only; no password rotation, regrant, audit inflation, or role reset. |
| S07 opt-out after prior opt-in | Existing role/grants/operator persist | Ordinary stack only; no worker/mutation/revoke/drop/rotation. Opt-out is not revocation. |
| S08 opt-in after prior opt-out | State matches S06 | Verify only; worker only after isolation checks. |
| S09 unexpected partial state | Role present with missing/extra grants/provenance/fixture | STOP for human repair/reset; never self-heal. |
| S10 privilege contamination | PUBLIC/runtime can reach control surface or allowlist != 78 | STOP-PRIVILEGE; no readiness. |
| S11 contract conflict | Unapproved `0016` migration/grant implementation | STOP-MIGRATION-ROLE-COUPLING. |
| S12 production/noncanonical opt-in | Any state | STOP before privilege operations. |

## Preservation evidence

- §7 still contains **exactly five** signatures: `control_entitlement_grant`,
  `control_entitlement_revoke`, `control_entitlement_get`,
  `control_operator_authorization_snapshot`, and
  `control_pre_tenant_admission_read(uuid,text,text)`. Argument order, `jsonb`
  returns and `MT049/MT050/MT051` reservations are unchanged.
- `mtmf_runtime` remains exactly **78** signatures; no runtime grant or owner
  access is added.
- Findings/requirements A–E, §5/§5A/§5A.7, §6/§6A/§6B, the dedicated
  `mtmf-dev-operator`, exact SYSTEM Role, no-root/no-password-grant rules, and
  the E01–E20 planned matrix remain.
- All twelve topology-field approval boxes and every §8/§8A/§9 `YES / NO`
  answer remain unanswered; deployment values remain blank or
  `UNRESOLVED — HUMAN APPROVAL REQUIRED`.

## Commands run and observed results

| Command | Observed result |
| --- | --- |
| `git fetch origin` | completed; no relevant upstream drift |
| `git branch --show-current` | `dev/pr24p-part-deux` |
| `git status --porcelain` | clean before edits |
| `git rev-parse HEAD origin/main origin/dev/pr24p-part-deux` | `901a0a4…`, `28d5de8…`, `901a0a4…` |
| `git merge-base origin/main HEAD` | `28d5de8…` |
| source inspection (`sed`/`rg`) of `scripts/mtmf-dev-stack.py`, `scripts/mtmf-dev-initialize.py`, `compose.dev.yaml`, migration/role modules, v011/v014/v015 | confirmed existing launcher order, migrator/owner postflight, three roles, head `0015`, 78 signatures |
| `git diff --check` | clean |
| §7 signature count | 5 |
| `## 5B.` section count | 1 |
| D01–D20 / E01–E20 row counts | 20 / 20 |
| §9 old `§8 development-profile` string | absent; only `§8A development-profile` present |
| Markdown fence/link checker over PR 24P artifacts | fences balanced; relative links resolve |
| `git diff --name-status` allowlist | exactly the four permitted docs |

No STOP condition fired during the fixup. No PostgreSQL instance was started, no
database probed, no role/grant created, no Podman/Compose action taken, no
Keycloak Admin REST call made, and no benchmark or feature test executed. Prior
baseline gates are historical and do not validate this fixup.

## Terminal status

**`AMENDMENT_E_FIXUP_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`.**

`STOP-P24P-TOPOLOGY` remains ACTIVE. PR 24P remains `PLANNED; STOP-P24P-TOPOLOGY`;
implementation is NOT STARTED; roadmap DONE is not claimed; PR 22B/PR 24 remain
blocked. Next permitted step is independent review of the revised §5B/§7/§8A,
followed by a separately recorded human approval of all twelve fields and actual
host values.
