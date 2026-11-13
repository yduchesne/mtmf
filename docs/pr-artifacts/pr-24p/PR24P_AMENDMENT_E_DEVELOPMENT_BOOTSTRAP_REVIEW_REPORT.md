# PR24P_AMENDMENT_E_DEVELOPMENT_BOOTSTRAP_REVIEW_REPORT

**Status:** **`AMENDMENT_E_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`**
**PR:** roadmap **PR 24P**
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**STOP status:** `STOP-P24P-TOPOLOGY` remains **ACTIVE**
**Implementation state:** NOT STARTED · **Feature tests/benchmark:** NOT EXECUTED · **Human approval:** PENDING

> Documentation-only evidence. This report does not accept the proposed
> development bootstrap as implemented, approved, or tested.

## Baseline main/branch SHAs and clean-start evidence

| Item | Observed value |
| --- | --- |
| Repository root | `/home/yduchesne/Dev/Github/yduchesne/mtmf` |
| Branch | `dev/pr24p-part-deux` |
| Branch tip before Amendment E | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| `origin/main` | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| Merge base | `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| Working tree before edits | clean (`git status --porcelain` empty) |
| Recent history | `28d5de8` merge of PR #76 (rev 3 docs); `434ebc2` Amendment D SHA record; `2406407` Amendment D contract; `b8dd4a0` Findings A–C |
| Current decision revision before edits | rev 3 (Findings A–D) |
| Prior Phase 0 baseline (historical) | `8712418a3d2de212791ae75a6235d3e00fced450` |

## Current-main and Phase 0 source reconciliation

Read fresh at the observed base: `AGENTS.md`; the detailed-plan guide; roadmap
PR 24P; security/architecture/database docs; onboarding §19; PR 21 Action
manifest; PR 24P decision record, STOP report, operator/isolation/genuine-token
placeholders; `docs/DEVELOPMENT_SETUP.md`; `scripts/mtmf-dev-stack.py`;
`compose.dev.yaml`/`compose.yaml`; `scripts/mtmf-dev-initialize.py`;
`mtmf_service/development_bootstrap.py`; `mtmf_service/development_user.py`;
`dev/keycloak/expected-client-policy.json`; `roles.py` /
`mtmf-provision-roles.py`; v011 binding schema; v015 B1.

Confirmed facts:

- Existing dev stack launches MTMF-owned PostgreSQL, Keycloak, TLS forwarder,
  one-shot initializer, then unprivileged service; the initializer is the only
  holder of migrator/owner and Keycloak admin credentials.
- Existing ordinary development user is provisioned by exact-username
  create-or-verify with authoritative Keycloak `sub`; it is **not** a SYSTEM
  operator.
- `mtmf-admin` is the Keycloak master-realm bootstrap administrator, not the
  MTMF SYSTEM operator.
- The approved interactive client `mtmf-evidence-same-client` uses standard
  authorization-code flow; password grant is disabled.
- Role provisioning currently covers owner/migrator/runtime only; runtime
  allowlist is 78; no `mtmf_control_exec` exists.
- No `system_operator_assignment` table, migration `0016`, control-plane package,
  dev operator fixture, private socket, or PR 24P implementation exists.
- v011 remains `(issuer,subject,lifecycle)` with one ACTIVE binding; v015 B1
  remains the authoritative exact-subject/reject-revoked-only behavior.

## Exactly changed files and new proposal subsections

**Edited**

```text
docs/pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md
docs/pr-artifacts/pr-24p/PR24P_STOP_AND_DEVIATION_REPORT.md
docs/pr-artifacts/pr-24p/PR24P_OPERATOR_AUTHORIZATION_CONTRACT.md
docs/pr-artifacts/pr-24p/PR24P_PRIVILEGE_AND_ISOLATION_REPORT.md
docs/pr-artifacts/pr-24p/PR24P_GENUINE_TOKEN_AND_RUNTIME_COMPROMISE_ACCEPTANCE.md
```

**Created**

```text
docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md
docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_E_DEVELOPMENT_BOOTSTRAP_REVIEW_REPORT.md
```

Decision-record changes: rev 4 header/§0 E row; Field 5 production prohibition
retained with the exact §5B exception; new §5B (5B.1–5B.8); Field 1/11/12
cross-references; §3 separate-approval note; §8A development-profile table; §9
rev-4 label and four E approval lines; §11 gate/consequence text.

No file outside `docs/pr-artifacts/pr-24p/` changed.

## Field 5 old/new prohibition and dev-only exception

**Old sentence removed:**

> It is not a runtime self-grant, not an environment-variable bootstrap, not a dev initializer, and not derived from root.

**New production rule:** it is not a runtime self-grant, not an
environment-variable source of authority, and not derived from root. In
production it is never installed by a development initializer or environment
flag; it requires the separately approved owner-controlled human installation
ceremony.

**New narrow exception:** only the explicitly opt-in, canonical-MTMF-development,
one-shot §5B fixture may create or verify exactly one dedicated non-root
`mtmf-dev-operator` and its exact approved SYSTEM
`urn:mtmf:iam:roles:system:application-administrator` assignment under owner
installation authority, with immutable
`dev-fixture:mtmf:pr24p:system-operator:v1` provenance and fail-closed
reconciliation. It is **NOT APPROVED** until the human explicitly approves it
with Field 5; it cannot be generalized to production or ordinary runtime.

## E-I01–E-I08 invariant-by-invariant documentation verification

| Invariant | Document location | Result |
| --- | --- | --- |
| E-I01 development-only activation; exact `development`/`mtmf`/issuer; `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED` default false, exact true/false, not authority | §5B.1; profile; §8A | Documented, not implemented |
| E-I02 dedicated `mtmf-dev-operator`, distinct from `mtmf-admin` and ordinary user; exact SYSTEM Role; no Tenant/root; actual verified `sub` | §5B.2; profile | Documented, not implemented |
| E-I03 create/verify through existing provisioner; no default/reset/impersonation; standard signed user flow remains | §5B.2; profile | Documented, not implemented |
| E-I04 short-lived migrator/`SET ROLE mtmf_owner` installer; fixed provenance label; UUIDv5 names; append-only event; no self-grant | §5B.3; profile | Documented, not implemented |
| E-I05 idempotent verify-only, no regrant/repair, partial/ambiguous STOP, explicit destructive reset only | §5B.5 (D01–D20); profile | Documented, not implemented |
| E-I06 future startup order 0–8; standard `up` unchanged without opt-in; `--migrations-only` must not install fixture | §5B.4; profile | Documented, not implemented |
| E-I07 distinct non-root UIDs, real `SO_PEERCRED`, separate sockets, restricted mounts, five control EXECUTEs, runtime 78, MTMF-only project | §5B.6; profile | Documented, not implemented |
| E-I08 production prohibition before privilege, no fallback issuer, human ceremony still required, residual host trust | §5B.7; profile | Documented, not implemented |

D01–D20 appear in §5B.5 and the profile; E01–E20 appear in §5B.8 and the profile.

## E01–E20 future acceptance matrix status (all NOT EXECUTED)

| ID | Status |
| --- | --- |
| E01 | NOT EXECUTED |
| E02 | NOT EXECUTED |
| E03 | NOT EXECUTED |
| E04 | NOT EXECUTED |
| E05 | NOT EXECUTED |
| E06 | NOT EXECUTED |
| E07 | NOT EXECUTED |
| E08 | NOT EXECUTED |
| E09 | NOT EXECUTED |
| E10 | NOT EXECUTED |
| E11 | NOT EXECUTED |
| E12 | NOT EXECUTED |
| E13 | NOT EXECUTED |
| E14 | NOT EXECUTED |
| E15 | NOT EXECUTED |
| E16 | NOT EXECUTED |
| E17 | NOT EXECUTED |
| E18 | NOT EXECUTED |
| E19 | NOT EXECUTED |
| E20 | NOT EXECUTED |

Future acceptance requires real PostgreSQL, genuine runtime/control credentials,
actual rootless Podman UID/mount separation, and genuine signed local Keycloak
user tokens. No mock, fabricated JWT, or same-UID/chmod check counts.

## Documentation checks and exact commands/results

| Command | Result |
| --- | --- |
| `git fetch origin` | completed |
| `git switch dev/pr24p-part-deux` | branch checked out |
| `git status --porcelain` | clean before edits |
| `git rev-parse HEAD` / `origin/main` / `merge-base` | all `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd` |
| `git diff --name-status origin/main...HEAD` | PR 24P docs only |
| `git log -6 --oneline` | rev 3 merge + Amendment A–D commits |
| `git diff --check` | clean |
| §7 signature count | **5** (`control_entitlement_grant`, `_revoke`, `_get`, `control_operator_authorization_snapshot`, `control_pre_tenant_admission_read`) |
| `rg '^## 5B\\.'` | exactly one §5B, between §5A.7 and §6 |
| D01–D20 row count / E01–E20 row count | 20 / 20 |
| Markdown fence/link checker over PR 24P artifacts | balanced fences; relative links resolve |
| obsolete `control_pre_tenant_entitlement_read` | only explicitly superseded/historical text; no active proposal |
| entitlement-expiry claim | none; only token expiry and the no-expiry prohibition remain |
| approval ticks (`☑`/`☒`/`[x]`) | none |

Prior Phase 0 baseline gates (`--qa` 2490 / 90.30%, `--sec` 0 findings, `--rust`
PASS, `--integration` 646 passed / 94 skipped, role verification PASS) are
historical evidence for the unimplemented base. They are **not** Amendment E
acceptance, and no gate was re-run for this docs-only change.

## Forbidden implementation/privilege/secret proof

- No `.py`, `.rs`, `.sql`, migration, Compose/YAML, Dockerfile, script, test,
  environment template, certificate, or credential changed.
- No `mtmf-dev-stack.py up`, initializer, role provisioning (non-`--verify`),
  migration, Keycloak Admin REST mutation, container lifecycle, database
  mutation, or benchmark was run.
- No `mtmf_control_exec` role, `system_operator_assignment` table, control
  socket, container, token, secret, or grant was created.
- `mtmf_runtime` allowlist remains 78; no production doc was changed.
- The host-idle benchmarking opportunity was recorded but **no benchmark or
  performance/load/stress test was executed**.

## Human-only unresolved §8 fields and §9 approvals

The original 13 §8 host-value blanks remain blank. §8A additionally leaves
UNRESOLVED:

- dev operator password-file path/ownership/mount/permissions;
- admin/provisioner/initializer/control/runtime UID/GID and user-namespace map;
- operator/admission socket paths/owners/modes;
- control DB secret path/ownership/rotation owner/network attachment;
- human-approved fixture decision ID/provenance reference.

§9 keeps every existing question and adds four unanswered E questions:
Field 5 + §5B verbatim; dedicated fixture/Role/provenance/no-regrant; §8 dev
values; production auto-bootstrap forbidden independently. No `YES` was set.
A named human decision ID, date, approving party, exact text/evidence, and
conditions are still required.

## Terminal status and next permitted action

**`AMENDMENT_E_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`.**

`STOP-P24P-TOPOLOGY` remains active; PR 24P implementation is NOT STARTED; the
roadmap is not marked DONE; PR 22B/PR 24 remain blocked. The next permitted step
is independent review of the proposed §5B/§8A values followed by a separately
recorded human approval or requested amendments. No privileged execution may
begin before that gate.
