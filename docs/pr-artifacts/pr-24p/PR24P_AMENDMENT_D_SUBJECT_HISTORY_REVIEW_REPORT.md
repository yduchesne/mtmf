# PR24P_AMENDMENT_D_SUBJECT_HISTORY_REVIEW_REPORT

**PR:** roadmap **PR 24P** — Operator and Pre-Tenant Privileged Execution Prerequisite
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Document type:** documentation-only Amendment D review/fixup evidence
**Final state:** **`AMENDMENT_D_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`**
**STOP status:** `STOP-P24P-TOPOLOGY` remains **ACTIVE**

> This is an amendment-evidence report, **not** a test-acceptance report for the
> proposed SQL. No implementation, migration, role, grant, socket, or deployment
> resource exists. No unit/integration/genuine-token/deployed-isolation feature
> test was executed for Amendment D.

---

## 1. Baseline and change inventory

| Item | Value |
| --- | --- |
| `origin/main` reconciled | `8712418a3d2de212791ae75a6235d3e00fced450` (PR 23 merged) |
| Merge base | `8712418a3d2de212791ae75a6235d3e00fced450` |
| Branch | `dev/pr24-pre-tenant` |
| Branch tip before Amendment D | `b8dd4a03dd56a6decbd24c8cc0e0b8092922e1fc` (`docs(pr24p): address independent topology review findings`) |
| Working tree before edits | clean |
| Amendment D commit | `2406407` (`docs(pr24p): freeze revoked-subject-history admission read contract`) |
| Source files inspected | `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`; `docs/ROADMAP_V01.md` §PR 24P; the PR 24P decision record, STOP report and pre-Tenant placeholder; `application/pre_tenant_subject.py`; `persistence/postgres/repositories.py`; `sql/v011/01`–`02`; `sql/v015/02`; `sql/v014/01`–`02`; `docs/ONBOARDING_ARCHITECTURE.md` §19; `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md` |

**Changed files (exact):**

```text
docs/pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md
docs/pr-artifacts/pr-24p/PR24P_STOP_AND_DEVIATION_REPORT.md
docs/pr-artifacts/pr-24p/PR24P_PRE_TENANT_ADMISSION_CONTRACT.md
docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_D_SUBJECT_HISTORY_REVIEW_REPORT.md  # this file
```

No other tracked file changed. No production code, SQL, migration, test,
roadmap, or normative document changed.

## 2. Passages changed and old/new signature

### 2.1 Decision record

| Section | Change |
| --- | --- |
| Header | Version/status changed to `2026-11-12 (rev 3: independent-review Findings A–D) · DESIGN PROPOSED`; `PR24P_BLOCKED_TOPOLOGY_APPROVAL` and `STOP-P24P-TOPOLOGY ACTIVE` retained. |
| §0 | Added Finding D row; summary now says **four unchanged operator signatures plus one replaced fifth**, and that §5A.7 is additive/unapproved. |
| §3 | Required decision material now includes the §5A.7 / fifth-signature verbatim approval. |
| §5A.4 | `NO_ENTITLEMENT` no longer claims expiration; now means no ACTIVE entitlement or exhausted ACTIVE entitlement. Added that `REVOKED_ONLY` is internal and maps to opaque `CONFLICT`. Success/error literals unchanged. |
| §5A.5 | Replaced conditional entitlement-only read with the unconditional post-PR-23 `control_pre_tenant_admission_read(application_id, issuer, subject)` flow and the full R01–R10 mapping. |
| §5A.7 (new) | Freezes the exact fifth signature, internal JSON result, H01–H06 historical precedence, active-actor/root validation, entitlement/exhaustion rules, no-expiration invariant, read semantics, privacy constraints, and planned SH01–SH20 acceptance obligations (not executed). |
| §7 | Replaced exactly one signature; prose now distinguishes the four unchanged operator signatures from the fifth pre-Tenant historical read and restates that it is never operator authorization or ALLOW. Other four signatures and SQLSTATEs unchanged. |
| §8 | All deployment values remain blank (including ingress UID and admission socket). |
| §9 | Version reference updated to rev 3; added the Amendment D §5A.7/fifth-signature approval line. All 12 fields remain unapproved `YES / NO`. |
| §11 | Gate condition now includes §5A.7 / revised fifth signature; findings A–D must be approved as frozen text. |
| Field 3, Field 7 | Added cross-references to §5A.7 (no other rewrite of those fields). |

**Old proposed signature (removed from active proposal):**

```sql
mtmf.control_pre_tenant_entitlement_read(
  application_id_value uuid
) RETURNS jsonb
```

**New proposed signature (fifth §7 entrypoint):**

```sql
mtmf.control_pre_tenant_admission_read(
  application_id_value uuid,
  issuer_value text,
  subject_value text
) RETURNS jsonb
```

The old name now appears only once, explicitly labelled `superseded` in
§5A.7.1; it is not an active entrypoint. §7 contains exactly **five** function
signatures.

### 2.2 STOP report

- Amendment history heading changed to Findings A–D; added the Finding D row
  (source-grounded mismatch, exact replacement, ACTIVE + older REVOKED remains
  ACTIVE, no-expiry correction, documentation-only status).
- "Preserved unchanged" now distinguishes four unchanged operator signatures
  from the replaced fifth.
- Smallest-decision checklist now includes §5A.7 and the revised fifth signature.
- Zero-unapproved-changes section now lists the four amendment files, states
  that this amendment touched only PR 24P documentation, and explicitly records
  that no unit/integration/genuine-token/deployed-isolation/feature test
  executed or passed.

### 2.3 Pre-Tenant placeholder

- Replaced `mtmf.control_pre_tenant_entitlement_read` with
  `mtmf.control_pre_tenant_admission_read(application_id, issuer, subject)` and
  cited §5A.7.
- Status remains **`NOT EXECUTED — STOP-P24P-TOPOLOGY`**.

## 3. H01–H06 and R01–R10 disposition

The decision record now states all precedence and mapping cases; there are no
unexplained gaps.

| Case | Frozen outcome |
| --- | --- |
| H01 (>1 ACTIVE) | `CONFLICT`; no entitlement read; never choose a row. |
| H02 (1 ACTIVE, eligible actor) | `ACTIVE`; no entitlement read. |
| H03 (1 ACTIVE but identity/principal invalid/root/LOCAL) | `CONFLICT`. |
| H04 (0 ACTIVE, ≥1 REVOKED) | `REVOKED_ONLY`; no entitlement read. |
| H05 (0 ACTIVE, 0 REVOKED) | `NEVER_SEEN`; entitlement read allowed. |
| H06 (unexpected lifecycle/integrity) | fail closed; no candidate. |
| R01 | `CANDIDATE` with entitlement UUID. |
| R02 | `NO_ENTITLEMENT`. |
| R03 | `EXISTING_SUBJECT`. |
| R04 | `EXISTING_SUBJECT` (ACTIVE appeared after PR 23 read). |
| R05/R06 | opaque `CONFLICT`. |
| R07 | `CONFLICT` (existing observed, history says never seen). |
| R08 | `UNAVAILABLE` (malformed/incompatible internal result). |
| R09 | no privileged read; existing typed authentication error. |
| R10 | opaque `UNAVAILABLE` (inactive/missing Application, root inconsistency, infrastructure). |

Critical precedence is explicit: an eligible ACTIVE binding plus older REVOKED
rows is `ACTIVE`, matching PR 23 B1. Revoked-only subject history can never be a
candidate. REVOKED entitlement history is independent and is not a subject
conflict.

## 4. Proof that shipped behavior was not modified

Source inspection confirmed:

- `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/02_onboarding_subject_and_steward_functions.sql` still has B1 order: `active_count > 1 → MT048`; `active_count = 1 → validate/reuse` (including with revoked history); `active_count = 0, revoked_count > 0 → MT048`; no history → create.
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v014/01_onboarding_entitlement_schema.sql` still has `state IN (1,2)`, positive `quota_total`, bounded `quota_consumed`, one ACTIVE per Application, and **no expiration/valid-until column**.
- `packages/mtmf-core/src/mtmf_core/application/pre_tenant_subject.py` still treats no ACTIVE binding as an unbound candidate and never inspects revoked history; this amendment documents the missing privileged classification, it does not change that service.
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/roles.py` `expected_runtime_signatures()` still totals **78**; no grant list was edited.
- `git diff --name-only` shows no file under `packages/`, `tests/`, `scripts/`, `dev/`, migrations, or SQL.

## 5. Commands executed and results

| Command | Result |
| --- | --- |
| `git fetch origin` | completed; `origin/main = 8712418…` |
| `git switch dev/pr24-pre-tenant` | already on branch |
| `git status --short` | clean before edits |
| `git rev-parse HEAD` / `origin/main` / `merge-base` | `b8dd4a0…` / `8712418…` / `8712418…` |
| `git diff --name-status origin/main...HEAD` | only PR 24P documentation files added |
| `git log -5 --oneline` | two Phase 0 commits ahead of `main` |
| source inspections (`sed`/`rg`) of v011/v014/v015, PR 23 service/repository, roles manifest | confirmed the facts in §4 |
| `rg -n 'control_pre_tenant_entitlement_read' docs/pr-artifacts/pr-24p/` | one **active-proposal** hit, explicitly marked superseded in §5A.7.1; remaining hits are this evidence report's old/new-signature documentation |
| `rg -n 'control_pre_tenant_admission_read\|REVOKED_ONLY\|5A\\.7\|rev 3' …` | new contract present |
| `rg -n 'expired\|expiry\|expires_at\|valid_until' …` | no entitlement-expiry claim; remaining hits are token expiry and the no-expiry prohibition |
| `git diff --check` | clean |
| fence/link consistency script over `docs/pr-artifacts/pr-24p/*.md` | fences balanced, relative links resolve |
| exactly-five-signature count in §7 | 5 |

Prior baseline gates (`--qa` 2490 / 90.30%, `--sec` 0 findings, `--rust` PASS,
`--integration` 646 passed / 94 skipped, role verification PASS) were executed
in an earlier Phase 0 turn against the unimplemented base. They are **not**
Amendment D acceptance and do not prove SH01–SH20.

## 6. Remaining human decisions and unfilled values

Still required before any implementation:

- explicit human approval of all twelve topology fields;
- verbatim approval of §5, §5A, §5A.7, §6, §6A, §6B and the five §7 signatures;
- all deployment-specific values in §8 (operator admin UID, control UID/GID,
  runtime UID/GID, operator socket path/mode, ingress UID/GID, admission socket
  path/mode, control secret mount, Podman project/network, host platform,
  rotation owner) remain blank;
- a named decision ID, date, approving party, exact text/evidence, and
  conditions in §9.

The agent did not set any `YES` and did not select any deployment value.

## 7. Terminal state

**`AMENDMENT_D_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`.**

`STOP-P24P-TOPOLOGY` remains active. PR 24P remains `PLANNED; STOP-P24P-TOPOLOGY`
in `docs/ROADMAP_V01.md`. PR 22B and PR 24 remain blocked from privileged
execution. No code acceptance is claimed.
