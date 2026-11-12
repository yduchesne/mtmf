# PR24P_BASELINE_AND_SCOPE_RECONCILIATION

**PR:** roadmap **PR 24P**
**Status:** `PR24P_BLOCKED_TOPOLOGY_APPROVAL` — Phase 0 (documentation/evidence only)
**Baseline commit reconciled:** `8712418a3d2de212791ae75a6235d3e00fced450`
**Branch observed:** `dev/pr24-pre-tenant` (clean, equals `origin/main`)
**Date of reconciliation:** 2026-11-12

This report records the exact Phase-0 baseline checks the execution plan
requires **before** any implementation, plus the scope boundary that remains
unimplemented. It is evidence, not approval.

---

## 1. Repository baseline

| Check | Observed | Required by plan | Result |
| --- | --- | --- | --- |
| `git rev-parse HEAD` | `8712418a3d2de212791ae75a6235d3e00fced450` | plan reference `8712418…` | **MATCH** |
| `git rev-parse origin/main` | `8712418a3d2de212791ae75a6235d3e00fced450` | equals HEAD | **MATCH** |
| `git status --porcelain` | clean before this artifact directory was created; only `?? docs/pr-artifacts/pr-24p/` afterwards | clean baseline | **MATCH** |
| PR 23 merged | `8712418 Merge pull request #75 from yduchesne/dev/pr23-verified-subject-stewardship` | merged | **MATCH** |
| PR 23 F1/F2 fixup present | `a68177e fix(pr23): tighten fresh-Tenant graph and canonical root UUID checks` (touches `v015/02_onboarding_subject_and_steward_functions.sql` + 356 test lines) | present on `main` | **MATCH** |
| Alembic head | `0015` (`select version_num from mtmf.alembic_version`) | `0015` | **MATCH** |
| Existing PR 24P implementation | absent — repository-wide grep for `system_operator`, `control_plane`, `authorize_global`, `mtmf_control_exec`, `operator_contracts` returns no source hit | no new operator implementation | **MATCH** |
| `MT049`/`MT050`/`MT051` SQLSTATE allocation | unused; the SQL tree currently uses `MT001`–`MT048` only | reserved-and-free check | **MATCH** (no `STOP-00`) |

Commands used:

```bash
git fetch origin
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain
git log --oneline -8
git show --stat --oneline a68177e
```

## 2. PostgreSQL role topology (real local MTMF database)

Provisioned with the canonical script (`scripts/mtmf-provision-roles.py`,
MTMF-owned Compose project `mtmf`, host `127.0.0.1:25432/mtmf`). Live catalog:

| Role | LOGIN | SUPER | CREATEROLE | CREATEDB | BYPASSRLS | Memberships |
| --- | --- | --- | --- | --- | --- | --- |
| `mtmf` (admin) | yes | yes | yes | yes | yes | — |
| `mtmf_owner` | no | no | no | no | no | — |
| `mtmf_migrator` | yes | no | no | no | no | member of `mtmf_owner` |
| `mtmf_runtime` | yes | no | no | no | no | — |
| `mtmf_control_exec` | **does not exist** | — | — | — | — | — |

`mtmf_runtime` effective EXECUTE count on `mtmf.*` functions: **78** (matches
`expected_runtime_signatures()` and the plan's baseline). No direct
table/sequence privileges, no owner/migrator membership.

v014 (PR 22A) functions present, owner-only, not runtime-granted:
`application_onboarding_entitlement_grant`,
`..._revoke`, `..._get`, `..._find_by_application`,
`..._event_find_by_entitlement`.

v015 (PR 23) participants present, owner-only, `SECURITY INVOKER`, not
runtime-granted: `onboarding_subject_prepare`, `onboarding_initial_steward_attach`.

## 3. Baseline gate results (same environment, before any PR 24P code)

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **2490 passed**, coverage **90.30%** (≥85% gate) — matches the PR 23 recorded baseline |
| Security | `./build.sh --sec` | **0 findings** (Bandit: no issues; Semgrep: 297 rules / 238 files / 0 findings) |
| Rust/native | `./build.sh --rust` | **PASS** (fmt, clippy `-D warnings`, tests, `maturin develop`, installed-native probe, boundary/differential/compiled-policy tests, clean-wheel verification, benchmark smoke) |
| PostgreSQL integration | `./build.sh --integration` | **646 passed, 94 skipped** — matches the PR 23 recorded baseline |
| Role verification | `uv run --no-sync python scripts/mtmf-provision-roles.py --verify` | **PASS** — "verified runtime privileges … mtmf_runtime is restricted" |

Environment notes (for reproducibility, no repository change):

- The local MTMF database was started with `scripts/mtmf-postgres.py up`
  (project `mtmf`, published host port `25432`, per the MTMF prefix-`2`
  convention). No other project's resources were touched.
- `.env.example` is documentation, not a strictly shell-sourceable file: one
  comment continuation line (`Tenant: …`) produces a harmless
  `Tenant: command not found` warning when sourced. Variables were exported
  before each command; no `.env` file was created or committed.
- Integration/live suites that require the Keycloak fixture were skipped in
  `--integration` (94 skips), exactly as at the PR 23 baseline. No live
  Keycloak was started in Phase 0, so PR 24P genuine-token acceptance is
  **NOT EXECUTED**.

## 4. Plan §2 "actual main facts" re-verification

| Plan claim | Verified at `8712418` |
| --- | --- |
| `Authorizer.authorize` is Tenant-bound; cross-Tenant only via TenantManagementGroup | **YES** — `authorization/authorizer.py:79`, `authorization/context.py:65-102` |
| `EffectiveRoleResolver` reads Tenant-bound assignments; `Role` has no scope field | **YES** — `application/effective_roles.py:125` |
| PR 21: two SYSTEM Roles; 11/2 grants; 7 additive Tenant Admin grants; admission markers zero-grant | **YES** — `docs/pr-artifacts/pr-21/PR21_AMENDMENT02_ACTION_MANIFEST.md`; `docs/ONBOARDING_ARCHITECTURE.md` §19.1–19.2 |
| PR 13 registry mutations privileged | **YES** — `sql/v010/` |
| PR 14 bindings owner-only; runtime bounded reads | **YES** — `sql/v011/` |
| PR 19C `VerifiedMutationProvenance` + `v012` audit | **YES** — `application/mutation_provenance.py:139` |
| PR 22A v014 signatures | **YES** — matches live catalog |
| PR 23 v015 participants owner-only `SECURITY INVOKER` | **YES** — `sql/v015/03_…_grants.sql` |
| Runtime allowlist 78 | **YES** — code manifest and live count both 78 |
| No public route added by PR 24P | **YES** — `mtmf-service` public routes untouched |
| Rust algorithms/policies unchanged | **YES** — no Rust change in this phase |
| Dev Keycloak profile `mtmf-dev` / `mtmf-evidence-same-client` / audience `mtmf-same-client-api` | **YES** — `dev/keycloak/expected-client-policy.json` |

## 5. Observations (recorded, not fixed in Phase 0)

1. **Documentation-only inconsistency in `roles.py`.** The
   `expected_runtime_signatures()` docstring says "the **44** repository
   read/write functions", but the actual `_REPOSITORY_FUNCTION_ARGUMENTS` map
   has **43** entries; the live total is 78, which matches the plan and the
   verifier. This is a pre-existing docstring wording defect with no runtime
   or security effect. Classification: **pre-existing documentation defect**
   (not introduced by PR 24P). It was left unchanged because Phase 0 is
   docs-only and must not modify production modules; PR 24P implementation
   may correct it under the approved scope.
2. **No isolation topology exists yet.** `compose.yaml` defines only
   PostgreSQL; `Dockerfile.service` builds the public HTTP service; there is no
   control-plane package, UID, socket, secret mount, or network attachment.
   Consequently the compromised-runtime negative controls (ISO-01…ISO-08)
   **cannot** be demonstrated today. This is exactly the condition the plan
   says must trigger `STOP-P24P-TOPOLOGY`, not a dev-only exception.
3. **The dev Keycloak fixture was not started in Phase 0**, so no genuine
   operator token class was exercised. PR 24P unit/live evidence remains
   pending approval.

## 6. Scope reconciliation — what Phase 0 did and did not do

**Did (documentation/evidence only):**

- fetched and verified the baseline SHA and history;
- provisioned and verified the **local development** PostgreSQL topology
  (MTMF-owned project) and recorded the real role/revision/allowlist state;
- ran the read-only baseline gates `--qa`, `--sec`, `--rust`, `--integration`,
  and `mtmf-provision-roles.py --verify`;
- created `docs/pr-artifacts/pr-24p/` with the decision request, this
  reconciliation, the STOP report, and clearly labelled not-executed
  placeholders for the remaining required artifacts.

**Did not (and must not before approval):**

- no migration `0016`, no `sql/v016/` resources;
- no `system_operator_assignment`, audit, replay, or control wrapper tables;
- no `mtmf_control_exec` role, grant, or secret;
- no `Authorizer` change, no `authorize_global_system`, no operator/pre-Tenant
  contract or service;
- no `mtmf-control-plane` package, socket, listener, or deployment;
- no change to `mtmf_runtime` (still exactly 78 EXECUTE signatures), v014,
  v015, `0006`/`0012`, Keycloak baselines, public DTOs, or `mtmf-service`
  routes;
- no change to `docs/SECURITY_MODEL.md`, `docs/AUTHORIZATION.md`,
  `docs/ONBOARDING_ARCHITECTURE.md`, `docs/ONBOARDING_HTTP_CONTRACT.md`,
  `docs/DATABASE.md`, or `docs/ROADMAP_V01.md`.

**Roadmap status:** PR 24P remains `PLANNED; STOP-P24P-TOPOLOGY` in
`docs/ROADMAP_V01.md`; nothing in this phase changes it.

## 7. Reconciliation verdict

Baseline is **exactly** the plan's reference. No `STOP-00` condition fired.
`STOP-P24P-TOPOLOGY` remains the only blocker, and it is a **human decision**,
not a coding task. Required next action: a recorded decision covering all
twelve topology fields and the frozen protocol/signatures in
[PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md](PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md).
