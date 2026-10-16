# PR22_BASELINE_RECONCILIATION

**PR:** roadmap PR 22 — Transactional Tenant Provisioning and Subscription Foundation
**Type:** additive persistence foundation (partial; first-Tenant composite BLOCKED)
**Status:** PHASE 0 COMPLETE — baseline verified; privilege preflight performed; composite blocked.

## 1. Repository state

| Item | Value |
| --- | --- |
| Branch | `dev/tenant-provisioning` |
| Working tree at start | clean |
| `git rev-parse HEAD` | `abba785f74c684d45e302d870a611abe10e1aa04` (fresh `main` after PR 21 merge) |
| `git rev-parse origin/main` | `abba785f74c684d45e302d870a611abe10e1aa04` |
| Migration head before | `0013_security_mutation_audit_partitioning` |
| Migration head after | `0014_pr22_onboarding_entitlement` |
| Push | none (not authorized) |

## 2. Authoritative documents read

`AGENTS.md`, `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`, `docs/ROADMAP_V01.md`
(PRs 13, 14, 21–26), `docs/ONBOARDING_ARCHITECTURE.md`,
`docs/ONBOARDING_HTTP_CONTRACT.md`, `docs/SECURITY_MODEL.md`,
`docs/AUTHORIZATION.md`, and all `docs/pr-artifacts/pr-21/PR21_AMENDMENT*.md`
reports including `PR21_AMENDMENT03_HUMAN_APPROVAL.md`.

## 3. Reused seams (verified paths)

| Concern | Path |
| --- | --- |
| SPI / provider | `mtmf_core/persistence/spi.py`, `persistence/postgres/spi.py` |
| UnitOfWork | `persistence/unit_of_work.py`, `persistence/postgres/unit_of_work.py` |
| Repository protocols | `persistence/repositories.py` |
| PostgreSQL repositories | `persistence/postgres/repositories.py` |
| Domain mappers | `persistence/postgres/mapping.py` |
| PR 13 registry schema/functions | `persistence/postgres/sql/v010/01..04` |
| PR 14 credential bindings | `persistence/postgres/sql/v011/01..04` |
| PR 19C audit/provenance | `persistence/postgres/sql/v012/01..06`, `application/mutation_provenance.py` |
| Runtime privilege allowlist | `persistence/postgres/roles.py` `expected_runtime_signatures()` (78) |
| Migration head constant | `persistence/postgres/migration.py` `HEAD_REVISION` |
| Packaged SQL discovery | `persistence/postgres/resources.py` |
| Integration harness | `tests/integration/postgres/conftest.py`, `helpers.py` |

No duplicate SPI, repository, authorization, or SQL-execution layer was
introduced.

## 4. Existing vs missing classification

| Component | State |
| --- | --- |
| Tenant/Application/registration/subscription domain + guards | DONE+VERIFIED (PR 13) |
| PR 13 operator-only registry mutation (never `mtmf_runtime`) | DONE+VERIFIED |
| PR 14 verified `(issuer, client_id) → Application` binding | DONE+VERIFIED |
| PR 19C audited management mutation pattern | DONE+VERIFIED |
| Ordinary Tenant-bound `Authorizer`; no global/SYSTEM operator target | DONE+VERIFIED (no global target support) |
| Onboarding entitlement persistence | **NOT STARTED → implemented as isolated operator primitives** |
| Quota/replay ledger tied to a Tenant-committing composite | **NOT STARTED** |
| First-Tenant atomic composite (Tenant + Identity/Principal/steward + initial pair) | **BLOCKED (STOP-P22-B)** |
| SYSTEM operator sign-in / global-target authorization / privileged execution adapter | **NOT PRESENT (PR 21 operator prerequisite)** |

## 5. Privilege preflight (grounded)

- PR 13 mutations (`application_add`, `application_save`,
  `application_tenant_registration_add/save`,
  `tenant_application_subscription_add/save`) are owner-owned `SECURITY INVOKER`
  with fixed empty `search_path` and are **not** granted to `mtmf_runtime`.
- The runtime allowlist is `expected_runtime_signatures()` (78 signatures); the
  mandatory post-upgrade verifier compares the effective runtime EXECUTE set to
  exactly that manifest.
- The service connects as `mtmf_runtime`. There is **no** operator execution
  adapter and **no** global/Tenant-independent target authorization.
- Therefore a first-Tenant composite could only be runtime-callable by making it
  `SECURITY DEFINER` and granting it to `mtmf_runtime` — a privileged mutation
  capability the plan forbids (STOP-P22-A) — or by leaving it operator-only with
  no production caller (no adapter exists). **STOP-P22-B applies.**

## 6. Baseline gate evidence (pre-change, base `abba785`)

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — 2462 passed, 90.36% coverage |
| `./build.sh --sec` | PASS — 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — 593 passed, 90 skipped |

## 7. Outcome

The safely isolated onboarding-entitlement foundation was implemented
(revision `0014`): per-Application `ACTIVE`/`REVOKED` entitlement with immutable
grant provenance, terminal revocation, single-ACTIVE uniqueness, append-only
history, explicit positive quota, and operator-only `SECURITY INVOKER` functions
never granted to `mtmf_runtime`. The first-Tenant composite, quota/replay
consumption inside a Tenant-committing transaction, and the runtime admission
read surface are **BLOCKED** pending the explicit architectural decision
documented in `PR22_STOP_REPORT.md`.
