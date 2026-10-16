# PR22_INTEGRATION_ACCEPTANCE

**PR:** roadmap PR 22
**Status:** entitlement foundation integration acceptance **PASS**; composite
feature acceptance **NOT RUN (BLOCKED)**.

## 1. PostgreSQL topology

| Item | Value |
| --- | --- |
| PostgreSQL | 18 (`docker.io/library/postgres:18`, MTMF-owned `mtmf` project, host port `25432`) |
| Administrator | provisioning/verification (owner-of-record bootstrap) |
| `mtmf_migrator` | runs Alembic migrations with `SET ROLE mtmf_owner`; authenticated contract verified |
| `mtmf_runtime` | restricted login; subject of every privilege-denial test |
| Migration head | `0014_pr22_onboarding_entitlement` |
| Runtime allowlist | unchanged **78** signatures |

## 2. Migration and privilege postflight

- `test_i01_fresh_migration_runs_mandatory_verifier` — fresh migration to
  `0014`, mandatory post-upgrade verifier passes on a fresh migrator session,
  runtime has no table privilege.
- `test_i02_already_head_rerun_reverifies_without_drift` — repeated
  `upgrade_to_head()` is a no-op with an identical privilege snapshot.
- `test_i03`/`test_i04` — contaminated grant fails postflight and recovers after
  remediation; Alembic head remains `0014` with no rollback claim.
- `test_bnd02_no_repository_crud_function_family` — the exact function manifest
  now includes the seven v014 functions.
- `test_p22_17_migration_postflight_and_runtime_allowlist_unchanged` — the
  runtime EXECUTE count remains exactly 78.

## 3. Restricted-runtime denial evidence

| Function | Runtime result |
| --- | --- |
| `application_onboarding_entitlement_grant` | `InsufficientPrivilege` |
| `application_onboarding_entitlement_revoke` | `InsufficientPrivilege` |
| `application_onboarding_entitlement_get` | `InsufficientPrivilege` |
| `application_onboarding_entitlement_find_by_application` | `InsufficientPrivilege` |
| `application_onboarding_entitlement_event_find_by_entitlement` | `InsufficientPrivilege` |
| direct `SELECT` on the entitlement tables | `InsufficientPrivilege` |

## 4. Executed foundation acceptance

10 real-PostgreSQL tests in
`tests/integration/postgres/test_pr22_onboarding_entitlement.py` executed
successfully: P22-01, P22-02, P22-03, P22-04, P22-05 (×2), P22-06, P22-16,
P22-17, P22-18. They prove the operator-only grant/revoke/read semantics,
single-ACTIVE uniqueness, terminal revocation, fresh-UUID replacement,
immutable provenance, append-only history, explicit positive quota, and runtime
denial — all against the real restricted runtime login.

## 5. NOT RUN (blocked)

P22-06 (quota exhaustion at provision), P22-07..P22-15 (concurrency, replay,
fault-injection rollback, composite participant, existing-Tenant/second-
Application, SYSTEM/root, PR 13 lifecycle under composite). These require the
BLOCKED first-Tenant composite (`PR22_STOP_REPORT.md`). No fake or partial
commit path was exercised.

## 6. Canonical gate results

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 2472 passed, 3 warnings, 90.32% coverage |
| Security | `./build.sh --sec` | PASS — Bandit no issues; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | PASS |
| Integration | `./build.sh --integration` | PASS — 603 passed, 90 skipped |

Environment: WSL2, Podman 4.9.3, Python 3.14.7 (uv), PostgreSQL 18, migration
head `0014`. No failures.
