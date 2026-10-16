# PR22A_INTEGRATION_ACCEPTANCE_REPORT

**Roadmap identifier:** PR 22A — Entitlement persistence foundation
**Status:** PASS.

## 1. Topology

| Item | Value |
| --- | --- |
| PostgreSQL | 18.6 (`docker.io/library/postgres:18`, MTMF-owned `mtmf` project, `127.0.0.1:25432`) |
| Administrator | provisioning/ownership bootstrap |
| `mtmf_migrator` | Alembic migrations under `SET ROLE mtmf_owner`; authenticated contract verified; mandatory post-upgrade verifier |
| `mtmf_runtime` | restricted login; subject of every privilege-denial test |
| Migration head | `0014_pr22_onboarding_entitlement` |
| Runtime allowlist | unchanged **78** signatures |

The database was restarted during this pass; WAL crash recovery completed and
`PostgreSQL 18.6` became ready. No data or schema migration occurred as part of
that recovery; the integration fixtures reset/migrate per test.

## 2. Executed entitlement tests (real PostgreSQL)

`tests/integration/postgres/test_pr22_onboarding_entitlement.py` — **13 passed**:

- P22-01 grant with explicit quota, single ACTIVE, immutable GRANTED event.
- P22-02 runtime cannot grant.
- P22-03 revoke terminal; replay false; direct reactivation denied; provenance immutable.
- P22-04 fresh-UUID regrant after revoke with independent history.
- P22-05 unknown/inactive Application denied.
- P22-06 nonpositive quota denied; table CHECK rejects bypass.
- P22-16 runtime cannot read/revoke/touch tables.
- P22-17 runtime allowlist remains exactly 78.
- P22-18 append-only history.
- **PR22A concurrency:** `test_p22a_concurrent_duplicate_grant_has_one_active`.
- **PR22A no-linkage:** `test_p22a_entitlement_functions_create_no_tenant_or_linkage`.
- **PR22A nil/unknown FK:** `test_p22a_nil_application_and_operator_uuids_are_denied`.

Only the operator/migrator connection exercises the operator-only functions; the
restricted `mtmf_runtime` login is used exclusively for denial assertions
(never simulated with `SET ROLE`).

## 3. Migration / privilege postflight

- Fresh migration to `0014` runs the mandatory post-upgrade verifier on a fresh
  authenticated migrator session; runtime has no table privilege.
- Repeated `upgrade_to_head()` is a no-op with an identical privilege snapshot.
- Contaminated-grant failure and recovery behave as before.
- Function inventory includes the seven v014 functions; runtime EXECUTE count is
  exactly 78.

## 4. Gates (final reported run)

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — 2472 passed, 3 warnings, 90.32% coverage |
| `./build.sh --sec` | PASS — Bandit 0 findings; Semgrep 297 rules / 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — **606 passed**, 90 skipped |
| `git diff --check` | clean |
| `git fsck --full` | exit 0; no error/broken/missing (32 dangling only) |

## 5. NOT RUN (out of PR 22A scope)

Quota exhaustion/consumption, replay/idempotency, atomic first-Tenant creation,
Identity/Principal/stewardship composition, and operator/pre-Tenant privileged
execution (PR 22B / PR 23 / PR 24P). No partial Tenant-commit path exists.
