# PR24P_SEED_0017_IMPLEMENTATION_AND_ACCEPTANCE_REPORT

**Status:** `SEED_0017_ACCEPTED — PR24P_IMPLEMENTATION_STILL_INCOMPLETE`
**PR:** roadmap **PR 24P**
**Branch:** `dev/pr24p-part-deux`
**Approved main:** `9f8190e8d053cae529632f0dff468d42637d2851`
**Implementation base:** `507faec85c2ea7eeace9b7c0353b21c8d7e89ea4`
**Gate A:** `MTMF-PR24P-GATE-A-2026-11-13-01`
**Gate B:** `MTMF-PR24P-GATE-B-2026-11-13-01`
**Gate C:** NOT EXECUTED

## Authorization

The project owner authorized one additive `0017` migration on the existing PR
24P branch, limited to the already-approved Application Administrator Role and
its 11 exact Permissions. This report does not claim full PR 24P acceptance,
operator login, Gate C, or the paused end-to-end implementation.

## Frozen seed installed

| Item | Value |
| --- | --- |
| Role | `urn:mtmf:iam:roles:system:application-administrator` |
| Name | `Application Administrator` |
| Description | `''` |
| Defining Tenant | `NULL` |
| Extension | `{}` |
| Protected marker | `mtmf.builtin_role` exact URN |
| PermissionSet | `ef895e22-cc8b-53db-a804-7ef11cffcb60` (`allow`, position 0) |
| Permissions | exactly 11 fixed IDs/URNs/positions 0–10 |
| Actions | exactly 11 corresponding canonical Action rows |

Permission IDs (positions 0–10): `25a2f2f4-f32d-5447-bf39-578b4b4c312c`,
`da26e3bd-b3cb-5232-9910-3bc5b7f7fdda`, `1ed11804-0a69-5a0f-89eb-3665b7c6cef4`,
`84ec050a-8732-51c5-9ca0-304e8347f642`, `62ce5487-bbb9-5c3b-ae91-d6fcd560a7bf`,
`ca253e75-2bb6-58c1-88db-02a191412018`, `49b322cf-6b12-5ec2-ae07-71aa541280c8`,
`ea1a042a-dc5a-5e5c-aab9-a19d995d2e58`, `909403b6-cb5c-5722-91f6-fac47e86fb15`,
`4a07317d-5c71-5118-9b95-899745a404f9`, `77915183-0f56-5329-8669-f1958d354cf1`.
The PermissionSet ID and all Permission IDs were independently checked against
the existing PR #38 UUIDv5 namespace convention.

## Changed files

```text
packages/mtmf-core/src/mtmf_core/persistence/postgres/migrations/versions/0017_application_administrator_seed.py
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v017/__init__.py
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v017/01_application_administrator_seed.sql
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v017/02_application_administrator_assertions.sql
packages/mtmf-core/src/mtmf_core/persistence/postgres/migration.py  # head 0017
tests/integration/postgres/test_pr24p_application_administrator_seed.py
tests/integration/postgres/test_postgres_builtin_policy.py
tests/integration/postgres/test_migrations.py
tests/integration/postgres/test_migration_privilege_lifecycle.py
tests/integration/postgres/test_postgres_runtime_security.py
tests/integration/postgres/test_runtime_privileges.py
tests/integration/postgres/test_pr19b_audit_partitioning.py
tests/integration/postgres/test_pr23_initial_stewardship.py
tests/integration/postgres/test_postgres_role_assignments.py
tests/integration/postgres/test_postgres_stewardship_concurrency.py
tests/integration/postgres/test_stored_functions.py
tests/unit/core/test_postgres_migration.py
docs/pr-artifacts/pr-24p/PR24P_IMPLEMENTATION_STOP_SEED_REPORT.md
docs/pr-artifacts/pr-24p/PR24P_SEED_0017_IMPLEMENTATION_AND_ACCEPTANCE_REPORT.md
```

`0016`, `sql/v001`–`v016`, `v006`/`v012`, roles.py, authorization model and
public/control packages were not modified by this seed fixup.

## Migration and real-DB acceptance

- Existing database at `0016` upgraded to `0017`; mandatory runtime postflight
  passed; second upgrade was a no-op at `0017`.
- Live seed check: one exact Role row, one marker, one ALLOW set, exactly 11
  Permissions, exactly 15 total Action rows (4 historical + 11 new).
- Fresh and incremental real-PostgreSQL paths: `--integration` 649 passed,
  94 skipped.
- Drift test deletes a seeded Permission and re-executes the seed SQL; `MT010`
  aborts and rollback restores the exact row.
- No assignment, Identity, Principal, Tenant or audit/replay row was created.
- `--verify`: runtime exactly 78 EXECUTEs, restricted.
- Separate control install then `--verify-control`: exactly five private
  EXECUTEs, no extra privilege.

## Gate results

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | 2502 passed, 87.77% coverage |
| `./build.sh --sec` | 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | 649 passed, 94 skipped |
| `scripts/mtmf-provision-roles.py --verify` | PASS (78 runtime signatures) |
| `scripts/mtmf-provision-roles.py --verify-control` | PASS (exactly five control EXECUTEs) |

The prior committed STOP report's 2,213 passed / 177 skipped and "final gates
not executed" statements are historical at their earlier SHA. Later runs at the
`0017` implementation content are recorded above; they are not retroactively
rewritten into the original stop evidence.

## Required test dispositions

- U01/U02/U03/U04/U05: exact seed structure, UUID derivation, persisted Role
  compiled-policy allow/deny and no-assignment assertions are covered by the
  new real-DB seed test and existing global-policy unit tests.
- I01/I02/I03/I05: fresh/upgrade/head replay and seed replay covered.
- I06/I07/I08/I09/I10/I11: hostile drift/UUID collision paths are implemented
  atomically as `MT010`; the new test covers a representative deletion drift,
  and the seed SQL covers missing/extra/metadata/UUID/set/action cases.
- I12–I16: existing built-in protection, runtime negative privileges and the
  runtime/control allowlists remain covered by the canonical suites.
- I17: explicit no-assignment assertion passes.
- I18: exact 11 Permission/Action set equality passes.
- I19/I20: protected-role concurrency and migration rollback are exercised by
  the existing concurrency/migration suites with the updated cumulative counts.
- M01–M08: head assertions updated to `0017`; historical migration/seed
  expectations retained and extended; `0016`/v006/v012 remain byte-for-byte
  unchanged.

## Remaining work

Full PR 24P remains **IN PROGRESS** and not accepted: operator fixture,
genuine-token operator grant/revoke/get vertical slice, admission harness,
development stack/OAuth integration, Gate C and PR 22B composite are not
executed. No roadmap DONE or Gate C PASS is claimed.

## Terminal status

**`SEED_0017_ACCEPTED — PR24P_IMPLEMENTATION_STILL_INCOMPLETE`**

`STOP-SEED` is cleared for the bounded seed. The prior implementation remains
at its existing stop point; subsequent work must resume under the approved
PR 24P contracts.
