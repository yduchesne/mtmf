# PR 23 — Independent Review Fixup Report (F1/F2)

**Date:** 2026-11-12
**Branch:** `dev/pr23-verified-subject-stewardship`
**Reviewed branch tip / baseline:** `227fbcb6981bacb4509d7ecde1bce244f367af96`
**Reviewed `main` / merge base:** `1bb46af8a8fe780be23521954e130ef895906ab9`
**Fixed content under test:** `a68177edddef46a077bf4942fbcd455cdd8a9428`
**PostgreSQL:** 18.6 (Debian 18.6-1.pgdg13+2), `127.0.0.1:25432/mtmf`
**Verdict:** `PR23_COMPLETE_INTERNAL_ONLY` — fixup accepted for final source re-review.

## Findings corrected

### F2 — cross-type canonical root UUID reuse (B1)

`mtmf.onboarding_subject_prepare` previously compared only
`new_principal_id = root_principal_id` and
`new_identity_id = root_identity_id`. The supplied binding UUID was not checked,
and cross-type collisions were not checked.

Fixed predicate: each of the three proposed UUIDs must differ from **all three**
canonical root UUIDs (root Tenant, root Principal, root Identity), with the
existing `MT047` failure before any B1 write.

### F1 — fresh-Tenant graph under-validation (B2)

`mtmf.onboarding_initial_steward_attach` previously checked six categories
(designation, Principal/Identity Tenant memberships, Identity Role assignment,
Application registration, subscription). It now also rejects, with `MT048`
before any B2 write:

1. `mtmf.organization.tenant_id`
2. `mtmf.group.tenant_id`
3. `mtmf.group_tenant_membership.tenant_id`
4. `mtmf.group_role_assignment.tenant_id`
5. `mtmf.role.defining_tenant_id`
6. `mtmf.tenant_management_group.manager_tenant_id`
7. `mtmf.tenant_management_group_membership.tenant_id`

Indirect child rows (`identity_group_membership`, `identity_org_membership`,
`group_org_membership`, management-group actor eligibility) remain covered by
their referentially required Group/Organization/management-group rows, exactly as
specified. The predicate is exact-Tenant only: unrelated state in another Tenant
does not make the target Tenant dirty.

## Files changed

```text
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/02_onboarding_subject_and_steward_functions.sql
tests/integration/postgres/test_pr23_initial_stewardship.py
```

No migration, grant, privilege, ownership, trigger, audit-taxonomy, runtime
allowlist, application service, Keycloak trust baseline, or future-PR code was
changed.

## Baseline evidence

| Item | Result |
| --- | --- |
| Branch tip | `227fbcb6981bacb4509d7ecde1bce244f367af96` |
| `origin/main` | `1bb46af8a8fe780be23521954e130ef895906ab9` |
| Merge base | `1bb46af8a8fe780be23521954e130ef895906ab9` |
| Working tree | clean before edits |
| Pre-fix targeted suite (`test_pr23_initial_stewardship.py` at `227fbcb`) | **22 passed** |
| `git fsck --full` | clean |

The independent-review defects were therefore not detected by the original 22
green tests; the fixup adds the missing coverage.

## New feature acceptance

`tests/integration/postgres/test_pr23_initial_stewardship.py` now contains
**40 tests** (22 original + 18 fixup):

| Case group | Count | Result |
| --- | --- | --- |
| F2 canonical-root permutations (3 proposed slots × 3 root UUIDs) | 9 | PASS — `MT047`, zero writes |
| F2 ordinary non-root create/reuse positive control | 1 | PASS — `CREATED` then `EXISTING` |
| F1-01 Organization | 1 | PASS — `MT048`, no B2 writes |
| F1-02 Group | 1 | PASS — `MT048`, no B2 writes |
| F1-03 Group–Tenant membership | 1 | PASS — `MT048`, no B2 writes |
| F1-04 Group Role assignment | 1 | PASS — `MT048`, no B2 writes |
| F1-05 Tenant-defined Role | 1 | PASS — `MT048`, no B2 writes |
| F1-06 Tenant as management-group manager | 1 | PASS — `MT048`, no B2 writes |
| F1-07 Tenant as managed target | 1 | PASS — `MT048`, no B2 writes |
| F1-08 cross-Tenant state not inherited, clean Tenant B attaches | 1 | PASS |
| Original P23-I01…I22 | 22 | PASS |

Each F1 negative case asserts:

- SQLSTATE exactly `MT048`;
- the seeded dirty row survives the failed statement;
- the target Tenant stays `scope=2`, `lifecycle=0`;
- zero `principal_tenant_membership`, `identity_tenant_membership`,
  `identity_role_assignment`, `stewardship_designation`, and
  `INITIAL_ONBOARDING` audit rows for the target Tenant;
- after rollback, the global subject and Tenant are absent.

Each F2 negative case asserts `MT047`, unchanged canonical root registry, and
zero new Principal/Identity/active-binding/Tenant/audit rows.

### Negative control (tests detect the old defect)

The new fixup tests were executed against the pre-fix `227fbcb` SQL in a clean
worktree:

```text
14 failed, 4 passed  (old SQL)
40 passed            (fixed SQL)
```

The four old-SQL passes are the same-type root checks that the old predicate
already covered; all cross-type/root-binding permutations and all seven F1
categories failed as intended. This proves the new tests are not vacuous.

## Canonical gates after fix

| Gate | Command | Result |
| --- | --- | --- |
| QA | `./build.sh --qa` | **PASS — 2490 passed, 0 skipped, 90.30%** |
| Security | `./build.sh --sec` | **PASS — 0 findings** |
| Rust | `./build.sh --rust` | **PASS** |
| Integration | `./build.sh --integration` | **PASS — 646 passed, 94 skipped** |
| Role verifier | `scripts/mtmf-provision-roles.py --verify` | **PASS** |
| Pre-commit | `uv run --no-sync pre-commit run --all-files` | **PASS** |
| Diff hygiene | `git diff --check` | PASS |
| Object integrity | `git fsck --full` | PASS |

`--integration` increased from 628 to 646 (+18 fixup cases), with the four live
cases remaining opt-in skipped as before.

## Genuine-token regression

Approved isolated `mtmf-dev` fixture, unchanged committed baseline/policy:

| Suite | Result |
| --- | --- |
| PR 23 L01–L04 | **4 passed, 0 skipped** |
| PR 14 live regression | **22 passed, 0 skipped** |

## Privilege and transaction posture (unchanged)

- Head remains `0015`; no new migration.
- Both participants remain owner-owned `SECURITY INVOKER` with empty
  `search_path`, PUBLIC EXECUTE revoked, and no `mtmf_runtime` EXECUTE.
- Runtime EXECUTE manifest remains exactly **78**; postflight and role verifier
  pass.
- No protected table grant, `SECURITY DEFINER` proxy, Tenant activation, quota,
  replay, registration/subscription, HTTP, or privileged executor was added.
- B1/B2 still run only inside the caller-owned PostgreSQL transaction and never
  commit/rollback independently. The fixup only tightens pre-write validation.

## Decision matrix outcome

All mandatory gates pass against the fixed content SHA. No STOP remains. The
fixup preserves the approved PR 23 internal-participant scope and does not
implement PR 24P, PR 22B, PR 24, PR 25, or PR 26.
