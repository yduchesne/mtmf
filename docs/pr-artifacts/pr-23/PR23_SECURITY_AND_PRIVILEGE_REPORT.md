# PR 23 — Security and Privilege Report

## Migration and postflight

- Fresh migration `0014 → 0015` and already-head no-op both succeeded under the
  real `mtmf_migrator` login with `SET ROLE mtmf_owner`.
- Mandatory effective-runtime-privilege postflight passed; runtime EXECUTE
  manifest remains **78** signatures.
- `scripts/mtmf-provision-roles.py --verify`:
  `verified runtime privileges on 127.0.0.1:25432/mtmf; mtmf_runtime is restricted`.

## Catalog posture (real PostgreSQL)

Both new functions:

```text
owner       = mtmf_owner
prosecdef   = false (SECURITY INVOKER)
proconfig   = ['search_path=""']
PUBLIC      = no EXECUTE
mtmf_runtime= no EXECUTE
```

Assertions in `04_onboarding_subject_and_steward_assertions.sql` additionally
verify:

- both exact signatures exist;
- no v015 runtime EXECUTE;
- no PUBLIC EXECUTE;
- `mtmf_runtime` holds no SELECT/INSERT/UPDATE/DELETE/TRUNCATE on `principal`,
  `identity`, `external_subject_identity`, `principal_tenant_membership`,
  `identity_tenant_membership`, `identity_role_assignment`,
  `stewardship_designation`, or `stewardship_audit`;
- 78 runtime-executable functions;
- 17 original root/stewardship triggers present;
- `stewardship_audit` CHECK admits exactly
  `BOOTSTRAP`, `INITIAL_ONBOARDING`, `RECOVERY`, `ROOT_IDENTITY_RECOVERY`,
  `TRANSFER`;
- `stewardship_designation` primary key is `tenant_id` only.

## Runtime denial (actual restricted login)

`tests/integration/postgres/test_pr23_initial_stewardship.py::test_p23_i18...`
authenticates as `mtmf_runtime` (fixture asserts `session_user = current_user =
mtmf_runtime`, not superuser, no owner/migrator membership) and confirms
`InsufficientPrivilege` (SQLSTATE 42501) for:

- `mtmf.onboarding_subject_prepare(...)`
- `mtmf.onboarding_initial_steward_attach(...)`
- direct subject-binding INSERT
- direct stewardship-designation SELECT
- direct stewardship-audit INSERT
- direct role-assignment UPDATE

No runtime grant, table grant, `SECURITY DEFINER` proxy, or privileged
`PostgresMtmfSpi` variant was added.

## Root, steward, and audit protections

- Canonical root Principal/Identity/Tenant IDs are rejected by both participants.
- Root registry remains unchanged after adversarial attempts.
- `INITIAL_ONBOARDING` preserves all four historical audit operations;
  arbitrary operations remain rejected by the CHECK.
- Append-only audit UPDATE/DELETE still raise `MT033`.
- Legacy PR 10 final-steward guards still deny membership/role removal (`MT032`).
- No protected seed migration (`0006`/`0012`) or shipped SQL `v001`–`v014` was
  modified.

## Failure classification

`MT047`/`MT048` are deterministic fail-closed structural codes and remain
`PersistenceError` in translation; they never become a successful response or a
policy ALLOW. No new HTTP error catalog entry was added.

## Independent-review fixup (F1/F2)

The F1/F2 fixup changes only the pre-write validation predicates in
`v015/02_onboarding_subject_and_steward_functions.sql`. It does not add a
migration, grant, ownership change, `SECURITY DEFINER` wrapper, table privilege,
runtime EXECUTE, trigger, seed change, Tenant activation, quota/replay, or
privileged executor.

Post-fix verification:

- both participants remain owner-owned, `SECURITY INVOKER`, empty
  `search_path`, PUBLIC revoked, `mtmf_runtime` denied;
- runtime EXECUTE manifest remains exactly **78**;
- migration head remains `0015` and postflight passes;
- append-only audit and root/steward guards remain intact;
- `--sec` reports 0 findings;
- F1 negative cases prove zero B2 writes and intact dirty state;
- F2 negative cases prove zero B1 writes and unchanged root registry;
- F1-08 proves exact-Tenant filtering for a globally reused Identity.
