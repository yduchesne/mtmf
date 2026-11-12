# PR 23 — SQL Transaction Participant Contract

Revision **`0015`** / `0015_pr23_initial_stewardship` (additive; down revision
`0014`). Files:

```text
packages/mtmf-core/src/mtmf_core/persistence/postgres/migrations/versions/0015_pr23_initial_stewardship.py
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/__init__.py
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/01_stewardship_audit_operation.sql
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/02_onboarding_subject_and_steward_functions.sql
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/03_onboarding_subject_and_steward_grants.sql
packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v015/04_onboarding_subject_and_steward_assertions.sql
```

## Audit taxonomy extension

`01_stewardship_audit_operation.sql` replaces
`stewardship_audit_operation_check` with exactly the four historical values plus
`INITIAL_ONBOARDING`. Rows, append-only triggers, and provenance columns are
untouched.

## B1 — `mtmf.onboarding_subject_prepare`

```sql
mtmf.onboarding_subject_prepare(
    issuer_value text,
    subject_value text,
    new_principal_id_value uuid,
    new_identity_id_value uuid,
    new_binding_id_value uuid
) RETURNS jsonb
```

- Exact, case-sensitive opaque issuer/subject; non-null/non-blank/≤512; never
  trimmed or case-folded for matching.
- Three target UUIDs required, pairwise distinct, unused in their target tables,
  and never canonical root IDs. The canonical-root exclusion is a full
  three-by-three rule: each proposed Principal, Identity, and binding UUID is
  rejected with `MT047` if it equals **any** of the root Tenant, root Principal,
  or root Identity UUIDs (not only the same-type root object).
- Requires exactly one initialized canonical root registry row.
- Takes
  `pg_advisory_xact_lock(hashtextextended('mtmf.pr23.subject:' || issuer || chr(31) || subject, 0))`
  then locks all matching binding rows in `id` order.
- One ACTIVE binding → validate active FEDERATED Identity, active Principal,
  non-root, and return `{"status":"EXISTING","identity_id":…,"principal_id":…}`
  with zero writes.
- No ACTIVE binding but any REVOKED history → `MT048` (never a new user).
- No history → insert exactly one Principal (`Onboarded Principal`, not deleted),
  one FEDERATED Identity (`Onboarded Identity`, not deleted), and one ACTIVE
  binding, all in the caller transaction; return `{"status":"CREATED",…}`.
- No Tenant, membership, Role, subscription, entitlement, or audit write.
- Any unexplained collision/ambiguity raises and aborts; no upsert, retry, or
  silent repair.

## B2 — `mtmf.onboarding_initial_steward_attach`

```sql
mtmf.onboarding_initial_steward_attach(
    tenant_id_value uuid,
    issuer_value text,
    subject_value text,
    identity_id_value uuid,
    assignment_id_value uuid
) RETURNS jsonb
```

- Requires a caller-created fresh ordinary `PROVISIONING` Tenant
  (`scope=2`, `lifecycle=0`, not deleted), owned by the supplied Identity and
  distinct from the root Tenant.
- Locks the Tenant `FOR UPDATE`, then the exact ACTIVE binding, then the
  Principal and Identity in the v008 order, then the designation.
- Requires the binding to point at the supplied Identity, an active FEDERATED
  Identity of an active Principal, and no canonical root object.
- Rejects any pre-existing stewardship designation, Principal/Identity Tenant
  membership, Identity Role assignment, Application registration, subscription,
  Organization, Group, Group–Tenant membership, Group Role assignment,
  Tenant-defined Role (`role.defining_tenant_id`), management-group manager
  state (`tenant_management_group.manager_tenant_id`), or managed-target state
  (`tenant_management_group_membership.tenant_id`) in the supposedly fresh
  Tenant (`MT048`). The check is exact-Tenant: unrelated state in another Tenant
  does not make the target Tenant dirty.
- Requires the protected built-in `urn:mtmf:iam:roles:system:tenant-administrator`
  Role and its `builtin_role` marker; never seeds or modifies them.
- Inserts both typed memberships via the reviewed v004 functions, exactly one
  direct Tenant-wide Tenant Administrator assignment via the v005 function
  (`organization_id = NULL`), one `stewardship_designation` version 1, and one
  `INITIAL_ONBOARDING` audit row with `actor_provenance = NULL` and reason
  `initial pre-Tenant stewardship; request audit pending PR22B`.
- Returns `{"tenant_id", "principal_id", "identity_id", "assignment_id",
  "stewardship_version": 1}`.
- Never activates a Tenant, calls `commit()`/`rollback()`, writes quota/replay/
  registration/subscription, or claims idempotent success for a dirty graph.

## SQLSTATE contract

| Code | Meaning |
| --- | --- |
| `MT047` | Malformed/unacceptable input, missing root registry, root object attempt, ineligible Tenant/subject, missing built-in Role |
| `MT048` | Existing-subject conflict, revoked-only key, dirty new-Tenant graph, or concurrency/assignment conflict |

`MT047`/`MT048` were unused at baseline (highest allocated was `MT046`). They are
not remapped to success or generic authorization DENY; persistence translation
keeps them fail-closed as `PersistenceError`.

## Privileges

Both functions: `OWNER TO mtmf_owner`, `SECURITY INVOKER`,
`SET search_path = ''`, PUBLIC EXECUTE revoked, **no** `mtmf_runtime` grant.
v015 adds no table/sequence privilege. The runtime EXECUTE manifest remains
exactly 78 signatures. `0015` assertions also verify the original root/
stewardship triggers, the five-value audit CHECK, and the single-column
`stewardship_designation` primary key.

## Transaction boundary (test-owned example only)

```text
BEGIN;                                        -- caller-owned
  SELECT mtmf.onboarding_subject_prepare(...);        -- CREATED / EXISTING
  INSERT INTO mtmf.tenant (... scope=2, lifecycle=0 ...);  -- future PR 22B
  SELECT mtmf.onboarding_initial_steward_attach(...);      -- structural graph
  -- future PR 22B: registration/subscription/quota/replay/audit/activate
COMMIT;   -- or ROLLBACK removes every participant effect
```

The real `PostgresMtmfSpi` remains runtime-only and cannot execute these
functions. The production privileged caller is explicitly PR 24P + PR 22B.
