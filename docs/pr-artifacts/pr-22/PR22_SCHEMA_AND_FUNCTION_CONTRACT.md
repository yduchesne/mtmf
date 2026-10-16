# PR22_SCHEMA_AND_FUNCTION_CONTRACT

**PR:** roadmap PR 22
**Status:** the entitlement foundation below is **IMPLEMENTED** (revision
`0014`). The first-Tenant composite and quota/replay consumption are
**PROPOSED / BLOCKED** and are not implemented.

## 1. Implemented schema (revision `0014`, `sql/v014`)

### 1.1 `mtmf.application_onboarding_entitlement`

| Column | Type | Constraint |
| --- | --- | --- |
| `id` | uuid | PK |
| `application_id` | uuid | FK → `mtmf.application(id)` |
| `state` | smallint | `CHECK (state IN (1,2))`; 1=ACTIVE, 2=REVOKED (terminal) |
| `granted_at` | timestamptz | DB-authoritative (`now()`) |
| `granted_by_operator_principal_id` | uuid | FK → `mtmf.principal(id)` |
| `grant_reason` | text | bounded 1..512 |
| `quota_total` | bigint | `> 0` (explicit positive limit; no implicit unlimited) |
| `quota_consumed` | bigint | `>= 0 AND <= quota_total`, monotonic |
| `version` | bigint | `>= 0` |
| `revoked_at` | timestamptz | present iff REVOKED |
| `revoked_by_operator_principal_id` | uuid | FK → `mtmf.principal(id)`; present iff REVOKED |
| `revocation_reason` | text | bounded 1..512; present iff REVOKED |

- Revocation-consistency CHECK: a REVOKED row carries complete revocation
  provenance; an ACTIVE row carries none.
- `UNIQUE INDEX application_onboarding_entitlement_active_unique
  (application_id) WHERE state = 1` — at most one ACTIVE per Application.
- `BEFORE UPDATE OR DELETE` guard `guard_application_onboarding_entitlement`:
  immutable `id`/`application_id`/`granted_at`/`granted_by_operator_principal_id`/
  `grant_reason`/`quota_total`; REVOKED terminal; only `1→2`; monotonic
  `quota_consumed`; DELETE rejected. SQLSTATE `MT046`.

### 1.2 `mtmf.application_onboarding_entitlement_event`

Append-only: `id`, `entitlement_id` FK, `event_type` (1=GRANTED, 2=REVOKED),
`occurred_at`, `operator_principal_id` FK, `correlation_id`, `old_state`
(nullable), `new_state`, `reason` (bounded 1..512). Shape CHECK:
GRANTED ⇒ `old_state IS NULL AND new_state=1`; REVOKED ⇒ `old_state=1 AND
new_state=2`. `guard_application_onboarding_entitlement_event` rejects
UPDATE/DELETE (SQLSTATE `MT046`).

## 2. Implemented functions (all owner-owned `SECURITY INVOKER`, `search_path=''`)

| Function | Signature | Grant |
| --- | --- | --- |
| `application_onboarding_entitlement_grant` | `(uuid, uuid, uuid, text, bigint, uuid) → boolean` | operator-only |
| `application_onboarding_entitlement_revoke` | `(uuid, uuid, text, uuid) → boolean` | operator-only |
| `application_onboarding_entitlement_get` | `(uuid) → jsonb` | operator-only |
| `application_onboarding_entitlement_find_by_application` | `(uuid) → setof jsonb` | operator-only |
| `application_onboarding_entitlement_event_find_by_entitlement` | `(uuid) → setof jsonb` | operator-only |
| `guard_application_onboarding_entitlement` | trigger | operator-only |
| `guard_application_onboarding_entitlement_event` | trigger | operator-only |

- Grant validates an existing **ACTIVE** Application, a bounded non-empty
  reason, and a positive `quota_total`; inserts `ACTIVE` with `quota_consumed=0`
  and appends one GRANTED event atomically. A duplicate ACTIVE grant returns
  `false` (no second row, no event).
- Revoke locks the row `FOR UPDATE`, returns `false` if unknown/already
  terminal, otherwise sets REVOKED with complete provenance and appends one
  REVOKED event.
- **No function is granted to `mtmf_runtime`.** `HEAD_REVISION` was advanced to
  `0014`; the runtime allowlist is unchanged at **78**.

## 3. Privilege model

- Tables owned by `mtmf_owner`; `PUBLIC` revoked; no runtime table privilege.
- Functions owner-owned, `SECURITY INVOKER`, `search_path=''`, `PUBLIC` EXECUTE
  revoked, not granted to `mtmf_runtime`.
- Migration `0014` assertions verify tables exist, no v014 function is
  runtime-executable, `PUBLIC` has no EXECUTE, no runtime table privilege, and
  the single-ACTIVE index exists. The mandatory post-upgrade runtime verifier
  runs after `0014` and passes with the unchanged 78-signature manifest.

## 4. Transaction boundaries

- The implemented operator primitives are single-statement atomic operations
  invoked by an operator/migrator connection.
- The **proposed** first-Tenant composite (Tenant + Identity/Principal/initial
  steward + one initial registration + one initial subscription + audit +
  replay/quota) is **NOT IMPLEMENTED**: its transaction seam is blocked
  (`PR22_STOP_REPORT.md`, STOP-P22-B). No partial Tenant-commit path exists.

## 5. Proposed (not implemented) — quota/replay and composite

The plan's `onboarding_provisioning_request` ledger, canonical fingerprint,
atomic quota reservation (`UPDATE ... WHERE state='ACTIVE' AND quota_consumed <
quota_total RETURNING`), replay finalization, and the PR 23-composed first-Tenant
transaction remain **PROPOSED** and are gated on the architectural decision.
