# PR22_SECURITY_MATRIX

**PR:** roadmap PR 22
**Status:** the entitlement foundation P22 cases are **EXECUTED**; the
Tenant-committing composite/quota/replay cases are **NOT RUN — BLOCKED**.
Feature acceptance is real-PostgreSQL evidence, not unit-only.

## 1. Executed cases (entitlement foundation)

| ID | Scenario | Expected | Result | Evidence |
| --- | --- | --- | --- | --- |
| P22-01 | Operator grant with explicit quota | ACTIVE row, immutable GRANTED event, one ACTIVE per Application | **PASS** | `test_p22_01_operator_grant_with_explicit_quota` |
| P22-02 | Grant attempt with runtime role | DB privilege denial, no state | **PASS** | `test_p22_02_runtime_cannot_grant_entitlement` |
| P22-03 | Revoke, then attempt resume | REVOKED terminal; no reactivation | **PASS** | `test_p22_03_revoke_is_terminal` |
| P22-04 | Regrant after revoke | New UUID, old history intact | **PASS** | `test_p22_04_regrant_after_revoke_uses_fresh_uuid` |
| P22-05 | Missing/inactive Application | Deny, no entitlement | **PASS** | `test_p22_05_inactive_application_is_denied`, `..._unknown_application_is_denied` |
| P22-06 | Non-positive/invalid quota | Deny; table CHECK rejects bypass | **PASS (foundation slice)** | `test_p22_06_nonpositive_quota_is_denied` |
| P22-16 | Restricted runtime executes privileged function | Explicit permission denial | **PASS** | `test_p22_16_runtime_cannot_read_or_revoke_entitlement` |
| P22-17 | Migration postflight with real `mtmf_runtime` | PASS; no extra grants | **PASS** | `test_p22_17_migration_postflight_and_runtime_allowlist_unchanged` |
| P22-18 | Idempotent migration / append-only history | No duplicate authority; protected `0006`/`0012` unchanged | **PASS (history slice)** | `test_p22_18_history_is_append_only`; migration/privilege lifecycle suites |

**Exact counts** (validated by the integration suite): distinct new
Permission-backed operations **0** (no catalog seed), admission-only Role grants
**0**, runtime allowlist unchanged at **78**, single-ACTIVE unique index present,
no runtime table/function privilege.

## 2. BLOCKED cases (Tenant-committing composite / quota / replay)

| ID | Scenario | Status | Reason |
| --- | --- | --- | --- |
| P22-06 (exhaustion) | Exhausted quota denies without extra Tenant | NOT RUN | consumption occurs only inside the blocked composite |
| P22-07 | Two concurrent requests, one quota slot | NOT RUN | composite blocked |
| P22-08 | Concurrent identical idempotency key | NOT RUN | replay ledger/composite blocked |
| P22-09 | Same key, different fingerprint | NOT RUN | replay ledger/composite blocked |
| P22-10 | Fault after Tenant/registration/subscription/audit | NOT RUN | composite blocked |
| P22-11 | Complete fixture participant in one transaction | NOT RUN | PR 23 participant + composite blocked |
| P22-12 | Absent participant | NOT RUN (unit-level fail-closed by design) | coordinator not implemented |
| P22-13 | Existing Tenant / second Application in first-Tenant path | NOT RUN | composite blocked |
| P22-14 | SYSTEM/root Tenant or retired Application | NOT RUN (retired-Application slice proven at grant; composite blocked) | composite blocked |
| P22-15 | PR 13 lifecycle/terminal rows preserved | PASS (regression: full integration suite green) | PR 13 unchanged |

## 3. Authorization invariants

- Entitlement is not a Role/Permission/subscription/credential; it is not
  assignable and confers no authority.
- `tenant:provision-object` / `tenant-invitation:accept-object` carry **zero**
  Role/Permission grants; no catalog seed was added (no new Permission-backed
  operation).
- No implicit entitlement from a service credential, Role, subscription, Tenant,
  or Application creation.
- No `mtmf_runtime` privileged mutation grant, direct or indirect; no
  `SECURITY DEFINER` runtime wrapper; no root impersonation or Tenant-bound
  Authorizer bypass.

## 4. Verification

The executed rows are proven by the real-PostgreSQL integration suite (603
passed / 90 skipped). The blocked rows are owned by the architectural decision
in `PR22_STOP_REPORT.md`; they are **NOT RUN** and no partial Tenant commit
exists.
