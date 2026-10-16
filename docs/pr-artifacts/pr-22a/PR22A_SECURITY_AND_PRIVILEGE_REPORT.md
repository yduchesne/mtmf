# PR22A_SECURITY_AND_PRIVILEGE_REPORT

**Roadmap identifier:** PR 22A
**Status:** entitlement foundation verified; no runtime privilege expansion.

## 1. Trust boundary

The onboarding entitlement is an operator/installation-controlled authority. It
is **not** a Role, Permission, subscription, or credential, and it confers no
authority by itself. In PR 22A no runtime path reads or mutates it.

## 2. Functions and effective grants

| Function | Security | Owner | `search_path` | PUBLIC | `mtmf_runtime` |
| --- | --- | --- | --- | --- | --- |
| `application_onboarding_entitlement_grant` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `application_onboarding_entitlement_revoke` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `application_onboarding_entitlement_get` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `application_onboarding_entitlement_find_by_application` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `application_onboarding_entitlement_event_find_by_entitlement` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `guard_application_onboarding_entitlement` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |
| `guard_application_onboarding_entitlement_event` | INVOKER | `mtmf_owner` | `''` | revoked | **no EXECUTE** |

No `SECURITY DEFINER` function is introduced. No `mtmf_runtime` EXECUTE, no
`PUBLIC` EXECUTE, no runtime table/sequence privilege. The runtime EXECUTE
allowlist remains the reviewed **78** signatures
(`expected_runtime_signatures()`), and migration `0014` asserts the absence of
runtime grants and table privileges.

## 3. Structural guarantees

- Single `ACTIVE` entitlement per Application (partial unique index) — a
  concurrent duplicate grant yields exactly one `ACTIVE` row (verified).
- `REVOKED` is terminal; grant provenance (`id`, `application_id`, `granted_at`,
  `granted_by_operator_principal_id`, `grant_reason`, `quota_total`) is
  immutable; `quota_consumed` is monotonic; history is append-only.
- Explicit positive `quota_total`, `0 <= quota_consumed <= quota_total`;
  `quota_consumed` stays `0` because consumption is intentionally not
  implemented (PR 22B).
- Grant requires an existing **ACTIVE** Application; unknown/inactive
  Application, malformed reason/quota, nil/unknown FKs, and duplicate `ACTIVE`
  grants fail closed.

## 4. Non-expansion evidence

- `0006`/`0012` immutable seeds unchanged.
- No new Action/Permission/Role catalog row; the PR 21 admission markers still
  have **zero** Role grants.
- No Tenant, registration, subscription, Identity, Principal, membership,
  steward, quota ledger, or audit-success row can be created by the entitlement
  functions (verified: `test_p22a_entitlement_functions_create_no_tenant_or_linkage`).
- No HTTP route, no runtime-callable proxy, no root impersonation, no
  Tenant-bound Authorizer bypass.

## 5. Remaining privilege blockers (not resolved here)

STOP-P22-A/STOP-P22-B remain for the composite (runtime-callable privileged
mutation) and are the reason PR 22B requires **PR 24P** and **PR 23**. See
`PR22A_STOP_REPORT.md`.
