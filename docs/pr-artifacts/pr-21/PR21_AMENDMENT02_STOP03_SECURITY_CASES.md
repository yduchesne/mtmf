# PR21_AMENDMENT02_STOP03_SECURITY_CASES

**PR:** roadmap PR 21 — Amendment 02 STOP-03 Authorization Approval Addendum
**Status:** **DESIGN-TIME CASES — NOT RUN.** Prior matrices (C01–C36, A01–A25,
B01–B28) are retained unchanged. This file adds S01–S24 and does not renumber or
delete any prior case. Implementation tests belong to PRs 22–26 and remain
NOT RUN here.

Owner/test layer: 22/23/24/25/26 = roadmap PR; unit = deterministic unit; PG =
real-PostgreSQL restricted-runtime integration; deployed = end-to-end.

| ID | Input / attempted operation | Expected decision | Owner | Test layer |
|---|---|---|---|---|
| S01 | Valid Application service token without onboarding entitlement requests a new Tenant | DENY; no write | 22/23 | PG + deployed |
| S02 | Entitled Application with forged/unverified user subject | DENY; no write | 23/24 | PG + deployed |
| S03 | Entitled Application with an existing global Identity | No new Tenant; existing-Identity resolution | 23/24 | PG |
| S04 | Pre-Tenant entitlement attempts Application create or another Tenant's registration | DENY | 22/24 | PG |
| S05 | Tenant Administrator attempts global Application create/retire | DENY | 24 | PG |
| S06 | Tenant Administrator attempts registration create/revoke | DENY | 24 | PG |
| S07 | Tenant Administrator attempts a subscription in a different Tenant | DENY; no enumeration | 24 | deployed |
| S08 | Tenant Administrator attempts a subscription with no `ACTIVE` registration | DENY | 24 | PG |
| S09 | Application Administrator attempts credential binding | DENY | 24 | PG |
| S10 | Credential Administrator attempts Application create or entitlement grant | DENY | 24 | PG |
| S11 | Service token alone claims either SYSTEM Role | DENY | 24 | deployed |
| S12 | Unassigned SYSTEM Role definition exists | No authority; DENY | 24 | PG |
| S13 | Verified SYSTEM operator has exact Role assignment and Action | Eligible for the approved privileged interface only; no implicit runtime DB privilege | 24 | PG + deployed |
| S14 | Proposed HTTP operator route with no secure privileged execution bridge | Route NOT EXPOSED; no `mtmf_runtime` grants | 24 | PG |
| S15 | Unverified recipient or invalid/replayed capability | DENY; no membership write | 25 | PG + deployed |
| S16 | Verified recipient + valid single-use capability + no Tenant membership | Admission may proceed atomically; no synthetic Role | 25 | PG |
| S17 | Any admission marker has an ordinary built-in Role grant | Contract FAIL | 22/25 | unit + PG |
| S18 | Any wildcard Permission or new seed edit to `0006`/`0012` | Contract FAIL | 22/24 | PG |
| S19 | Retired Application attempts reactivation | DENY | 24 | PG |
| S20 | Revoked registration or cancelled/expired subscription updated in place | DENY; replacement requires fresh UUID and authority | 24 | PG |
| S21 | Tenant-scoped Permission evaluated at SYSTEM scope | DENY | 24 | unit + PG |
| S22 | Caller-supplied Application ID disagrees with the verified binding | DENY | 24 | deployed |
| S23 | Operator execution attempts mutation through the runtime DB account | DENY; no privileged grant | 24 | PG |
| S24 | Credentials appear in an Application management response/audit | Contract FAIL | 24/25 | PG + unit |

## Arithmetic / coverage assertions

- Manifest rows present: **25** (rows 1–25).
- Distinct new Permission-backed operations: **20** = 11 (`application-administrator`)
  + 2 (`application-credential-administrator`) + 7 (Tenant Administrator).
- Admission-only Action identifiers with zero grants: **2** (rows 2, 19).
- Existing approved Action reused: **1** (row 1); aliases: **2** (rows 11→8, 17→12).
- Every S case is owned by a future PR and is **NOT RUN** in PR 21.

## Cross-references

- `PR21_AMENDMENT02_ACTION_MANIFEST.md`,
  `PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md`,
  `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`.
- Prior cases: `PR21_SECURITY_MATRIX.md`, `PR21_AMENDMENT01_SECURITY_CASES.md`,
  `PR21_AMENDMENT02_SECURITY_CASES.md`.
