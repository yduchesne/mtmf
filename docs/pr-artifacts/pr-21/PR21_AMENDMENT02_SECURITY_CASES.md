# PR21_AMENDMENT02_SECURITY_CASES

**PR:** roadmap PR 21 — Amendment 02
**Status:** **DESIGN-TIME CASES — NOT RUN.** The original `C01`–`C36`
(`PR21_SECURITY_MATRIX.md`) and Amendment 01 `A01`–`A25`
(`PR21_AMENDMENT01_SECURITY_CASES.md`) are retained unchanged; this file adds
`B01`–`B22` and does not renumber or delete any prior case.

Setup/action/expected/owner/test layer: 22/23/24/25/26 = roadmap PR; unit =
deterministic unit; PG = real-PostgreSQL restricted-runtime integration;
deployed = end-to-end.

| ID | Setup | Action | Expected result | Owner | Test layer |
|---|---|---|---|---|---|
| B01 | Verified new Identity; Application has no onboarding entitlement | `resolve-or-provision` | deny; nothing created | 23/24 | PG + deployed |
| B02 | Entitlement `REVOKED` before request | `resolve-or-provision` (new Identity) | deny; no new Tenant; existing Tenants unaffected | 23/24 | PG |
| B03 | Entitlement `ACTIVE`; per-Application quota exhausted | `resolve-or-provision` | deny; no write; no quota overshoot | 22/23 | PG concurrency |
| B04 | Two simultaneous entitled new-Identity requests under quota N | concurrent `resolve-or-provision` | at most N creations; atomic reservation; no overshoot | 22/23 | PG concurrency |
| B05 | Service token client ≠ user token client | `resolve-or-provision` | reject (cross-client) | 24 | deployed |
| B06 | New Identity (no binding) | `resolve-or-provision` (entitled) | `CREATED`; Identity/Principal/Tenant/steward/initial registration+subscription; stable IDs | 22/23 | PG + deployed |
| B07 | Existing Identity, eligible Tenant | `resolve-or-provision` | `REUSED`; no mutation | 23/24 | PG + deployed |
| B08 | Same verified Alice in Digr then ATI (one Tenant) | second Application onboard | same Identity/Tenant UUIDs; `SUBSCRIPTION_REQUIRED` for ATI | 24/26 | deployed |
| B09 | Identity member of two eligible Tenants | `resolve-or-provision` | `SELECTION_REQUIRED`; authorized choices only; no leak | 24 | PG + deployed |
| B10 | Existing Identity + Tenant, calling Application not subscribed | `resolve-or-provision` | `SUBSCRIPTION_REQUIRED`; no auto-subscribe; no second Tenant | 24 | PG + deployed |
| B11 | Subscription exists, registration absent/`REVOKED` | eligibility / subscribe | ineligible; `REUSED` denied; no silent registration | 22/24 | PG |
| B12 | Tenant Administrator attempts registration | registration create | deny (system authority only, P04) | 24 | PG |
| B13 | Application attempts self-registration | registration create | deny | 24 | deployed |
| B14 | Tenant Administrator attempts self-subscription without registration | subscription create | deny | 24 | PG |
| B15 | Registration `REVOKED`; system operator replaces | registration create (new UUID) | new registration; audit with predecessor; no terminal reactivation | 24 | PG |
| B16 | Subscription `CANCELLED`/`EXPIRED`; Tenant admin replaces with `ACTIVE` registration | subscription create (new UUID) | new subscription; audit with predecessor; no terminal reactivation | 24 | PG |
| B17 | Subscription `SUSPENDED` | resume | in-place `SUSPENDED→ACTIVE`; not a replacement; CAS enforced | 24 | PG |
| B18 | Application `RETIRED` | any Application update / subscribe | deny; cannot reopen | 24 | PG |
| B19 | Application suspended/old credential still cryptographically valid | eligibility | ineligible immediately | 24/26 | deployed |
| B20 | Credential `(issuer, client_id)` bound to a different Application | service authentication | reject; no Application override | 14/24 | PG + deployed |
| B21 | SYSTEM/root Tenant target for onboarding/subscription | any onboarding op | deny | 22/24 | deployed |
| B22 | Cross-Tenant list/inspect of registration/subscription | read/list | only authorized Tenant scope; opaque result; no enumeration | 24 | deployed |
| B23 | Same idempotency key, changed fingerprint | onboarding/subscription | `409`; no write | 22/24 | PG |
| B24 | Later step fails after initial creation begins | first-Tenant transaction | full rollback; no partial active Tenant or orphan records | 22 | PG |
| B25 | Concurrent duplicate current-row create | concurrent subscribe/register | exactly one current row; loser conflict/replay | 22/24 | PG concurrency |
| B26 | Successful grant/revoke/provision/replacement | audit | exactly one append-only atomic audit row with actor/entitlement/predecessor/outcome | 22/24/25 | PG |
| B27 | No-op / failed mutation | audit | no false success row | 22/24 | PG |
| B28 | Credential binding add/revoke | Application CRUD | not implied; separate operation only | 24 (gated) | PG |

## Cross-references

- Prior cases: `PR21_SECURITY_MATRIX.md` (C01–C36),
  `PR21_AMENDMENT01_SECURITY_CASES.md` (A01–A25).
- Decisions: `PR21_AMENDMENT02_DECISION_RECORD.md`;
  manifest/authorization: `PR21_AMENDMENT02_ACTION_MANIFEST.md`,
  `PR21_AMENDMENT02_AUTHORIZATION_MATRIX.md`.
- STOP state: `PR21_AMENDMENT02_STOP_REPORT.md`.
