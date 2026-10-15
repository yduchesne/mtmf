# PR21_AMENDMENT01_SECURITY_CASES

**PR:** roadmap PR 21 — Amendment 01
**Status:** **DESIGN-TIME CASES — NOT EXECUTED.** The original C01–C36 in
`PR21_SECURITY_MATRIX.md` are retained unchanged and are not renumbered or
deleted. This file **adds** A01–A20 for the new resolve-or-provision,
Application-management, registration, and subscription-management contracts.

Owner/test layer: 22/23/24/25 = roadmap PR; unit = deterministic unit test;
PG = real-PostgreSQL restricted-runtime integration; deployed = end-to-end.

| ID | Scenario | Expected outcome | Owner/test layer |
|---|---|---|---|
| A01 | Verifiably new Identity, entitled Application, no Tenant | `CREATED`; atomic Identity/Principal/Tenant/steward/initial registration+subscription; stable IDs; one audit | 22/23 — PG + deployed |
| A02 | Service token alone attempts first-Tenant creation | deny; no writes | 24 — deployed |
| A03 | Wrong issuer/audience/client-binding pair | deny | 24 — deployed |
| A04 | Forged `(issuer, subject)` / caller-supplied UUID | deny before any write | 23/24 — PG + deployed |
| A05 | Existing Identity + one eligible Tenant (registered+subscribed) | `REUSED`; no mutation; same IDs | 23/24 — PG + deployed |
| A06 | Existing Identity + Tenant suspended/inactive | fail closed / explicit status; no replacement Tenant | 23/24 — PG |
| A07 | Existing Identity + multiple eligible Tenants | `SELECTION_REQUIRED`; only authorized choices; no leak; no mutation | 24 — PG + deployed |
| A08 | Conflicting subject binding or corrupt/partial state | fail closed; no auto-repair | 23 — PG |
| A09 | Existing Identity + membership but calling Application not subscribed | `SUBSCRIPTION_REQUIRED`; no auto-subscription; no second Tenant | 24 — PG + deployed |
| A10 | Subscription present but registration absent/revoked | ineligible; no `REUSED`; no silent registration | 22/24 — PG |
| A11 | Inactive/`SUSPENDED`/`RETIRED` Application | deny subscribe/inspect-by-none; `RETIRED` cannot reopen | 24 — PG |
| A12 | `CANCELLED`/`EXPIRED` subscription or expired `ends_at` | ineligible; terminal immutability; no reopen | 22/24 — PG |
| A13 | Wrong or absent recipient proof / unapproved Role invitation | deny; no redemption | 25 — PG + deployed |
| A14 | Invitation capability replay / concurrent double acceptance | exactly one grant; safe replay otherwise | 25 — PG concurrency |
| A15 | Cross-Tenant enumeration via selection or list | only authorized, non-enumerating choices; opaque `404` otherwise | 24 — deployed |
| A16 | Idempotency collision (same key, changed fingerprint) | `409`; no write; replay returns same IDs | 22 — PG |
| A17 | Registration mutation attempted without STOP-04 authority | deny; Tenant Administrator privileges not silently broadened | 24 — PG |
| A18 | `RETIRED` Application update/reopen attempt | deny | 24 — PG |
| A19 | Unauthorized subscription creation (no Tenant authority) | deny; no silent subscription | 24 — PG + deployed |
| A20 | Terminal subscription in-place reactivation attempt | deny; replacement is a new row under STOP-05 only | 22/24 — PG |
| A21 | Initial registration/subscription rollback on later step failure | whole pre-Tenant transaction rolls back; no partial active Tenant | 22 — PG |
| A22 | Root/SYSTEM Tenant subscription or onboarding | deny | 22/24 — deployed |
| A23 | Operator-only stored function exposed to `mtmf_runtime` | privilege test fails; no runtime mutation grant | 22/24 — PG |
| A24 | Stale authorization snapshot after subscription/application suspension | new evaluation denies; bounded existing snapshot TTL | 24/26 — PG + deployed |
| A25 | Second Application adoption of one Tenant | same Tenant/Identity; independent subscription authorization | 26 — deployed |

## Cross-references

- Existing `C01`–`C36`: `PR21_SECURITY_MATRIX.md` (unchanged).
- Authorization actors/scopes: `PR21_AMENDMENT01_AUTHORIZATION_MATRIX.md`.
- Decision/STOP boundaries: `PR21_AMENDMENT01_DECISION_RECORD.md`,
  `PR21_AMENDMENT01_STOP_REPORT.md`.


---

## Amendment 02 update (2026-10-15)

A01–A25 are retained unchanged. Amendment 02 adds B01–B28 in
[PR21_AMENDMENT02_SECURITY_CASES.md](PR21_AMENDMENT02_SECURITY_CASES.md).
