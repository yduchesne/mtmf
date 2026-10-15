# PR21_SECURITY_MATRIX

**PR:** roadmap PR 21 — Application-neutral onboarding architecture and API contracts
**Status:** **DESIGN-TIME MATRIX — NOT EXECUTED.** Writing a row is not a test and
does not claim production behavior. Every row is a future implementation case
owned by PRs 22–26. PR 26 owns the deployed COLD/REPEAT/RECREATE and
fault/concurrency acceptance.

The assertions below are normative for the future implementation. The
"owner/test layer" column names the roadmap PR and the expected test layer
(unit, real-PostgreSQL integration, or deployed end-to-end). Future
integration tests MUST exercise the production services, real PostgreSQL, the
restricted `mtmf_runtime` role, stored functions and UnitOfWork; only explicit
external IdP boundaries may be faked for deterministic tests.

## Matrix

| ID | Scenario | Expected outcome | Owner/test layer |
| --- | --- | --- | --- |
| C01 | Approved operator creates a Tenant for a verified new user | One ACTIVE ordinary Tenant, verified steward, atomic audit, stable UUIDs returned | 22/23 — real-PostgreSQL integration + deployed |
| C02 | Same idempotency key and fingerprint after a lost response | Identical UUIDs returned; no duplicate Tenant/membership/assignment | 22 — real-PostgreSQL integration |
| C03 | Same idempotency key, changed request fingerprint | `409`; no write | 22 — real-PostgreSQL integration |
| C04 | Concurrent requests with the same `tenant_key` | Exactly one Tenant; loser gets deterministic replay or conflict | 22 — real-PostgreSQL concurrency |
| C05 | Duplicate display `name`, different `tenant_key` | Two legal Tenants | 22 — real-PostgreSQL integration |
| C06 | Missing verified user or forged Identity UUID | Deny; no write | 23 — real-PostgreSQL integration |
| C07 | Service token alone requests Tenant creation | Deny | 22/24 — real-PostgreSQL + deployed |
| C08 | SYSTEM/root Tenant target or subscription | Deny | 22/24 — real-PostgreSQL + deployed |
| C09 | Initial steward missing Principal/Identity membership | Tenant cannot become ACTIVE | 22/23 — real-PostgreSQL integration |
| C10 | Steward lacks approved Tenant Administrator Role | Tenant cannot become ACTIVE | 23 — real-PostgreSQL integration |
| C11 | IdP outage before the transaction | Typed failure; no writes | 23/24 — deployed fault |
| C12 | DB/audit failure mid-mutation | Full rollback (state + audit) | 22/23 — real-PostgreSQL fault |
| C13 | Existing `(issuer, subject)` seen again | Reuse the global Identity/Principal | 23 — real-PostgreSQL integration |
| C14 | Conflicting external subject binding | Deny reassociation; no rebind | 23 — real-PostgreSQL integration |
| C15 | Identity is a member of Tenant A but not Tenant B | No automatic B membership | 23 — real-PostgreSQL integration |
| C16 | Unauthorized Application knows a Tenant UUID/key | No lookup leak and no subscription | 24 — deployed |
| C17 | Application subscribed to A only | No B authorization | 24/26 — deployed |
| C18 | Cross-client service/user token pair | Reject | 24 — deployed |
| C19 | Authorized invitation creation | `PENDING` invitation; no membership yet | 25 — real-PostgreSQL + deployed |
| C20 | Wrong verified recipient accepts | Deny; no redemption | 25 — real-PostgreSQL + deployed |
| C21 | Expired or revoked invitation | Deny | 25 — real-PostgreSQL integration |
| C22 | Concurrent double acceptance | Exactly one grant | 25 — real-PostgreSQL concurrency |
| C23 | Capability presented without a verified user token | Deny | 25 — real-PostgreSQL + deployed |
| C24 | Unapproved Role / ROOT Role invitation | Deny | 25 — real-PostgreSQL integration |
| C25 | Existing Identity joins a second Tenant | Same global IDs; isolated memberships | 25/26 — real-PostgreSQL + deployed |
| C26 | Consumer database failure after the MTMF commit | Authorized reconciliation; same IDs; no duplicate MTMF state | 25/26 — deployed fault |
| C27 | Unknown/duplicate field, nil UUID | Whole-request validation error; no partial write | 24/25 — unit + deployed |
| C28 | Inactive Tenant/Application | Deny subscription/invitation | 24/25 — real-PostgreSQL integration |
| C29 | Authorization snapshot presented as a provisioning credential | Deny | 24 — deployed |
| C30 | Secret/JWT/capability appears in audit or logs | Security test fails | 22–25 — real-PostgreSQL + telemetry |
| C31 | Wrong issuer/audience | Deny | 24 — deployed |
| C32 | First-time invitee has no membership | Pre-membership verification; no fabricated grant | 25 — real-PostgreSQL + deployed |
| C33 | `owner_identity_id` treated as Role/steward | Deny | 22/23 — unit + real-PostgreSQL |
| C34 | Incompatible existing subscription | `409`; no silent repair | 22/24 — real-PostgreSQL integration |
| C35 | Post-onboarding batch evaluation | Only exact authorized Actions | 26 — deployed |
| C36 | Two independently authenticated Applications | Distinct subscriptions; same global Identity IDs | 26 — deployed |

## Column semantics

- **Expected outcome** is fail-closed unless it explicitly says otherwise. No
  row may produce an `ALLOW`, a success response, or a usable snapshot on a
  prerequisite failure.
- **Owner** is the roadmap PR that implements the behavior and owns its
  adversarial acceptance (AGENTS.md: no unplanned separate audit PRs).
- **Test layer** distinguishes deterministic unit tests, real-PostgreSQL
  restricted-runtime integration tests, and deployed end-to-end conformance.
  A row listed as "deployed" is not proven by a unit test.

## Cross-references

- Admission/state/identity rules: `docs/ONBOARDING_ARCHITECTURE.md`.
- Wire-level error/visibility expectations: `docs/ONBOARDING_HTTP_CONTRACT.md`.
- Action-URN mapping proposal (unapproved): `PR21_CONTRACT_REVIEW.md`.
- Open admission decision: `PR21_STOP_REPORT.md` (STOP-01).
