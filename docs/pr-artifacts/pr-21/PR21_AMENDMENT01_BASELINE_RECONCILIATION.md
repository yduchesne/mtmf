# PR21_AMENDMENT01_BASELINE_RECONCILIATION

**PR:** roadmap PR 21 — Amendment 01 (Application-Neutral Tenant Onboarding and Management Lifecycle Contracts)
**Type:** documentation-only amendment on the existing PR 21 branch
**Branch:** `dev/onboarding-foundation`
**Base SHA:** `455ae7a35d090b2546afa0c78fc9e4750ffee5ec`
**Pre-amendment PR 21 tip:** `739397820c064e5b7d2cc2b6cc90d3ec4f2025a2`
**Reconciliation status:** PHASE 0 COMPLETE — branch reconciled, repository reality recorded.

## 1. Branch and working state

| Item | Value |
| --- | --- |
| Branch | `dev/onboarding-foundation` |
| `git rev-parse HEAD` at start | `739397820c064e5b7d2cc2b6cc90d3ec4f2025a2` |
| `git rev-parse origin/main` | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Working tree | clean |
| Divergence | PR 21 documentation commits are ahead of `main`; no remote `origin/dev/onboarding-foundation` was configured/pushed, so no reset/rebase/cherry-pick was performed |
| Alembic migration head | `0013_security_mutation_audit_partitioning` |
| Production changes | none (documentation-only amendment) |

## 2. Files inspected (direct source, not roadmap claims)

| Area | File(s) |
| --- | --- |
| Lifecycle enums | `packages/mtmf-core/src/mtmf_core/domain/lifecycle.py` |
| Application registry domain + transitions | `packages/mtmf-core/src/mtmf_core/domain/application.py` |
| Eligibility evaluator | `packages/mtmf-core/src/mtmf_core/domain/eligibility.py` |
| Application eligibility service | `packages/mtmf-core/src/mtmf_core/application/application_eligibility.py` |
| Registry schema/indexes | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v010/01_application_registry_schema.sql` |
| Registry guards + mutation/read functions | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v010/02_application_registry_functions.sql` |
| Registry grants | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v010/03_application_registry_grants.sql` |
| SPI repository protocols | `packages/mtmf-core/src/mtmf_core/persistence/repositories.py` |
| HTTP routes | `packages/mtmf-service/src/mtmf_service/app.py` |
| Management DTOs / errors | `packages/mtmf-api/src/mtmf_api/management.py`, `errors.py` |
| PR 13 decisions | `docs/pr-artifacts/pr-13/PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md` |
| Prior PR 21 docs/artifacts | `docs/ONBOARDING_*.md`, `docs/pr-artifacts/pr-21/*` |

## 3. Reconciliation matrix

| # | Expected fact | Result | Evidence |
| --- | --- | --- | --- |
| F01 | PR 13 global `Application` lifecycle is `ACTIVE/SUSPENDED/RETIRED` | FOUND | `lifecycle.py` `ApplicationLifecycle`; `application.py` |
| F02 | `ApplicationTenantRegistration` lifecycle is `ACTIVE/REVOKED` | FOUND | `lifecycle.py` `RegistrationLifecycle` |
| F03 | `TenantApplicationSubscription` lifecycle is `PENDING/ACTIVE/SUSPENDED/CANCELLED/EXPIRED` with `[starts_at, ends_at)` | FOUND | `lifecycle.py`, `application.py`, schema `tenant_application_subscription_window_check` |
| F04 | Registration/subscription mutation is operator/installation-only; runtime has read-only eligibility | FOUND | `v010/03_application_registry_grants.sql`: mutation functions are `SECURITY INVOKER` and **not** granted; 8 read functions `SECURITY DEFINER` granted to `mtmf_runtime` |
| F05 | PR 13-1 restricts `ends_at` to shortening; terminal rows immutable | FOUND | `guard_tenant_application_subscription()`; `validate_subscription_end_change`; `_require_nonterminal` |
| F06 | `SUSPENDED -> ACTIVE` is legal; terminal reactivation is not | FOUND | `_SUBSCRIPTION_TRANSITIONS` (`SUSPENDED→ACTIVE`), `_TERMINAL_SUBSCRIPTION_LIFECYCLES`; Application `_APPLICATION_TRANSITIONS` (`SUSPENDED→ACTIVE`); guard functions |
| F07 | Terminal rows do not block a later current row for the same pair | FOUND | partial unique indexes `..._current_unique` filter only current lifecycles; S4 history retention |
| F08 | Existing HTTP management route is only the PR 19C identity-group-membership mutation | FOUND | `app.py`: `_EVALUATE_ROUTE`, `_MANAGEMENT_MEMBERSHIP_ROUTE`, health routes only |
| F09 | No general Application CRUD or subscription mutation API exists | FOUND | `app.py`, `mtmf_api/management.py` (only `IdentityGroupMembershipAdd*`) |
| F10 | PR 21 proposes a subscription route with incomplete update semantics; `POST /v1/management/tenants` is DEFERRED; STOP-01 open | FOUND | `docs/ONBOARDING_HTTP_CONTRACT.md`, `docs/pr-artifacts/pr-21/PR21_STOP_REPORT.md` |
| F11 | Ordinary actor resolution requires an existing ACTIVE Tenant + memberships + eligible subscription | FOUND | `application/authentication.py` `AuthenticatedActorContextService.resolve` |
| F12 | A stable `subscription_id` / `registration_id` UUID exists | FOUND | `TenantApplicationSubscription.id`, `ApplicationTenantRegistration.id` (`application.py`); PKs in schema |
| F13 | Application has a unique normalized `application_key` | FOUND | `normalize_application_key`; `application_key_unique` |
| F14 | Exact onboarding Action URNs / pre-Tenant entitlement Role are approved | NOT FOUND | `PR21_CONTRACT_REVIEW.md` §1 marks them UNAPPROVED; no seeded Action/Role for onboarding |

## 4. Source-grounded PR 13 lifecycle constraints (normative)

These are the actual permitted transitions from `application.py` and the SQL guards; the amendment MUST NOT contradict them.

**Application** (`guard_application_registry_application` / `_APPLICATION_TRANSITIONS`):
- `ACTIVE → SUSPENDED`, `ACTIVE → RETIRED`, `SUSPENDED → ACTIVE`, `SUSPENDED → RETIRED`.
- `RETIRED` is terminal and rejects any update (including same-state).
- Immutable: `id`, `application_key`, `owner_identity_id`.

**Registration** (`guard_application_tenant_registration` / `_REGISTRATION_TRANSITIONS`):
- `ACTIVE → REVOKED` only. `REVOKED` is terminal and rejects any update.
- Immutable: `id`, `application_id`, `tenant_id`, `created_by_identity_id`, `created_at`.

**Subscription** (`guard_tenant_application_subscription` / `_SUBSCRIPTION_TRANSITIONS`):
- `PENDING → ACTIVE`, `PENDING → CANCELLED`, `ACTIVE → SUSPENDED`, `ACTIVE → CANCELLED`, `ACTIVE → EXPIRED`, `SUSPENDED → ACTIVE`, `SUSPENDED → CANCELLED`, `SUSPENDED → EXPIRED`.
- `CANCELLED` and `EXPIRED` are terminal and reject any update.
- `ends_at` is restrictive only (shorten or set on open-ended; never extend/replace-later/clear).
- Immutable: `id`, `application_id`, `tenant_id`, `created_by_identity_id`, `starts_at`, `created_at`.

**Uniqueness / history:** current registration = `ACTIVE` only; current subscription = `PENDING/ACTIVE/SUSPENDED`. Terminal rows are retained history and do not block a later current row for the same `(application_id, tenant_id)`. This means a **replacement subscription** is a new row with a new UUID after a terminal row; `REVOKED` registration likewise permits a later `ACTIVE` registration. **Policy** for when such replacement is allowed is not yet approved (see `PR21_AMENDMENT01_STOP_REPORT.md`, STOP-05).

**Eligibility** (`eligibility.py`) is fail-closed and requires all of: `ACTIVE` Application, `ACTIVE` Tenant, `ACTIVE` registration for the pair, and eligible in-window `ACTIVE` subscription. It never returns an authorization `ALLOW`.

## 5. Current public HTTP surface

| Method + path | Status | Admission |
| --- | --- | --- |
| `POST /v1/authorization/evaluate` | Implemented (PR 17) | two-token verified actor + eligibility |
| `POST /v1/management/identity-group-memberships` | Implemented (PR 19C) | two-token verified actor + exact Action |
| `GET /health/live`, `GET /health/ready` | Implemented | operational |

No Application-registration, subscription-management, or onboarding route exists.

## 6. Outcome

Repository reality confirms the amendment's assumptions. The architecture
amendment must reconcile with the **actual** transition sets above (notably:
`suspension → active` is legal for both Application and subscription; terminal
states are immutable; replacement is a new row). The pre-Tenant admission
(Option B) requires a new verified-subject seam, which is not present and is
assigned to PR 23/24.
