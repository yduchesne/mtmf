# PR 13 Application Registry and Tenant Subscription Decisions

## 1. Purpose and authority

PR 12 approved an HTTP-only MTMF PDP/PEP model and recorded security
decision `T6` (one authenticated credential identity maps to exactly one
registered Application; Application–Tenant authorization must be
explicit) and the `T5` precedence chain (service authentication →
verified acting-user context → subscription eligibility → policy
evaluation). PR 13 owns the domain state, persistence, and trusted
internal eligibility logic for the Application/Tenant prerequisites.

`docs/ROADMAP_V01.md` delegated the subscription lifecycle specifics to
PR 13. This register records the decisions that PR 13 implements. When
this register and another document differ on a security question,
`docs/SECURITY_MODEL.md` takes precedence; when this register and a
later explicit PR conflict, the later explicit decision wins.

**Approval status:** these decisions were requested and approved as the
implementation contract for PR 13. A change to any of `S1`–`S8` changes
a security boundary and requires explicit human approval; it must not be
made as an implementation convenience.

## 2. Decisions

| ID | Decision | Notes |
|---|---|---|
| S1 | A registered **Application** is a global, Tenant-independent aggregate. **ApplicationTenantRegistration** and **TenantApplicationSubscription** are separate typed aggregates. | A registration and a subscription are independent security facts; neither implies the other. |
| S2 | Lifecycles: Application `ACTIVE` / `SUSPENDED` / `RETIRED`; Registration `ACTIVE` / `REVOKED`; Subscription `PENDING` / `ACTIVE` / `SUSPENDED` / `CANCELLED` / `EXPIRED`. | Only `ACTIVE` grants eligibility. `RETIRED`, `REVOKED`, `CANCELLED`, and `EXPIRED` are terminal. No implicit reinstatement. |
| S3 | The subscription validity window is the UTC half-open interval `[starts_at, ends_at)`; `starts_at` is required and `ends_at` is optional (unbounded only when absent). Evaluation time is captured once per evaluation and passed explicitly. | `at == starts_at` is in-window; `at == ends_at` is out-of-window. Evaluation time is never taken from an untrusted HTTP caller in PR 13. |
| S4 | At most one *current* registration and one *current* subscription exist per `(application_id, tenant_id)`. Current rows are enforced by partial unique indexes; terminal rows are retained as history. | In-place lifecycle transitions overwrite the current row's lifecycle; the terminal row that leaves the "current" set remains as history. Full append-only transition audit remains deferred to PR 19. |
| S5 | Application/registration/subscription mutation is **operator/installation-privileged only** in PR 13. The restricted `mtmf_runtime` login receives a read-only eligibility surface and never a management mutation grant. | Mirrors the PR 11 TenantManagementGroup posture; avoids recreating the PR 10/11 shared-runtime-login trust problem before PR 14 supplies a verified actor boundary. |
| S6 | No implicit entitlement: creating a registration never creates or activates a subscription; creating a subscription never registers the Application; positive eligibility requires an `ACTIVE` Application, an `ACTIVE` tenant, an `ACTIVE` registration, and an eligible in-window `ACTIVE` subscription. The ROOT tenant receives no automatic exception. | No fact substitutes for another. |
| S7 | Subscription expiry is **time-derived**: a subscription is ineligible immediately at `ends_at` without waiting for an asynchronous status transition. `EXPIRED` remains an optional terminal administrative state and is not required for expiry enforcement. | No stale grants due to a delayed background job. |
| S8 | Global Application creation/transition and Tenant registration/subscription creation/transition are operator-controlled writes for PR 13. There is no runtime public management route. | Later verified-actor management use cases require an explicit Action-policy review and the PR 14 trusted boundary. |

## 3. Consequences

- `Application` has immutable internal identity and a stable unique
  normalized application key; it is never a Principal, Identity, Tenant,
  Organization, Group, Role, Permission, or OAuth credential.
- A subscription is a Tenant–Application fact. Organizations do not
  independently subscribe in v0.1; Organization restriction remains an
  authorization-time concern once a policy model exists.
- No Role, Permission, ROOT authority, Tenant stewardship, management
  group coverage, or ordinary membership overrides an ineligible
  prerequisite.
- The internal eligibility evaluator returns a typed eligibility result
  and reason; it never returns an `AuthorizationDecision` and never
  issues an `ALLOW`.
- `PersistenceError`/infrastructure failures propagate distinctly and
  are never converted into an eligibility reason.

## 4. Implementation notes

- **No privileged Python management boundary is invented.** The existing
  `PostgresMtmfSpi` provider is bound to the restricted `mtmf_runtime`
  login and there is no separate privileged execution SPI. PR 13 therefore
  implements registry mutation as owner-owned `SECURITY INVOKER` stored
  functions that are never granted to `mtmf_runtime` and are exercised
  through an operator/migrator connection, mirroring the PR 11
  TenantManagementGroup posture. Inventing a new privileged provider
  boundary, or granting the runtime login broad write access, is out of
  scope (PR 13 STOP conditions 2/3).
- **No request body can override an authenticated Application binding.**
  PR 13 exposes no HTTP/DTO/CLI entry point; the read-only eligibility
  service takes explicit Application/Tenant identifiers and performs no
  authentication. PR 14 owns deriving the Application from verified
  credentials.
- **Current-row uniqueness is enforced by partial unique indexes**
  (`application_tenant_registration` where `lifecycle = ACTIVE` and
  `tenant_application_subscription` where `lifecycle IN (PENDING, ACTIVE,
  SUSPENDED)`) so terminal rows accumulate as history while at most one
  current row exists per pair.

## 5. Deferred to later PRs

- Mapping an authenticated OAuth credential to exactly one registered
  Application (PR 14).
- Dedicated Application management `Action`s and public management
  policy (PR 14/15).
- Append-only, externally queryable subscription lifecycle transition
  audit (PR 19).
- Billing, metering, quotas, Organization subscriptions, and external
  IdP integration are out of scope for v0.1.
