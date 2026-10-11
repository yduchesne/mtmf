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

**Approval provenance:** `S1`–`S8` were **proposed and implemented in
PR 13**; a prior human approval was **not recorded**. Do not treat their
presence in this register, or the PR 13 implementation, as human
approval. PR 13-1 reviewer approval, if granted, adopts the `S1`–`S8`
architecture and the separately specified `A1` mutation refinement. A
change to any of `S1`–`S8` changes a security boundary and requires
explicit human approval; it must not be made as an implementation
convenience.

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

### A1 — Subscription mutation hardening (PR 13-1)

**Status:** `ADOPTED FOR IMPLEMENTATION` by the PR 13-1 implementation
request on 2026-10-11; an explicit reviewer approval reference/date is to
be recorded when PR #44 is reviewed. `A1` refines `S3`/`S7` for the
mutation boundary only; it does not rewrite their recorded history.

`A1` is a security-sensitive refinement to `S3`/`S7`. It defines the
**only** legal way an existing subscription's end date may change, and it
makes terminal rows fully immutable:

- `starts_at` is immutable after creation.
- `ends_at` may be supplied at creation as a timezone-aware instant
  strictly later than `starts_at`, or be absent (open-ended).
- For a **nonterminal** subscription (`PENDING`, `ACTIVE`, `SUSPENDED`),
  an operator may **shorten** an existing finite end date or set a finite
  end date on an open-ended subscription, provided the new value is
  strictly after `starts_at` and strictly earlier than the existing finite
  end date, if any. This is a restrictive change only.
- **Never extend** a finite end date, **never clear** a finite end date to
  `NULL`, and never replace a finite end date with a later instant.
- A `CANCELLED` or `EXPIRED` subscription is terminal: no update of any
  column, including a same-state update or `ends_at`. An Application
  `RETIRED` or registration `REVOKED` is likewise terminal; its same-state
  updates must not mutate any field.
- A lifecycle transition and a shortening may be combined atomically
  **only if** both are independently valid and the source state is
  nonterminal. A same-state operation may shorten the window but must not
  be used to bypass lifecycle rules, and a true no-op must not fabricate a
  transition or change eligibility.
- Any change to `ends_at` is operator-only and never available to
  `mtmf_runtime`. Existing committed revocations and expirations continue
  to deny fresh eligibility evaluations.
- Renewal or replacement with a later/absent end date is **out of scope
  for PR 13-1**. To renew, create a new subscription only after the prior
  current subscription becomes terminal, subject to the existing
  unique-current-row constraint. The old row is never silently forced
  terminal.

The database guard is the authoritative last line of defense: it compares
`NEW.ends_at` to the locked current row's `OLD.ends_at` for both the
stored function and a direct owner `UPDATE`. The Python domain exposes the
same rules through `transition_to`, `shorten_end_to`, and
`transition_and_shorten_to`.

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
- **The end-date mutation contract is shared by the domain and the
database.** The pure validator `validate_subscription_end_change`
  governs creation-adjacent amendments; the `guard_tenant_application_subscription`
  trigger governs persisted updates (including direct owner `UPDATE`)
  against the locked row. The in-memory provider mirrors the same
  terminal/lifecycle/end-date rules so the two providers stay
  behaviorally equivalent.
- **Migration safety.** Revision `0010` and packaged `sql/v010` remained
  unmerged and were the only consumer of these guard bodies when PR 13-1
  hardened them, so they were edited in place rather than superseded by an
  additive revision. No `v001`–`v009` resource was modified.

## 5. Deferred to later PRs

- Mapping an authenticated OAuth credential to exactly one registered
  Application (PR 14).
- Dedicated Application management `Action`s and public management
  policy (PR 14/15).
- Append-only, externally queryable subscription lifecycle transition
  audit (PR 19).
- Billing, metering, quotas, Organization subscriptions, and external
  IdP integration are out of scope for v0.1.
