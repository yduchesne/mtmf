# Onboarding HTTP Contract (APPROVED DESIGN — NOT IMPLEMENTED)

> **STATUS: APPROVED DESIGN WIRE CONTRACT — NOT IMPLEMENTED, NOT DEPLOYED.**
> This document specifies the future versioned onboarding management API that
> roadmap PRs 24–25 will implement. **No endpoint below exists.** The only
> management route on `main` (baseline `455ae7a`) is
> `POST /v1/management/identity-group-memberships` (PR 19C). Do not advertise
> any capability here as working.
>
> **All PR 21 design STOPs are CLOSED by recorded human decisions**
> (STOP-01 D8; STOP-02/04/05/06 P02/P04/P05/P06; **STOP-03 by
> `PR21-STOP03-APPROVAL-2026-10-15`**). The exact Action/Permission/Role
> literals are approved **as design** and listed in
> `pr-artifacts/pr-21/PR21_AMENDMENT02_ACTION_MANIFEST.md`; provenance is
> `pr-artifacts/pr-21/PR21_AMENDMENT03_HUMAN_APPROVAL.md`. **Nothing here is
> deployed or implemented.**
>
> **Operator prerequisite (NOT IMPLEMENTED):** Application/registration/
> entitlement/credential routes are **OPERATOR-EXECUTION GATED** (see §16.7)
> until the named **PR 24P** prerequisite implements operator sign-in,
> SYSTEM-scope assignment, global-target authorization, and a privileged
> audited execution adapter without `mtmf_runtime` privileged grants. No
> Tenant-bound Authorizer bypass and no root impersonation.
>
> **Dependency status:** PR 22A's operator-only entitlement persistence (`0014`)
> is merged, but its positive quota is not consumed and no onboarding HTTP
> endpoint is implemented. PR 23 (verified subject/steward participant) and
> PR 24P (approved privileged execution) must precede PR 22B (atomic composite),
> which must precede PR 24's onboarding HTTP exposure. The PR 24P topology
> approval gate remains open.

This document uses the existing `mtmf-api` detached DTO and static
`ApiErrorResponse` conventions. It introduces no DTO class, route, or code in
PR 21.

## 1. Common wire rules

- **Transport:** HTTPS, versioned `/v1/...`. Strict bounded canonical JSON;
  unknown fields, duplicate object members, nil UUIDs, non-finite numbers, and
  unsupported enums fail whole-request validation.
- **Headers (ordinary already-member management):**
  `Authorization: Bearer <service-access-token>` **and**
  `X-MTMF-User-Authorization: Bearer <user-access-token>`. The two tokens MUST
  belong to the same OAuth client (existing cross-client rule).
- **Operator provisioning is not implicitly exposed by those two headers.** A
  separately verified operator provisioning authority (STOP-01 Option A) would
  use its own approved admission; the DTO/body never carries an actor, Action,
  Role, Permission, audit field, or policy decision.
- **Response:** `Cache-Control: no-store`; stable authoritative MTMF UUIDs.
  Never return a success body or usable snapshot on failure.
- **Errors:** the static PR 15 envelope. The onboarding contract additionally
  requires additive `NOT_FOUND` (404, opaque, no enumeration), `CONFLICT` (409),
  and `GONE` (410, only if safe to disclose). These codes do **not** yet exist
  in `mtmf_api.errors`; PR 24/25 own the additive change.

### Existing error codes reused

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` | malformed/duplicate/unknown field, nil UUID, bad enum |
| 401 | `UNAUTHENTICATED` | invalid/missing service token |
| 403 | `UNTRUSTED_ACTOR` | acting user/tenant verification failed |
| 403 | `INELIGIBLE_APPLICATION` | Application/subscription not eligible |
| 403 | `FORBIDDEN` | authenticated actor denied by exact Action/scope/guard |
| 413 | `REQUEST_TOO_LARGE` | body exceeds the byte bound |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | wrong content type |
| 429 | `RATE_LIMITED` | request rate exceeded |
| 503 | `DEPENDENCY_UNAVAILABLE` | IdP/database unavailable |
| 500 | `INTERNAL_ERROR` | unexpected fault |

## 2. Endpoint summary

| Method + path | Operation | Owner | Admission | Status |
| --- | --- | --- | --- | --- |
| `POST /v1/onboarding/resolve-or-provision` | first-registration resolve-or-provision | PR 24 (+PR 23 seam) | verified service + user proof + pre-Tenant entitlement (Option B) | PROPOSED |
| `POST /v1/management/tenants/resolve` | resolve authorized key to UUID | PR 24 | already eligible Tenant actor; no global enumeration | PROPOSED |
| `GET /v1/management/tenants/{tenant_id}` | authorized Tenant metadata | PR 24 | exact Tenant context | PROPOSED |
| `POST /v1/management/applications` | register global Application | PR 24 | separately authorized system management authority | PROPOSED |
| `GET /v1/management/applications/{application_id}` | inspect Application | PR 24 | authorized inspect | PROPOSED |
| `PATCH /v1/management/applications/{application_id}` | Application lifecycle | PR 24 | system management authority | PROPOSED |
| `POST /v1/management/applications/{application_id}/registrations` | Application–Tenant registration | PR 24 | STOP-04 authority | PROPOSED |
| `GET`/`PATCH /v1/management/applications/{application_id}/registrations/{registration_id}` | inspect/revoke registration | PR 24 | STOP-04 authority | PROPOSED |
| `POST /v1/management/applications/{application_id}/subscriptions` | create subscription | PR 24 | exact Tenant authority (D6) | PROPOSED |
| `GET /v1/management/applications/{application_id}/subscriptions[/{subscription_id}]` | inspect/list subscriptions | PR 24 | exact Tenant authority; bounded; no enumeration | PROPOSED |
| `PATCH /v1/management/applications/{application_id}/subscriptions/{subscription_id}` | suspend/cancel subscription | PR 24 | exact Tenant authority; CAS | PROPOSED |
| `POST /v1/management/tenants/{tenant_id}/invitations` | create invitation | PR 25 | exact invitation-create authority | PROPOSED |
| `POST /v1/management/invitations/accept` | accept invitation | PR 25 | independently verified pre-membership recipient | PROPOSED |
| `POST /v1/management/invitations/{invitation_id}/revoke` | revoke invitation | PR 25 | exact revoke authority | PROPOSED |
| `POST /v1/management/tenants` | self-service Tenant create | **DEFERRED** | no separate public route; superseded by `resolve-or-provision` (Option B) | DEFERRED |

## 3. `POST /v1/management/tenants/resolve`

- **Owner:** PR 24. **Admission:** already eligible Tenant actor; the request
  carries explicit Tenant context and the actor must be authorized for the
  exact resolve Action. No global enumeration.
- **Request fields:**

  | Field | Type | Required | Limits |
  | --- | --- | --- | --- |
  | `tenant_id` | canonical UUID | yes | not nil |
  | `tenant_key` | string | yes | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, case-sensitive |

- **Response:** `200` `{"tenant_id","tenant_key","name","lifecycle"}`; `name` is
  display metadata; `lifecycle` is the `TenantLifecycle` enum.
- **Idempotency:** read-only; no idempotency key.
- **Expected errors:** `400`, `401`, `403`, `404` (invisible/mismatched target,
  no existence oracle), `429`, `503`.
- **Example:** `{"tenant_id":"11111111-1111-4111-8111-111111111111","tenant_key":"acme"}` → `200`.

## 4. `GET /v1/management/tenants/{tenant_id}`

- **Owner:** PR 24. **Admission:** exact Tenant context; authorized Tenant
  metadata read.
- **Path:** `tenant_id` canonical UUID, not nil.
- **Response:** `200` `{"tenant_id","tenant_key","name","lifecycle"}`.
- **Idempotency:** read-only.
- **Expected errors:** `401`, `403`, `404`, `429`, `503`.
- **Visibility:** an unauthorized or invisible Tenant returns the same opaque
  `404`; no metadata fingerprinting.

## 5. `POST /v1/management/applications/{application_id}/subscriptions`

- **Owner:** PR 24. **Admission:** separately authorized management actor
  (operator or existing eligible Tenant management authority); registration and
  subscription are distinct; SYSTEM/root is rejected.
- **Path:** `application_id` canonical UUID, not nil.
- **Request fields:**

  | Field | Type | Required | Limits |
  | --- | --- | --- | --- |
  | `tenant_id` | canonical UUID | yes | ordinary ACTIVE Tenant; never SYSTEM/root |
  | `idempotency_key` | canonical UUID | yes | not nil; scoped per authenticated actor + operation |
  | `requested_state` | enum | yes | `ACTIVE` (initial); `SUSPENDED`/`CANCELLED` via update semantics owned by PR 24 |

- **Response:** `201` `{"application_id","tenant_id","state","created":true}`;
  `200` with `"created":false` for an idempotent replay.
- **Idempotency scope:** `(verified actor, "subscription.manage", idempotency_key)`
  + canonical request fingerprint. Same key/different fingerprint → `409`.
  Incompatible existing subscription → `409`; never a silent repair.
- **Expected errors:** `400`, `401`, `403`, `404`, `409`, `429`, `503`.
- **Example request:** `{"tenant_id":"...","idempotency_key":"...","requested_state":"ACTIVE"}`.
- **Amendment 01 refinement:** §14.1 supersedes this sketch with the required
  `starts_at`/optional `ends_at` window and a stable `subscription_id` response.
  Registration is a separate fact (§13); an `ACTIVE` subscription without an
  `ACTIVE` registration is not eligible.

## 6. `POST /v1/management/tenants/{tenant_id}/invitations`

- **Owner:** PR 25. **Admission:** verified steward/administrator holding the
  exact invitation-create authority in the exact Tenant.
- **Path:** `tenant_id` canonical UUID, not nil.
- **Request fields:**

  | Field | Type | Required | Limits |
  | --- | --- | --- | --- |
  | `tenant_id` | canonical UUID | yes | must equal the path Tenant; ordinary ACTIVE Tenant |
  | `idempotency_key` | canonical UUID | yes | not nil |
  | `recipient_issuer` | string | yes | trusted issuer identifier; identifies an **intended** recipient, not proof |
  | `recipient_subject` | string | yes | opaque subject; never an email as identity proof |
  | `expires_at` | RFC3339 UTC | yes | now + 15 minutes to now + 7 days |
  | `role_urn` | string | yes | an **approved exact** Tenant Role URN; never ROOT, never arbitrary Permissions |

- **Response:** `201` `{"invitation_id","tenant_id","status":"PENDING","expires_at"}`.
- **Idempotency scope:** `(verified actor, "invitation.create", idempotency_key)`.
- **Expected errors:** `400`, `401`, `403` (including unapproved Role),
  `404`, `409`, `429`, `503`.
- **Visibility:** creating an invitation grants **no** membership.

## 7. `POST /v1/management/invitations/accept`

- **Owner:** PR 25. **Admission:** a **separate verified-token-only
  pre-membership admission seam**. The recipient is not yet a Tenant member, so
  this route MUST NOT call ordinary already-member actor resolution. It requires
  independent user proof (a verified signed user token) **plus** a single-use
  capability.
- **Request fields:**

  | Field | Type | Required | Limits |
  | --- | --- | --- | --- |
  | `invitation_id` | canonical UUID | yes | not nil |
  | `acceptance_token` | opaque string | yes | random high-entropy; hashed at rest; never logged |
  | `idempotency_key` | canonical UUID | yes | not nil |

- **Response:** `201`
  `{"tenant_id","principal_id","identity_id","membership_created":true,"status":"ACCEPTED"}`.
- **Capability rules:** random high-entropy; hashed at rest; never logged;
  bounded to exactly one invitation and its expiry (15 minutes–7 days);
  insufficient without independently verified user proof; single-use.
- **Idempotency scope:** `(verified recipient subject, "invitation.accept",
  idempotency_key)`. A replay with the same fingerprint returns the same IDs
  and does not create a second membership.
- **Expected errors:** `400`, `401`, `403` (wrong verified recipient),
  `404`, `409` (already accepted with a different fingerprint), `410`
  (expired/revoked, only if safe to disclose), `429`, `503`.
- **Visibility:** acceptance derives the actual recipient from verified signed
  token claims; the request carries no recipient identity.

## 8. `POST /v1/management/invitations/{invitation_id}/revoke`

- **Owner:** PR 25. **Admission:** exact revoke authority in the invitation's
  Tenant.
- **Path:** `invitation_id` canonical UUID, not nil.
- **Request fields:** `{"tenant_id": UUID, "idempotency_key": UUID}` (both
  required).
- **Response:** `200` `{"invitation_id","tenant_id","status":"REVOKED"}`.
- **Idempotency scope:** `(verified actor, "invitation.revoke", idempotency_key)`.
- **Expected errors:** `400`, `401`, `403`, `404`, `409` (already terminal with
  a changed fingerprint), `410`, `429`, `503`.

## 9. `POST /v1/management/tenants` — DEFERRED

There is **no approved v0.1 public admission** for self-service Tenant
creation. This route is listed only to record the deferred roadmap objective.
It MUST NOT be implemented until STOP-01 is resolved and the corresponding
authoritative documentation change is approved. It is not an operator
bootstrap path.

## 10. Non-HTTP admission and operator management

### 10.1 Pre-Tenant admission (Option B — approved direction)

First registration is served by the HTTP `ResolveOrProvisionTenant` operation
(§11), not by ordinary already-member actor resolution. Internally the use case
independently verifies the Application service token, the user proof, and the
pre-Tenant onboarding entitlement (STOP-02) **before** the UoW, then performs
Identity resolution and, only for a truly new global Identity with no eligible
Tenant, an atomic initial provisioning. It MUST NOT call
`AuthenticatedActorContextService.resolve` for an unknown Tenant, impersonate
root, use the privileged development initializer as a production onboarding
interface, expose privileged database functions through `mtmf_runtime`, or
accept a caller-supplied actor UUID as authentication.

### 10.2 Operator/system management

Application registration, Application–Tenant registration, and subscription
mutation remain operator/installation-privileged in PR 13. The future approved
management authority for those operations is **STOP-04** (registration) and the
system management authority for Application records; credential bindings are a
separate boundary (**STOP-06**). These operations are subject to the same
authentication, exact-Action authorization, and atomic audit requirements, not
to the pre-Tenant branch.

## 11. `POST /v1/onboarding/resolve-or-provision`

- **Owner:** PR 24 (with the PR 23 verified-subject seam). **Status:** PROPOSED.
- **Admission:** verified Application service token + independently verified
  user proof + pre-Tenant onboarding entitlement (STOP-02). This is **not** the
  ordinary already-member actor path.
- **Request fields:**

  | Field | Type | Required | Limits |
  | --- | --- | --- | --- |
  | `idempotency_key` | canonical UUID | yes | not nil |
  | `requested_tenant_id` | canonical UUID | no | selection follow-up only; never identity proof |
  | `requested_tenant_key` | string | no | `tenant_key` grammar; never identity proof |
  | `requested_display_name` | string | no | bounded; display metadata only, non-unique |

- **Outcomes (stable typed response):** `CREATED`, `REUSED`,
  `SELECTION_REQUIRED`, `SUBSCRIPTION_REQUIRED`, `ONBOARDING_REQUIRED`; denials
  use the static error envelope. Every success/reuse body returns authoritative
  `tenant_id`, `principal_id`, `identity_id`, and the Application eligibility
  state; `CREATED` additionally returns the initial registration/subscription
  identifiers.
- **Follow-up:** `SELECTION_REQUIRED` is completed by repeating the operation
  with `requested_tenant_id`; the same operation may return a read-only outcome
  (`REUSED`/`SELECTION_REQUIRED`/`SUBSCRIPTION_REQUIRED`/`ONBOARDING_REQUIRED`)
  without creating anything.
- **Idempotency scope:** `(verified Application, verified subject,
  "onboarding.resolve_or_provision", idempotency_key)` + canonical fingerprint.
  Same key/different fingerprint → `409`. A replay returns the same IDs and
  creates nothing new.
- **Expected errors:** `400`, `401`, `403` (no entitlement / ineligible /
  ineligible Tenant), `404` (invisible; no enumeration), `409`, `429`, `503`.
- **Visibility:** never leak inaccessible Tenant names/IDs; a user with an
  existing Tenant but no calling-Application subscription is
  `SUBSCRIPTION_REQUIRED`, never `REUSED`.
- **Example:** `{"idempotency_key":"..."}` → `201`
  `{"outcome":"CREATED","tenant_id":"...","principal_id":"...","identity_id":"..."}`.

## 12. Application management

All routes below are PROPOSED / NOT IMPLEMENTED and require a separately
authorized **system management** authority — never self-registration through a
caller service token.

### 12.1 `POST /v1/management/applications`

- Request: `application_key` (normalized grammar), `name` (bounded),
  `idempotency_key` (UUID), optional `extension` (JSON object).
- Response `201`: `{application_id, application_key, lifecycle:"ACTIVE", created:true}`.
- Idempotency scope: `(verified system actor, "application.create", idempotency_key)`.
- Errors: `400`, `401`, `403`, `409` (duplicate key/fingerprint), `429`, `503`.
- **Credential boundary:** creating an Application does **not** create service
  credentials; binding management is a separate security-sensitive operation
  (STOP-06).

### 12.2 `GET /v1/management/applications/{application_id}`

- Authorized inspect; response `{application_id, application_key, name,
  lifecycle}`. Errors `401`, `403`, `404`, `429`, `503`.

### 12.3 `PATCH /v1/management/applications/{application_id}`

- Body: `{lifecycle, version}`; `lifecycle` ∈ `{SUSPENDED, RETIRED, ACTIVE}` and
  only the **source-permitted** transitions from §17.5 (`ACTIVE↔SUSPENDED`,
  `ACTIVE/SUSPENDED→RETIRED`). `RETIRED` is terminal.
- Compare-and-swap on `version`; `409` on stale version or illegal transition.
- No physical `DELETE` in v0.1. Errors `400`, `401`, `403`, `404`, `409`, `429`, `503`.
- Audit: one append-only mutation record.

## 13. Application–Tenant registration

- **Owner:** PR 24. Registration `ACTIVE→REVOKED` (`REVOKED` terminal);
  eligibility requires an `ACTIVE` registration **and** an `ACTIVE` in-window
  subscription. A subscription row alone is insufficient.
- **Proposed routes:**
  - `POST /v1/management/applications/{application_id}/registrations` —
    `{tenant_id, idempotency_key}` → `201 {registration_id, application_id, tenant_id, lifecycle:"ACTIVE"}`.
  - `GET /v1/management/applications/{application_id}/registrations/{registration_id}`
    — authorized inspect.
  - `PATCH .../registrations/{registration_id}` — `{lifecycle:"REVOKED", version}`
    only; `REVOKED` terminal.
- **Authority:** PR 13 registration mutation is operator-only. Whether a Tenant
  administrator may be delegated registration authority, or whether the initial
  registration is atomically composed with subscription creation under one
  reviewed Action, is **STOP-04**. Tenant Administrator privileges are not
  silently broadened.
- Registration `REVOKED` is distinct from subscription `CANCELLED`.

## 14. Subscription management

### 14.1 `POST /v1/management/applications/{application_id}/subscriptions`

Existing proposed route, retained. Creates a subscription for an **existing**
ordinary Tenant under exact Tenant authority (or an approved operator/system
path). Body: `{tenant_id, idempotency_key, requested_state:"ACTIVE", starts_at,
ends_at?}`. `starts_at` required, timezone-aware; `ends_at` optional and
strictly after `starts_at`. Response `201 {subscription_id, application_id,
 tenant_id, state, starts_at, ends_at, created:true}`; `200 created:false` on
replay. Idempotency `(verified actor, "subscription.create", idempotency_key)`.
Errors `400`, `401`, `403`, `404`, `409`, `429`, `503`.

### 14.2 `GET /v1/management/applications/{application_id}/subscriptions` and `.../{subscription_id}`

- Authorized lookup/list with **bounded pagination**; no cross-Tenant
  enumeration; exact-ID GET supported. Invisible targets return opaque `404`.
- Errors `401`, `403`, `404`, `429`, `503`.

### 14.3 `PATCH /v1/management/applications/{application_id}/subscriptions/{subscription_id}`

- Body: `{lifecycle, ends_at?, version}`. Only source-permitted transitions
  from §17.5 (`PENDING→ACTIVE/CANCELLED`; `ACTIVE→SUSPENDED/CANCELLED/EXPIRED`;
  `SUSPENDED→ACTIVE/CANCELLED/EXPIRED`). `CANCELLED`/`EXPIRED` terminal.
  `ends_at` is restrictive only (shorten or set on open-ended).
- Compare-and-swap on `version`; `409` on stale version/illegal transition.
- No `DELETE`/hard-deletion. Terminal replacement is a **new row with a new
  UUID**; whether/when replacement is allowed is **STOP-05** and is not
  implemented.
- Errors `400`, `401`, `403`, `404`, `409`, `429`, `503`; one atomic audit row.

### 14.4 Registration/subscription composite authority

If a Tenant administrator can authorize a subscription but registration
requires system authority, the workflow MUST use either a separately authorized
operator step or an approved composite admission (STOP-04). It MUST NOT silently
broaden Tenant Administrator privileges.

## 15. Amendment 01 authorization matrix

All Actions below are **UNAPPROVED candidates** (STOP-03). No wildcard and no
invented built-in Role grant.

| Operation | Verified Application | Verified acting user | Existing Tenant context | Candidate exact Action (UNAPPROVED) | Authority owner | Operator/entitlement | Audit |
|---|---|---|---|---|---|---|---|
| `resolve-or-provision` (new Identity, new Tenant) | required | required | none | `urn:mtmf:iam:actions:system:tenant:provision-object` | pre-Tenant entitlement (STOP-02) | entitlement; system grants it | yes |
| `resolve-or-provision` (existing Identity, existing Tenant) | required | required | required for REUSED/SELECTION | `urn:mtmf:iam:actions:system:tenant:get-object` (reused) | ordinary actor / entitlement for the pre-Tenant branch | entitlement only for the create branch | yes |
| Application create/inspect/suspend/retire | required (system) | — | none | `urn:mtmf:iam:actions:system:application:create-object` / `update-object` | system management Role (STOP-03) | operator/system | yes |
| Registration create/revoke | required | — | Tenant exact | `urn:mtmf:iam:actions:system:application-tenant-registration:add-object` / `revoke-object` | STOP-04 | operator/system | yes |
| Subscription create | required | required | Tenant exact | `urn:mtmf:iam:actions:system:application-subscription:manage-object` | Tenant administrator or operator | independent approval (D6) | yes |
| Subscription suspend/cancel | required | required | Tenant exact | same as subscribe | Tenant administrator or operator | independent approval (D6) | yes |
| Invitation acceptance | required | required (pre-membership recipient) | invited Tenant only | `urn:mtmf:iam:actions:system:tenant-invitation:accept-object` | PR 25 pre-membership seam | n/a | yes |

## 16. Amendment 02 refinements — entitlement, registration, replacement, credential separation

Normative for PRs 22–26. Exact Action/Role literals remain STOP-03 open
(`pr-artifacts/pr-21/PR21_AMENDMENT02_ACTION_MANIFEST.md`).

### 16.1 `resolve-or-provision` trust, admission, and lifecycle

- **Required proofs:** verified Application service token **and** independently
  verified user token; denied without either. Identity is derived from verified
  claims, never from body UUID/email.
- **Ordering (no IdP/network inside the UoW):** verify service token and user
  proof outside the UoW → resolve global Identity/Principal by
  `(issuer, subject)` → if absent, require an `ACTIVE` Application onboarding
  entitlement and reserve quota → one serialized UoW creates the new
  Identity/Principal/Tenant/memberships/steward **and the exact initial
  registration + subscription** → activate → atomic audit → commit.
- **Entitlement:** required only for the new-Identity branch; not required for a
  read-only reuse/selection/subscription-required/onboarding-required outcome.
  Revocation stops new provisioning and does not retroactively revoke Tenants.
- **Outcomes and mutability:** `CREATED` (create), `REUSED` (no mutation),
  `SELECTION_REQUIRED` (no mutation; authorized choices only), `SUBSCRIPTION_REQUIRED`
  (no mutation; no auto-subscription), `ONBOARDING_REQUIRED` (no auto-create).
- **Idempotency:** scope `(verified Application, verified subject, "onboarding.resolve_or_provision", idempotency_key)` + durable fingerprint; replay returns the same IDs; a changed fingerprint is `409`.
- **Errors/visibility:** `400/401/403/404/409/429/503`; never leak inaccessible Tenant names/IDs; an existing Tenant without the calling-Application subscription is `SUBSCRIPTION_REQUIRED`, never `REUSED`.

### 16.2 Application management

- Requires separately authorized **system management** authority; never
  self-registration via a caller service token.
- **Credential binding is separate** and not implied by create/PATCH; no raw
  client secret appears in any Application request or response; credential
  administration is a separately gated contract (§16.5).
- Suspend/resume follow PR 13 in-place transitions; retire is terminal.
  Suspension/retirement immediately fails active-Application eligibility even if
  an old credential remains valid.

### 16.3 Application–Tenant registration (P04)

- Create/revoke/replacement requires **system management** authority. Tenant
  Administrators have no registration authority.
- Subscription requires an `ACTIVE` registration; registration alone does not
  activate a subscription; no implicit Application self-registration.
- **Initial-Tenant exception:** the entitled onboarding transaction creates the
  exact initial registration+subscription, bound to that Application and new
  Tenant, audited with the entitlement and both records.
- `REVOKED` is terminal; replacement is a new registration UUID created by
  system authority.

### 16.4 Subscription management and replacement (P05)

- A **Tenant Administrator** may create/resume/suspend/cancel/replace a
  subscription for its own Tenant only through an approved exact Permission,
  with existing dominance, **and only when an `ACTIVE` registration exists**; a
  system operator may do the same. No silent subscription.
- In-place `SUSPENDED→ACTIVE` is a resume, not replacement. `CANCELLED`/`EXPIRED`
  are terminal; replacement is a **new subscription UUID** with predecessor
  reference, reason, actor, and correlation ID, separately authorized and
  idempotent. `ends_at` remains restrictive-only.
- `PATCH` uses compare-and-swap/version; stale version or illegal transition is
  `409`. No physical DELETE.

### 16.5 Credential binding (separate, gated — P06)

No credential-binding endpoint is included in this contract. If the approved
PR 14 trust model supports it, PR 24 defines a separate system-authorized
contract for `(issuer, client_id)→Application` add/revoke with immutable
provenance, conflict detection, audit, and no secret exposure; otherwise a
separately named prerequisite with an exact owner is recorded. Application
CRUD never mints credentials.

### 16.6 Read/list authorization and non-enumeration

Registration and subscription inspect/list are bounded and scoped to the
verified actor's authorized Tenant(s); invisible targets return the same opaque
result; no cross-Tenant enumeration; no metadata fingerprinting.

### 16.7 Execution status — proposed routes vs currently executable operations

The routes in this contract are **PROPOSED HTTP routes**, not executable
operations. As of branch tip `8c5937d`:

| Operation group | Status |
| --- | --- |
| Application create/get/suspend/resume/retire; registration create/get/revoke; entitlement grant/revoke/get; credential-binding add/revoke | **NOT IMPLEMENTED / OPERATOR-EXECUTION GATED** — no operator sign-in, SYSTEM-scope assignment, global-target authorization, or privileged execution adapter exists; PR 24 (or a named prerequisite) owns the reviewed bridge. |
| Subscription create/get/suspend/resume/cancel | **NOT IMPLEMENTED** — requires a verified actor with the exact Tenant-scoped grant; PR 24. |
| Invitation create/accept/revoke | **NOT IMPLEMENTED** — PR 25. |
| `resolve-or-provision` | **NOT IMPLEMENTED** — PR 24 transport + PR 23 admission seam. |

No route is exposed merely because its Action URN is proposed or approved.
Privileged registry/entitlement/credential mutations remain privileged
administrative operations and are **never** granted to `mtmf_runtime`. The
exact proposed Role partition and operator contract are in
`pr-artifacts/pr-21/PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md` and
`PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md` (status: PROPOSED — AWAITING
HUMAN APPROVAL).

## 17. Forward compatibility and change control

- Response fields are additive within `/v1`; an incompatible change requires a
  new version under `VERSIONING.md`.
- New error codes are additive and keep static messages.
- Every future endpoint MUST register its `VerifiedMutationProvenance`
  `target_kind`/exact-Action-URN pairing; unregistered mutations fail closed.
- No endpoint may be documented as implemented before it exists in
  `mtmf-client` and the deployed service.

## References

- [ONBOARDING_ARCHITECTURE.md](ONBOARDING_ARCHITECTURE.md)
- `pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md`, `PR21_CONTRACT_REVIEW.md`,
  `PR21_STOP_REPORT.md`
- `pr-artifacts/pr-21/PR21_AMENDMENT01_AUTHORIZATION_MATRIX.md`,
  `PR21_AMENDMENT01_STOP_REPORT.md`, `PR21_AMENDMENT01_DECISION_RECORD.md`
- `pr-artifacts/pr-21/PR21_AMENDMENT02_ACTION_MANIFEST.md`,
  `PR21_AMENDMENT02_AUTHORIZATION_MATRIX.md`,
  `PR21_AMENDMENT02_STOP_REPORT.md`,
  `PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md`,
  `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`,
  `PR21_AMENDMENT02_STOP03_SECURITY_CASES.md`
- [HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
