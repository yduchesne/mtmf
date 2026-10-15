# Onboarding HTTP Contract (PROPOSED — NOT IMPLEMENTED)

> **STATUS: PROPOSED WIRE CONTRACT — NOT IMPLEMENTED.**
> This document specifies the future versioned onboarding management API that
> roadmap PRs 24–25 will implement. **No endpoint below exists.** The only
> management route on `main` (baseline `455ae7a`) is
> `POST /v1/management/identity-group-memberships` (PR 19C). Do not advertise
> any capability here as working.
>
> The admission model is **not approved** (STOP-01 open): see
> `../pr-artifacts/pr-21/PR21_STOP_REPORT.md` and
> [ONBOARDING_ARCHITECTURE.md](ONBOARDING_ARCHITECTURE.md). Action URNs and
> error codes below are proposals, not approved decisions.

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
| `POST /v1/management/tenants/resolve` | resolve authorized key to UUID | PR 24 | already eligible Tenant actor; no global enumeration | PROPOSED |
| `GET /v1/management/tenants/{tenant_id}` | authorized Tenant metadata | PR 24 | exact Tenant context | PROPOSED |
| `POST /v1/management/applications/{application_id}/subscriptions` | subscription | PR 24 | separately authorized management actor | PROPOSED |
| `POST /v1/management/tenants/{tenant_id}/invitations` | create invitation | PR 25 | exact invitation-create authority | PROPOSED |
| `POST /v1/management/invitations/accept` | accept invitation | PR 25 | independently verified pre-membership recipient | PROPOSED |
| `POST /v1/management/invitations/{invitation_id}/revoke` | revoke invitation | PR 25 | exact revoke authority | PROPOSED |
| `POST /v1/management/tenants` | self-service Tenant create | **DEFERRED** | no approved v0.1 public admission; STOP-01 | DEFERRED |

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

## 10. Non-HTTP operator bootstrap

New-Tenant provisioning under STOP-01 Option A is **not** an HTTP route. It uses
a separately authenticated, approved operator provisioning authority outside the
ordinary two-token actor path, invoking the reviewed application use case and
reviewed stored functions. It MUST NOT:

- use the privileged development initializer as a production onboarding
  interface;
- impersonate root or use a root/root-subscription shortcut;
- expose privileged database functions through `mtmf_runtime`;
- accept a caller-supplied actor UUID as authentication.

The exact operator authentication carrier is part of the STOP-01 decision.

## 11. Forward compatibility and change control

- Response fields are additive within `/v1`; an incompatible change requires a
  new version under `VERSIONING.md`.
- New error codes are additive and keep static messages.
- Every future endpoint MUST register its `VerifiedMutationProvenance`
  `target_kind`/exact-Action-URN pairing; unregistered mutations fail closed.
- No endpoint may be documented as implemented before it exists in
  `mtmf-client` and the deployed service.

## References

- [ONBOARDING_ARCHITECTURE.md](ONBOARDING_ARCHITECTURE.md)
- `PR21_SECURITY_MATRIX.md`, `PR21_CONTRACT_REVIEW.md`, `PR21_STOP_REPORT.md`
  in `../pr-artifacts/pr-21/`
- [HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
