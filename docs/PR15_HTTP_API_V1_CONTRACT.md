# PR 15 — MTMF v1 HTTP batch authorization contract (normative)

> **STATUS: NORMATIVE CONTRACT — CONTRACT-ONLY PACKAGE.**
> This document freezes the public v1 request/response/error wire shapes
> implemented by `packages/mtmf-api`. The HTTP route and its runtime
> behavior are **not** implemented: `POST /v1/authorization/evaluate`
> belongs to PR 17, batch evaluation belongs to PR 16, and scoped
> snapshots belong to PR 18. `mtmf-api` is a data contract, not a server,
> and never makes an authorization decision.

Decision provenance: [PR 15 API contract decisions](PR15_API_CONTRACT_DECISIONS.md).
Semantic sources: [HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
C01–C11, [PR 12 Integration Security Decisions](PR12_INTEGRATION_SECURITY_DECISIONS.md),
[Security Model](SECURITY_MODEL.md), [Authorization](AUTHORIZATION.md),
[Architecture](ARCHITECTURE.md).

## 1. Purpose and dominant invariant

MTMF is the authoritative Policy Decision Point (PDP). A consuming
application is a Policy Enforcement Point (PEP). This document defines
the detached, versioned data contract exchanged between them.

**Invariant.** A request/response is a strictly validated, detached,
versioned data value. It cannot confer identity, create an authorization
grant, or expose MTMF implementation types. Every accepted request
occurrence receives exactly one ordered decision; no failure mode
produces an `ALLOW`.

## 2. Endpoint and versioning

| Property | Value |
| --- | --- |
| Method and route (PR 17) | `POST /v1/authorization/evaluate` |
| Media type (PR 17) | `application/json`; HTTPS only |
| Version selection | The URL path segment `/v1`. No request-body version field. |
| Response/error `schema_version` | Literal `"1"` |
| Version negotiation | None; a new version is a new URL prefix |

`mtmf-api` itself defines no route and no transport behavior.

## 3. Trust boundary and authentication ownership

- Service (Application) authentication and acting end-user verification
  are **PR 17** responsibilities and are separate gates. The v1 DTOs
  carry **no** credential and **no** authentication field.
- Application identity is derived only from verified credentials; it is
  never read from the body.
- The wire `tenant_id` is a **requested selector** validated by PR 17
  against the verified actor; it is not proof of membership. The optional
  `organization_id` is likewise a requested selector.
- The response exposes **no** Application, Principal, or Identity UUID.
  Those remain verified context in the service/client binding.
- Root/SYSTEM Tenant cannot be a consuming Application context.

No field named `application_id`, `principal_id`, `identity_id`,
`client_id`, `service_token`, `user_token`, `is_root`, `roles`,
`permissions`, or `allowed` is accepted. Unknown fields are rejected.

## 4. JSON policy

- JSON objects; `snake_case` member names; UTF-8.
- Canonical lowercase UUID strings. Nil UUIDs are rejected.
- RFC 3339 UTC timestamps ending in `Z` (optional fractional seconds).
- Duplicate member names (recursively), non-finite numbers, non-object
  top-level values, over-deep nesting, and unknown fields are rejected.
- Unknown keys are never normalized away or ignored.

## 5. Request body

```json
{
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "organization_id": null,
  "actions": [
    {
      "request_id": "check-1",
      "action": "urn:mtmf:iam:actions:system:document:read-object",
      "resource": {"kind": "application_owned", "type": "document", "id": "doc-123"}
    },
    {
      "request_id": "check-2",
      "action": "urn:mtmf:iam:actions:system:document:read-object",
      "resource": {"kind": "application_owned", "type": "document", "id": "doc-123"}
    }
  ]
}
```

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `tenant_id` | UUID string | yes | Requested Tenant selector; non-nil; canonical lowercase |
| `organization_id` | UUID string or `null` | no | Absent/`null` means Tenant-level context; non-nil when present |
| `actions` | array | yes | 1–100 entries; order and duplicates preserved |
| `actions[].request_id` | string | yes | 1–64 ASCII `[A-Za-z0-9._:-]`; unique within the batch; correlation only |
| `actions[].action` | string | yes | Exact canonical Action URN; see §6 |
| `actions[].resource` | object | yes | Tagged union; see §7 |

The request carries no `schema_version`; the version is the URL.

## 6. Action grammar

The public `action` value is the **exact canonical MTMF Action URN**:

```text
urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>
```

- ASCII, 1–256 characters.
- The definition namespace is `system` (the only namespace defined by the
  authoritative documents).
- `<resource>`, `<verb>`, and `<qualifier>` are non-empty; the operation
  is always `<verb>-<qualifier>` (first `-` separates the two).
- No whitespace and no `*` anywhere: there is no request-side wildcard,
  no implicit action set, and no action inferred from omission.
- Missing, malformed, or wildcard Actions are a **whole-request
  validation failure** (`INVALID_REQUEST`).
- A syntactically valid but unregistered/unknown Action is **not** a DTO
  error; it produces a per-item `DENY/UNKNOWN_ACTION`.

See the [decision register W3](PR15_API_CONTRACT_DECISIONS.md) for why
the exact URN (rather than a short public name) is the frozen choice.

## 7. Resource union

The resource is a tagged union discriminated by `kind`. No unknown fields
are permitted.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `capability` | none | Capability-level check with no instance. Never implies object-level access. |
| `application_owned` | `type` (≤128 ASCII), `id` (≤256) | Scope binding metadata for an application-owned resource. The PEP must independently enforce its own Tenant/resource isolation. |
| `mtmf_owned` | `type` (≤128 ASCII), `id` (≤256) | MTMF-owned resource. PR 17 must validate target class and required qualifiers against authoritative MTMF policy before any `ALLOW`; until that validation exists this kind **fails closed**. |

There is no nested free-form `qualifiers` dictionary in v1. If an
approved MTMF-owned resource-specific policy cannot be expressed by
`{kind, type, id}`, stop and request a narrow explicit schema extension
rather than improvising policy input.

## 8. Response body

```json
{
  "schema_version": "1",
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "organization_id": null,
  "issued_at": "2026-10-11T20:00:00Z",
  "expires_at": "2026-10-11T20:01:00Z",
  "decisions": [
    {"request_id": "check-1", "effect": "ALLOW", "reason": "PERMITTED"},
    {"request_id": "check-2", "effect": "DENY", "reason": "NO_PERMISSION"}
  ]
}
```

- `decisions` is nonempty, ordered, and exactly corresponds to the
  request occurrences (same count, same order, same `request_id` set, no
  omission/extra/duplication).
- `effect` ∈ {`ALLOW`, `DENY`}.
- `reason` = `PERMITTED` only with `ALLOW`. `DENY` uses
  `NO_PERMISSION`, `EXPLICIT_DENY`, `UNKNOWN_ACTION`, `INVALID_SCOPE`, or
  `UNSUPPORTED_RESOURCE`.
- `issued_at`/`expires_at` are UTC with `issued_at < expires_at` and a
  positive duration ≤ 300 seconds.
- No partial response is ever serialized after an infrastructure failure;
  a failed request is an error envelope, never a decision list.

A successful response is never serialized from a partial decision list,
an exception, or a missing authoritative decision.

## 9. Public error envelope

```json
{
  "schema_version": "1",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Request validation failed",
    "request_id": "req-trace-123"
  }
}
```

- `error.message` is a fixed static string keyed by `code`.
- `error.request_id` is an optional opaque **transport trace** id assigned
  by the service. It is not the per-action `actions[].request_id`.
- No `details`, stack traces, tokens, SQL, JWKS, matched policy,
  Tenant-existence oracle, or internal exception strings.

| HTTP (PR 17) | `code` | Meaning |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` | Malformed JSON, invalid envelope, or invalid qualifiers |
| 401 | `UNAUTHENTICATED` | Missing/invalid service credential |
| 403 | `UNTRUSTED_ACTOR` | Acting user/Tenant verification or binding failed |
| 403 | `INELIGIBLE_APPLICATION` | Missing/inactive registration/subscription or Application/Tenant ineligibility |
| 413 | `REQUEST_TOO_LARGE` | HTTP byte limit exceeded (PR 17) |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Not JSON (PR 17) |
| 429 | `RATE_LIMITED` | Request rate limit (PR 17) |
| 503 | `DEPENDENCY_UNAVAILABLE` | Issuer/DB/external dependency unavailable; fail closed |
| 500 | `INTERNAL_ERROR` | Unexpected internal failure; fail closed |

`REQUEST_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE`, and `RATE_LIMITED` are
reserved by PR 15 and emitted by PR 17. The transport must never emit
HTTP 200 with a usable subset after a dependency failure.

## 10. Batch semantics

- One verified Application and one verified acting Identity/Tenant
  context per batch; an optional Organization is validated and scoped.
- Each input occurrence receives one correlated decision, including
  duplicates. Duplicates are preserved, never deduplicated.
- All decisions share the same verified context; a batch never mixes
  users, Tenants, or Applications.
- Deterministic policy results may mix `ALLOW`/`DENY` per item.
- An infrastructure failure fails the **whole** request: no partial
  response and never a per-item `ALLOW` derived from a failed evaluation.
- A capability `ALLOW` never grants unrestricted access to individual
  application-owned resources; the PEP enforces its own row/resource
  isolation.

## 11. Conformance and snapshot handoff

`mtmf-api.conformance.validate_response_for_request(request, response)`
is a pure structural check: exact length, unique and input-ordered
`request_id` correlation, and Tenant/Organization equality. It performs
no policy evaluation and can never mint an `ALLOW`.

`request_id` correlation alone is **not** authority. PR 18 must bind a
snapshot to the original immutable request plus the verified
authenticated context (Application, verified actor, Tenant, optional
Organization, resource/scope, enumerated Actions/results). PR 17/18 own
the effective TTL (60s default / 300s maximum / 15s sensitive) and the
sensitivity classification; the DTO only represents the bounded window.

## 12. Non-goals of PR 15

- No HTTP route, ASGI app, authentication wiring, or transport error
  mapping (PR 17).
- No batch evaluator or Rust/Python parity work (PR 16).
- No client, OAuth token acquisition, or scoped snapshots (PR 18).
- No migration, database grant, OAuth issuance, root access, or
  cross-client delegation.

## 13. Machine-readable schema

`packages/mtmf-api/schema/authorization-v1.schema.json` mirrors this
contract as JSON Schema (draft 2020-12), including
`additionalProperties: false`, the discriminated resource union, required
fields, and bounds. Cross-field constraints (`request_id` uniqueness,
correlation, `issued_at < expires_at`, effect/reason coupling) are
documented there as programmatic and are enforced by the DTOs and the
conformance check.
