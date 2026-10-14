# PR19C_AMENDMENT02_HTTP_CONTRACT_REVIEW

**PR:** roadmap PR 19C.
**Date:** 2026-10-14.
**Scope:** the frozen PR 19C management HTTP contract and its additive error catalog change.

## 1. Route

`POST /v1/management/identity-group-memberships` (single route, no alias, no GET/list). All responses carry `Cache-Control: no-store`. Registered in `mtmf_service/app.py`; the worker runs through the existing bounded admission and shared `evaluation_timeout_seconds`.

## 2. Request

Exact keys only:

```json
{"tenant_id":"<uuid>","identity_id":"<uuid>","group_id":"<uuid>"}
```

Parsed by `mtmf_api.json_codec.parse_membership_add_json` using the existing strict loader (duplicate-member rejection, non-finite rejection, depth bound, UTF-8 validation, canonical lowercase non-nil UUID round-trip). Missing/extra keys, wrong types, arrays/objects, noncanonical/zero UUIDs, invalid UTF-8 and malformed JSON are `INVALID_REQUEST`/400 with no use-case invocation. Oversized bodies are `REQUEST_TOO_LARGE`/413; media/encoding violations are `UNSUPPORTED_MEDIA_TYPE`/415. Tokens are carried only in `Authorization` and the configured user header; no token or context appears in the body.

## 3. Responses

| Condition | Status | Body |
| --- | --- | --- |
| Newly committed membership | 201 | `{tenant_id, identity_id, group_id, created: true}` |
| Authorized idempotent no-op | 200 | `{tenant_id, identity_id, group_id, created: false}` |
| Auth/eligibility/transport/dependency/internal | static envelope | unchanged PR 15 catalog |
| Authenticated actor denied by exact Action or guard | 403 | `FORBIDDEN` / `Operation is not permitted` |

Serialization is deterministic compact JSON (`serialize_membership_add_response`). No `Location`, audit id, operation id, actor, target, or policy detail is returned. There is no post-commit read used to infer `created`; the value is the use case's authoritative boolean.

## 4. Additive error catalog change

`ApiErrorCode.FORBIDDEN = "FORBIDDEN"` (HTTP 403, static message `Operation is not permitted`) is added to `mtmf_api.errors`, the `authorization-v1.schema.json` error enum, and the error fixture set. This is the explicitly approved additive v1 management-route extension. The existing PR 15 codes, mappings, and the `/v1/authorization/evaluate` behavior are unchanged. A verified policy/guard denial is **not** misclassified as `UNTRUSTED_ACTOR` or `INELIGIBLE_APPLICATION`.

`mtmf_service/observability/classification.py` maps `FORBIDDEN` to the request-rejection event with the new closed reason `OPERATION_FORBIDDEN`.

## 5. No-oracle properties

Unknown Tenant/Identity/Group, cross-Tenant targets, an inactive Tenant, and a missing steward are all mapped to the same opaque `FORBIDDEN` response (the adapter catches `ManagementAuthorizationDeniedError`, `SessionContextError`, `TenantBoundaryError`, and the `PersistenceReferenceError` the lock/verify function raises for invalid prerequisites). Database outages remain `DEPENDENCY_UNAVAILABLE`/503 and are never converted to `FORBIDDEN`; the adapter does not catch broad exceptions. This prevents a target-existence oracle.

## 6. Backward compatibility

- `/v1/authorization/evaluate`: request/response/status/telemetry unchanged; full unit + integration suites pass.
- Health probes unchanged.
- `mtmf-client` connector surface unchanged (Amendment 02 Step E: no generic management connector method invented).

## 7. Timeout / response-uncertainty semantics (documented)

A `503`/timeout response is **outcome unknown**: the worker may still complete and commit. The admission permit is retained until the worker actually returns (`release_if_not_started` only releases a worker that never began). A fresh authenticated retry resolves the uncertainty: the committed membership is observed as a `200 created=false` no-op and the audit count remains exactly one. This is proven by `test_uh12_timeout_keeps_permit_until_worker_completes` at the HTTP boundary and by DB-H02/CC-H04 for the persisted state.
