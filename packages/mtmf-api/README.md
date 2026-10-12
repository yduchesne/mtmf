# mtmf-api

Detached public API contract for MTMF v0.1: strict, versioned JSON DTOs
for the batch authorization endpoint, a stable public error catalog, and
a pure request/response conformance check.

> **This package is not an HTTP server and never makes authorization
> decisions.** The route (`POST /v1/authorization/evaluate`) and its
> authenticated runtime are PR 17; batch policy evaluation is PR 16;
> scoped snapshots are PR 18. `mtmf-api` is a data contract.

## Guarantees

- **No runtime dependencies.** `dependencies = []`; Python 3.14 stdlib
  only.
- **Import isolation.** Importing `mtmf_api` does not import `mtmf-core`,
  `mtmf-service`, FastAPI, PostgreSQL drivers, `sqlalchemy`, or the Rust
  native module.
- **Strict and fail-closed.** Duplicate JSON members, non-finite numbers,
  unknown fields, malformed UUIDs/timestamps, wildcard Actions, and
  out-of-bound batches are rejected with `ApiContractValidationError`.
- **Detached.** All values are immutable `dataclasses`; no live domain
  object crosses the boundary.
- **Correlated.** Every request occurrence receives exactly one ordered
  decision, including duplicates.

## Normative contract

- [PR 15 HTTP API v1 contract](../../../docs/pr-artifacts/pr-15/PR15_HTTP_API_V1_CONTRACT.md)
- [PR 15 API contract decisions](../../../docs/pr-artifacts/pr-15/PR15_API_CONTRACT_DECISIONS.md)
- [Machine-readable schema](schema/authorization-v1.schema.json)

## Public API

```python
from mtmf_api import (
    ApiErrorCode,
    ApiErrorResponse,
    parse_request_json,
    serialize_request,
    parse_response_json,
    serialize_response,
    validate_response_for_request,
)

request = parse_request_json(request_bytes)
# ... the service produces a detached response (PR 17) ...
response = parse_response_json(response_bytes)
validate_response_for_request(request, response)

error = ApiErrorResponse.for_code(ApiErrorCode.INVALID_REQUEST)
```

The public `action` value is the **exact canonical Action URN**
(`urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`). There is no
request-side wildcard, and an unknown-but-syntactically-valid Action is a
per-item `DENY/UNKNOWN_ACTION`, not a validation error.

## Modules

| Module | Responsibility |
| --- | --- |
| `mtmf_api.authorization` | Immutable request/response DTOs, enums, bounds |
| `mtmf_api.json_codec` | Strict deterministic JSON parse/serialize |
| `mtmf_api.errors` | Stable public error catalog and envelope |
| `mtmf_api.conformance` | Pure request/response correlation check |
