"""MTMF public API contract package (PR 15).

This package owns the detached, versioned v1 HTTP batch-authorization
DTOs, strict JSON codecs, the stable public error catalog, and the pure
request/response conformance check.

It is a *contract-only* package:

- it never implements an HTTP server or route;
- it never evaluates authorization or resolves policy;
- it performs no I/O and has no runtime dependencies;
- it imports no MTMF implementation package, database driver, HTTP
  framework, or native module.

Consumers may import it without installing ``mtmf-core``,
``mtmf-service``, FastAPI, PostgreSQL, or the Rust permission engine.
"""

from __future__ import annotations

from mtmf_api.authorization import (
    MAX_ACTION_LENGTH,
    MAX_BATCH_ACTIONS,
    MAX_REQUEST_ID_LENGTH,
    MAX_RESOURCE_ID_LENGTH,
    MAX_RESOURCE_TYPE_LENGTH,
    MIN_BATCH_ACTIONS,
    SCHEMA_VERSION,
    SNAPSHOT_DEFAULT_TTL,
    SNAPSHOT_MAX_TTL,
    SNAPSHOT_SENSITIVE_MAX_TTL,
    ActionDecision,
    ActionRequest,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
    ensure_utc,
    validate_action_urn,
)
from mtmf_api.conformance import ResponseConformanceError, validate_response_for_request
from mtmf_api.errors import (
    ERROR_HTTP_STATUS,
    ERROR_MESSAGES,
    ApiContractValidationError,
    ApiErrorCode,
    ApiErrorResponse,
)
from mtmf_api.json_codec import (
    DEFAULT_MAX_REQUEST_BYTES,
    parse_error_json,
    parse_request_json,
    parse_response_json,
    serialize_error,
    serialize_request,
    serialize_response,
)

__all__ = [
    "DEFAULT_MAX_REQUEST_BYTES",
    "ERROR_HTTP_STATUS",
    "ERROR_MESSAGES",
    "MAX_ACTION_LENGTH",
    "MAX_BATCH_ACTIONS",
    "MAX_REQUEST_ID_LENGTH",
    "MAX_RESOURCE_ID_LENGTH",
    "MAX_RESOURCE_TYPE_LENGTH",
    "MIN_BATCH_ACTIONS",
    "SCHEMA_VERSION",
    "SNAPSHOT_DEFAULT_TTL",
    "SNAPSHOT_MAX_TTL",
    "SNAPSHOT_SENSITIVE_MAX_TTL",
    "ActionDecision",
    "ActionRequest",
    "ApiContractValidationError",
    "ApiErrorCode",
    "ApiErrorResponse",
    "AuthorizationBatchRequest",
    "AuthorizationBatchResponse",
    "AuthorizationEffect",
    "DecisionReason",
    "ResourceKind",
    "ResourceTarget",
    "ResponseConformanceError",
    "ensure_utc",
    "parse_error_json",
    "parse_request_json",
    "parse_response_json",
    "serialize_error",
    "serialize_request",
    "serialize_response",
    "validate_action_urn",
    "validate_response_for_request",
]

__version__ = "0.1.0"
