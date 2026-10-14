"""Strict, deterministic JSON codecs for the detached v1 contract.

Parsing is fail-closed: duplicate member names, non-finite numbers,
non-object top-level values, unknown fields, malformed UUIDs/timestamps,
and out-of-bound collections are all rejected with
:class:`~mtmf_api.errors.ApiContractValidationError`. There is no I/O,
no policy evaluation, and no framework dependency.

Serialization is canonical and stable: fixed field order, exact enum
spellings, lowercase UUID strings, and RFC 3339 UTC timestamps ending in
``Z``. Two serializations of the same value are byte-identical.
"""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from mtmf_api.authorization import (
    MAX_BATCH_ACTIONS,
    MIN_BATCH_ACTIONS,
    SCHEMA_VERSION,
    ActionDecision,
    ActionRequest,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
)
from mtmf_api.errors import (
    ERROR_MESSAGES,
    ApiContractValidationError,
    ApiErrorCode,
    ApiErrorResponse,
)
from mtmf_api.management import (
    IdentityGroupMembershipAddRequest,
    IdentityGroupMembershipAddResponse,
)

#: Convenience precheck applied only when raw ``bytes`` are supplied. The
#: authoritative HTTP body limit belongs to PR 17; already-parsed objects
#: are never re-measured against this constant.
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024

#: Maximum JSON container nesting accepted by the strict loader. The v1
#: schema nests only a handful of levels, so a small bound rejects abuse
#: without constraining legitimate payloads.
_MAX_JSON_DEPTH = 8

_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")

_REQUEST_REQUIRED = frozenset({"tenant_id", "actions"})
_REQUEST_OPTIONAL = frozenset({"organization_id"})
_ACTION_REQUIRED = frozenset({"request_id", "action", "resource"})
_RESPONSE_REQUIRED = frozenset(
    {
        "schema_version",
        "tenant_id",
        "organization_id",
        "issued_at",
        "expires_at",
        "decisions",
    }
)
_DECISION_REQUIRED = frozenset({"request_id", "effect", "reason"})
_ERROR_REQUIRED = frozenset({"schema_version", "error"})
_ERROR_BODY_REQUIRED = frozenset({"code", "message"})
_ERROR_BODY_OPTIONAL = frozenset({"request_id"})
_MEMBERSHIP_ADD_REQUIRED = frozenset({"tenant_id", "identity_id", "group_id"})


def _reject_non_finite(value: str) -> Any:
    """Reject JSON ``NaN``/``Infinity`` constants."""
    raise ApiContractValidationError(f"non-finite JSON number is not allowed: {value}")


def _object_pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApiContractValidationError(f"duplicate JSON member name: {key!r}")
        result[key] = value
    return result


def _check_shape(value: Any, depth: int = 0) -> None:
    """Reject over-deep or non-JSON Python shapes after parsing."""
    if depth > _MAX_JSON_DEPTH:
        raise ApiContractValidationError("JSON nesting is too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ApiContractValidationError("JSON object keys must be strings")
            _check_shape(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_shape(item, depth + 1)
    elif value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ApiContractValidationError("non-finite JSON numbers are not allowed")
    else:
        raise ApiContractValidationError("unsupported JSON value")


def _loads_strict(text: str) -> Any:
    """Parse JSON text with duplicate-key and non-finite rejection."""
    try:
        value: Any = json.loads(
            text,
            object_pairs_hook=_object_pairs_without_duplicates,
            parse_constant=_reject_non_finite,
        )
    except ApiContractValidationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ApiContractValidationError("malformed JSON") from exc
    _check_shape(value)
    return value


def _dumps(value: dict[str, Any]) -> str:
    """Serialize a mapping canonically."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _expect_object(value: Any, context: str) -> dict[str, Any]:
    """Require a JSON object and return it."""
    if not isinstance(value, dict):
        raise ApiContractValidationError(f"{context} must be a JSON object")
    return value


def _expect_keys(
    obj: dict[str, Any],
    required: frozenset[str],
    optional: frozenset[str],
    context: str,
) -> None:
    """Enforce an exact field set: no unknown keys and no missing required keys."""
    keys = set(obj)
    unknown = keys - (required | optional)
    if unknown:
        raise ApiContractValidationError(f"{context} contains unknown fields: {sorted(unknown)!r}")
    missing = required - keys
    if missing:
        raise ApiContractValidationError(f"{context} is missing fields: {sorted(missing)!r}")


def _parse_uuid(value: Any, field: str) -> UUID:
    """Parse a canonical lowercase, non-nil UUID string."""
    if not isinstance(value, str):
        raise ApiContractValidationError(f"{field} must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ApiContractValidationError(f"{field} is not a valid UUID") from exc
    if str(parsed) != value:
        raise ApiContractValidationError(f"{field} must be a canonical lowercase UUID")
    if parsed.int == 0:
        raise ApiContractValidationError(f"{field} must not be the nil UUID")
    return parsed


def _parse_optional_uuid(value: Any, field: str) -> UUID | None:
    """Parse an optional UUID selector (``null`` means absent)."""
    if value is None:
        return None
    return _parse_uuid(value, field)


def _parse_timestamp(value: Any, field: str) -> datetime:
    """Parse an RFC 3339 UTC timestamp ending in ``Z``."""
    if not isinstance(value, str):
        raise ApiContractValidationError(f"{field} must be a UTC timestamp string")
    if _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ApiContractValidationError(f"{field} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1])
    except ValueError as exc:
        raise ApiContractValidationError(f"{field} is not a valid timestamp") from exc
    return parsed.replace(tzinfo=UTC)


def _format_timestamp(value: datetime) -> str:
    """Format a datetime as canonical RFC 3339 UTC text."""
    normalized = value.astimezone(UTC)
    base = normalized.strftime("%Y-%m-%dT%H:%M:%S")
    if normalized.microsecond:
        return f"{base}.{normalized.microsecond:06d}Z"
    return f"{base}Z"


def _parse_resource(value: Any, index: int) -> ResourceTarget:
    """Parse the tagged resource union for one action entry."""
    context = f"actions[{index}].resource"
    obj = _expect_object(value, context)
    if "kind" not in obj:
        raise ApiContractValidationError(f"{context} is missing the 'kind' field")
    kind_value = obj["kind"]
    try:
        kind = ResourceKind(kind_value)
    except ValueError as exc:
        raise ApiContractValidationError(
            f"{context}.kind is not a supported resource kind"
        ) from exc
    if kind is ResourceKind.CAPABILITY:
        _expect_keys(obj, frozenset({"kind"}), frozenset(), context)
    else:
        _expect_keys(obj, frozenset({"kind", "type", "id"}), frozenset(), context)
    resource_type = obj.get("type")
    resource_id = obj.get("id")
    if resource_type is not None and not isinstance(resource_type, str):
        raise ApiContractValidationError(f"{context}.type must be a string")
    if resource_id is not None and not isinstance(resource_id, str):
        raise ApiContractValidationError(f"{context}.id must be a string")
    return ResourceTarget(
        kind=kind,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def _parse_action(value: Any, index: int) -> ActionRequest:
    """Parse one action occurrence."""
    context = f"actions[{index}]"
    obj = _expect_object(value, context)
    _expect_keys(obj, _ACTION_REQUIRED, frozenset(), context)
    return ActionRequest(
        request_id=obj["request_id"],
        action=obj["action"],
        resource=_parse_resource(obj["resource"], index),
    )


def _parse_decision(value: Any, index: int) -> ActionDecision:
    """Parse one decision entry."""
    context = f"decisions[{index}]"
    obj = _expect_object(value, context)
    _expect_keys(obj, _DECISION_REQUIRED, frozenset(), context)
    effect_value = obj["effect"]
    try:
        effect = AuthorizationEffect(effect_value)
    except ValueError as exc:
        raise ApiContractValidationError(f"{context}.effect is not a valid effect") from exc
    reason_value = obj["reason"]
    try:
        reason = DecisionReason(reason_value)
    except ValueError as exc:
        raise ApiContractValidationError(f"{context}.reason is not a valid reason") from exc
    return ActionDecision(request_id=obj["request_id"], effect=effect, reason=reason)


def _decode_text(payload: bytes | str) -> str:
    """Decode a ``bytes``/``str`` payload, applying the byte-size precheck."""
    if isinstance(payload, bytes):
        if len(payload) > DEFAULT_MAX_REQUEST_BYTES:
            raise ApiContractValidationError("request body exceeds the permitted size")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApiContractValidationError("request body is not valid UTF-8") from exc
    if isinstance(payload, str):
        return payload
    raise TypeError("payload must be bytes or str")


def parse_request_json(payload: bytes | str) -> AuthorizationBatchRequest:
    """Parse and strictly validate a v1 request body."""
    data = _expect_object(_loads_strict(_decode_text(payload)), "request")
    _expect_keys(data, _REQUEST_REQUIRED, _REQUEST_OPTIONAL, "request")
    tenant_id = _parse_uuid(data["tenant_id"], "tenant_id")
    organization_id = _parse_optional_uuid(data.get("organization_id"), "organization_id")
    actions_raw = data["actions"]
    if not isinstance(actions_raw, list):
        raise ApiContractValidationError("actions must be a JSON array")
    if not MIN_BATCH_ACTIONS <= len(actions_raw) <= MAX_BATCH_ACTIONS:
        raise ApiContractValidationError(
            f"actions must contain between {MIN_BATCH_ACTIONS} and {MAX_BATCH_ACTIONS} entries"
        )
    actions = tuple(_parse_action(item, index) for index, item in enumerate(actions_raw))
    return AuthorizationBatchRequest(
        tenant_id=tenant_id,
        organization_id=organization_id,
        actions=actions,
    )


def _resource_to_mapping(resource: ResourceTarget) -> dict[str, Any]:
    """Render a resource target as an ordered mapping."""
    if resource.kind is ResourceKind.CAPABILITY:
        return {"kind": resource.kind.value}
    return {
        "kind": resource.kind.value,
        "type": resource.resource_type,
        "id": resource.resource_id,
    }


def serialize_request(request: AuthorizationBatchRequest) -> str:
    """Serialize a request DTO to canonical JSON."""
    mapping: dict[str, Any] = {
        "tenant_id": str(request.tenant_id),
        "organization_id": str(request.organization_id) if request.organization_id else None,
        "actions": [
            {
                "request_id": action.request_id,
                "action": action.action,
                "resource": _resource_to_mapping(action.resource),
            }
            for action in request.actions
        ],
    }
    return _dumps(mapping)


def parse_response_json(payload: bytes | str) -> AuthorizationBatchResponse:
    """Parse and strictly validate a v1 response body."""
    data = _expect_object(_loads_strict(_decode_text(payload)), "response")
    _expect_keys(data, _RESPONSE_REQUIRED, frozenset(), "response")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ApiContractValidationError("unsupported response schema_version")
    tenant_id = _parse_uuid(data["tenant_id"], "tenant_id")
    organization_id = _parse_optional_uuid(data.get("organization_id"), "organization_id")
    issued_at = _parse_timestamp(data["issued_at"], "issued_at")
    expires_at = _parse_timestamp(data["expires_at"], "expires_at")
    decisions_raw = data["decisions"]
    if not isinstance(decisions_raw, list) or not decisions_raw:
        raise ApiContractValidationError("decisions must be a nonempty JSON array")
    decisions = tuple(_parse_decision(item, index) for index, item in enumerate(decisions_raw))
    return AuthorizationBatchResponse(
        tenant_id=tenant_id,
        organization_id=organization_id,
        issued_at=issued_at,
        expires_at=expires_at,
        decisions=decisions,
        schema_version=data["schema_version"],
    )


def serialize_response(response: AuthorizationBatchResponse) -> str:
    """Serialize a response DTO to canonical JSON."""
    mapping: dict[str, Any] = {
        "schema_version": response.schema_version,
        "tenant_id": str(response.tenant_id),
        "organization_id": str(response.organization_id) if response.organization_id else None,
        "issued_at": _format_timestamp(response.issued_at),
        "expires_at": _format_timestamp(response.expires_at),
        "decisions": [
            {
                "request_id": decision.request_id,
                "effect": decision.effect.value,
                "reason": decision.reason.value,
            }
            for decision in response.decisions
        ],
    }
    return _dumps(mapping)


def parse_error_json(payload: bytes | str) -> ApiErrorResponse:
    """Parse and strictly validate a v1 error envelope."""
    data = _expect_object(_loads_strict(_decode_text(payload)), "error response")
    _expect_keys(data, _ERROR_REQUIRED, frozenset(), "error response")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ApiContractValidationError("unsupported error schema_version")
    body = _expect_object(data["error"], "error response.error")
    _expect_keys(body, _ERROR_BODY_REQUIRED, _ERROR_BODY_OPTIONAL, "error response.error")
    code_value = body["code"]
    try:
        code = ApiErrorCode(code_value)
    except ValueError as exc:
        raise ApiContractValidationError("error response.error.code is not a known code") from exc
    message = body["message"]
    if message != ERROR_MESSAGES[code]:
        raise ApiContractValidationError("error response message must match the static catalog")
    return ApiErrorResponse(code=code, message=message, request_id=body.get("request_id"))


def serialize_error(error: ApiErrorResponse) -> str:
    """Serialize an error envelope to canonical JSON."""
    body: dict[str, Any] = {"code": error.code.value, "message": error.message}
    if error.request_id is not None:
        body["request_id"] = error.request_id
    mapping: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "error": body}
    return _dumps(mapping)


def parse_membership_add_json(payload: bytes | str) -> IdentityGroupMembershipAddRequest:
    """Parse and strictly validate a management membership-add request body.

    Reuses the strict duplicate-key, non-finite, depth, UTF-8 and canonical
    lowercase UUID discipline of the v1 codec. Unknown/extra keys are
    rejected.
    """
    data = _expect_object(_loads_strict(_decode_text(payload)), "request")
    _expect_keys(data, _MEMBERSHIP_ADD_REQUIRED, frozenset(), "request")
    return IdentityGroupMembershipAddRequest(
        tenant_id=_parse_uuid(data["tenant_id"], "tenant_id"),
        identity_id=_parse_uuid(data["identity_id"], "identity_id"),
        group_id=_parse_uuid(data["group_id"], "group_id"),
    )


def serialize_membership_add_response(response: IdentityGroupMembershipAddResponse) -> str:
    """Serialize a membership-add response to canonical JSON."""
    mapping: dict[str, Any] = {
        "tenant_id": str(response.tenant_id),
        "identity_id": str(response.identity_id),
        "group_id": str(response.group_id),
        "created": response.created,
    }
    return _dumps(mapping)
