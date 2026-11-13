"""Strict private Unix-socket protocol framing and validation."""

from __future__ import annotations

import json
import struct
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MAX_OPERATOR_FRAME = 16_384
MAX_ADMISSION_FRAME = 32_768
MAX_TOKEN_BYTES = 8_192


class ProtocolError(ValueError):
    """Malformed private request; never a privileged error."""


@dataclass(frozen=True, slots=True)
class Request:
    """A decoded private request, operation-specific."""

    operation: str
    operation_id: uuid.UUID
    fields: Mapping[str, Any]


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def decode_frame(frame: bytes, *, admission: bool = False) -> Mapping[str, Any]:
    """Decode one bounded UTF-8 JSON object with duplicate-key rejection."""
    limit = MAX_ADMISSION_FRAME if admission else MAX_OPERATOR_FRAME
    if not frame or len(frame) > limit:
        raise ProtocolError("frame is empty or too large")
    if len(frame) < 4:
        raise ProtocolError("frame is shorter than its length prefix")
    declared = struct.unpack(">I", frame[:4])[0]
    body = frame[4:]
    if declared != len(body):
        raise ProtocolError("frame length does not match prefix")
    if b"\x00" in body:
        raise ProtocolError("embedded NUL is forbidden")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("invalid UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("request must be a JSON object")
    return value


def encode_frame(payload: Mapping[str, Any]) -> bytes:
    """Encode one bounded canonical-ish JSON response frame."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def canonical_uuid(value: object, name: str) -> uuid.UUID:
    """Parse a canonical non-nil UUID string."""
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be canonical UUID text")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ProtocolError(f"{name} is not a UUID") from exc
    if parsed.int == 0:
        raise ProtocolError(f"{name} must not be nil")
    if str(parsed) != value:
        raise ProtocolError(f"{name} is not canonical")
    return parsed


def decode_operator_request(payload: Mapping[str, Any]) -> Request:
    """Validate one exact operator request envelope."""
    operation = payload.get("operation")
    if payload.get("v") != 1 or not isinstance(operation, str):
        raise ProtocolError("unsupported operator envelope")
    if operation == "health.private":
        _require_keys(payload, {"v", "operation"})
        return Request(operation, uuid.UUID(int=0), dict(payload))
    operation_id = canonical_uuid(payload.get("operation_id"), "operation_id")
    if operation == "entitlement.grant":
        _require_keys(
            payload,
            {
                "v",
                "operation",
                "operation_id",
                "operator_access_token",
                "application_id",
                "entitlement_id",
                "quota_total",
                "reason",
            },
        )
        return Request(operation, operation_id, dict(payload))
    if operation == "entitlement.revoke":
        _require_keys(
            payload,
            {
                "v",
                "operation",
                "operation_id",
                "operator_access_token",
                "application_id",
                "entitlement_id",
                "reason",
            },
        )
        return Request(operation, operation_id, dict(payload))
    if operation == "entitlement.get":
        _require_keys(
            payload,
            {
                "v",
                "operation",
                "operation_id",
                "operator_access_token",
                "application_id",
                "entitlement_id",
            },
        )
        return Request(operation, operation_id, dict(payload))
    raise ProtocolError("unsupported operation")


def decode_admission_request(payload: Mapping[str, Any]) -> Request:
    """Validate the exact admission.prepare request envelope."""
    if payload.get("v") != 1 or payload.get("operation") != "admission.prepare":
        raise ProtocolError("unsupported admission envelope")
    _require_keys(
        payload,
        {
            "v",
            "operation",
            "request_id",
            "service_access_token",
            "user_access_token",
        },
    )
    request_id = canonical_uuid(payload.get("request_id"), "request_id")
    return Request("admission.prepare", request_id, dict(payload))


def _require_keys(payload: Mapping[str, Any], expected: set[str]) -> None:
    if set(payload) != expected:
        raise ProtocolError("unknown or missing request field")
    for name, value in payload.items():
        if name in {"operator_access_token", "service_access_token", "user_access_token"} and (
            not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_TOKEN_BYTES
        ):
            raise ProtocolError(f"{name} is missing or too large")
        if name in {"application_id", "entitlement_id", "operation_id", "request_id"}:
            canonical_uuid(value, name)
    operation = payload.get("operation")
    if operation == "entitlement.grant":
        quota = payload.get("quota_total")
        if not isinstance(quota, int) or isinstance(quota, bool) or quota <= 0:
            raise ProtocolError("quota_total must be a positive integer")
    if "reason" in payload:
        reason = payload.get("reason")
        if not isinstance(reason, str):
            raise ProtocolError("reason must be text")
        if reason != reason.strip() or not 1 <= len(reason) <= 512:
            raise ProtocolError("reason must be exactly trimmed and bounded")
