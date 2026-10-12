"""Low-level HTTP transport guards for the PR 17 PDP route.

These helpers enforce the bounded byte read, media-type and authorization
carrier rules before any trust or policy work. They raise :class:`PublicError`
with the exact PR 15 code so the error mapping stays in one place. They
never trust a forwarded header for a security decision.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mtmf_api.errors import ApiErrorCode
from mtmf_service.errors import PublicError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.requests import Request


def peer_key(request: Request) -> str:
    """Return a non-spoofable transport-peer key for rate limiting.

    The ASGI ``client`` address is the transport peer, not a header, so an
    attacker cannot rotate it with ``X-Forwarded-For``.
    """
    client = request.client
    return client.host if client is not None and client.host else "unknown"


def enforce_json_content_type(request: Request) -> None:
    """Reject anything but a single ``application/json`` media type.

    :raises PublicError: ``UNSUPPORTED_MEDIA_TYPE`` for a missing,
        ambiguous, or non-JSON content type, or an explicit
        content-encoding.
    """
    values = request.headers.getlist("content-type")
    if len(values) != 1:
        raise PublicError(ApiErrorCode.UNSUPPORTED_MEDIA_TYPE)
    media_type = values[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise PublicError(ApiErrorCode.UNSUPPORTED_MEDIA_TYPE)
    encodings = request.headers.getlist("content-encoding")
    if any(value.strip().lower() not in ("", "identity") for value in encodings):
        raise PublicError(ApiErrorCode.UNSUPPORTED_MEDIA_TYPE)


async def read_bounded_body(request: Request, *, max_bytes: int) -> bytes:
    """Read the request stream while enforcing the actual byte bound.

    A declared ``Content-Length`` over the bound is rejected immediately,
    but the streamed byte count is always enforced too, so an absent or
    false length (or a chunked body) cannot exceed the limit.

    :raises PublicError: ``INVALID_REQUEST`` for a malformed
        ``Content-Length`` and ``REQUEST_TOO_LARGE`` when the bound is
        exceeded.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_length = int(declared)
        except ValueError as exc:
            raise PublicError(ApiErrorCode.INVALID_REQUEST) from exc
        if declared_length < 0:
            raise PublicError(ApiErrorCode.INVALID_REQUEST)
        if declared_length > max_bytes:
            raise PublicError(ApiErrorCode.REQUEST_TOO_LARGE)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise PublicError(ApiErrorCode.REQUEST_TOO_LARGE)
        chunks.append(chunk)
    return b"".join(chunks)


def extract_service_token(request: Request) -> str:
    """Extract the single ``Authorization: Bearer`` service token.

    :raises PublicError: ``UNAUTHENTICATED`` for a missing, duplicated,
        wrong-scheme, or empty service credential.
    """
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise PublicError(ApiErrorCode.UNAUTHENTICATED)
    return _bearer(values[0], ApiErrorCode.UNAUTHENTICATED)


def extract_user_token(request: Request, *, header_name: str) -> str:
    """Extract the single acting-user bearer token carrier.

    :raises PublicError: ``UNTRUSTED_ACTOR`` for a missing, duplicated,
        wrong-scheme, or empty user token. The token is never trusted
        until PR 14 verifies it.
    """
    values = request.headers.getlist(header_name)
    if len(values) != 1:
        raise PublicError(ApiErrorCode.UNTRUSTED_ACTOR)
    return _bearer(values[0], ApiErrorCode.UNTRUSTED_ACTOR)


def _bearer(value: str, code: ApiErrorCode) -> str:
    """Parse a ``Bearer <token>`` header value or fail closed."""
    scheme, separator, token = value.partition(" ")
    if not separator or scheme.strip().lower() != "bearer":
        raise PublicError(code)
    token = token.strip()
    if not token or " " in token:
        raise PublicError(code)
    return token
