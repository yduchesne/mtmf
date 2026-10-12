"""Stable public error catalog for the MTMF v1 HTTP contract (PR 15).

This module owns the *detached* public error DTO and the stable error
code taxonomy that `mtmf-service` (PR 17) maps onto HTTP responses. It
imports no MTMF implementation package: an error is a value, not an
exception from `mtmf-core`.

The catalog distinguishes invalid request data (emitted by the DTO
package itself as :class:`ApiContractValidationError`) from the stable
wire error *envelope* (:class:`ApiErrorResponse`). Message text is a
static public string keyed by code so that no internal exception text,
stack trace, SQL, token, or policy detail can leak through the public
surface.

Ownership: PR 15 reserves these codes; PR 17 is responsible for actually
emitting authentication/actor/eligibility/transport failures. An unknown
but syntactically valid Action is *not* an ``INVALID_REQUEST``; it is a
per-item DENY on the decision DTO.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

#: Maximum length of the opaque, service-assigned transport trace id in
#: :attr:`ApiErrorResponse.request_id`. This is *not* the per-action
#: ``request_id`` carried on the request/decision DTOs.
MAX_ERROR_REQUEST_ID_LENGTH: Final = 256


class ApiErrorCode(Enum):
    """The stable public error codes of the v1 HTTP contract.

    Codes are uppercase wire spellings. They are intentionally coarse:
    they do not distinguish user existence, Tenant existence, secret
    details, or policy internals.
    """

    INVALID_REQUEST = "INVALID_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNTRUSTED_ACTOR = "UNTRUSTED_ACTOR"
    INELIGIBLE_APPLICATION = "INELIGIBLE_APPLICATION"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    RATE_LIMITED = "RATE_LIMITED"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: Static public message for each code. The message never varies with the
#: underlying failure so it cannot be used as an oracle.
ERROR_MESSAGES: Final[Mapping[ApiErrorCode, str]] = MappingProxyType(
    {
        ApiErrorCode.INVALID_REQUEST: "Request validation failed",
        ApiErrorCode.UNAUTHENTICATED: "Service authentication failed",
        ApiErrorCode.UNTRUSTED_ACTOR: "Acting user or tenant verification failed",
        ApiErrorCode.INELIGIBLE_APPLICATION: "Application or subscription is not eligible",
        ApiErrorCode.REQUEST_TOO_LARGE: "Request body exceeds the permitted size",
        ApiErrorCode.UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
        ApiErrorCode.RATE_LIMITED: "Request rate limit exceeded",
        ApiErrorCode.DEPENDENCY_UNAVAILABLE: "A required dependency is unavailable",
        ApiErrorCode.INTERNAL_ERROR: "An unexpected internal error occurred",
    }
)


#: Reserved HTTP status mapping. PR 15 freezes the mapping; PR 17 emits it.
ERROR_HTTP_STATUS: Final[Mapping[ApiErrorCode, int]] = MappingProxyType(
    {
        ApiErrorCode.INVALID_REQUEST: 400,
        ApiErrorCode.UNAUTHENTICATED: 401,
        ApiErrorCode.UNTRUSTED_ACTOR: 403,
        ApiErrorCode.INELIGIBLE_APPLICATION: 403,
        ApiErrorCode.REQUEST_TOO_LARGE: 413,
        ApiErrorCode.UNSUPPORTED_MEDIA_TYPE: 415,
        ApiErrorCode.RATE_LIMITED: 429,
        ApiErrorCode.DEPENDENCY_UNAVAILABLE: 503,
        ApiErrorCode.INTERNAL_ERROR: 500,
    }
)


class ApiContractValidationError(ValueError):
    """Raised when wire data violates the detached v1 contract.

    This is a *parsing/validation* failure, never an authorization
    decision. It is always fail-closed: callers must not synthesize an
    ``ALLOW`` from it, and it must not be serialized as a decision.
    """


@dataclass(frozen=True, slots=True)
class ApiErrorResponse:
    """The detached, stable public error envelope.

    :attr:`message` must equal the static message for :attr:`code`; this
    keeps the public text uniform and prevents a caller from echoing
    internal detail. :attr:`request_id` is an optional opaque transport
    trace id *assigned by the service*; it is not the per-action
    ``request_id`` of the request DTO.
    """

    code: ApiErrorCode
    message: str
    request_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, ApiErrorCode):
            raise ApiContractValidationError("error code must be an ApiErrorCode")
        if self.message != ERROR_MESSAGES[self.code]:
            raise ApiContractValidationError("error message must match the static catalog text")
        if self.request_id is not None:
            if not isinstance(self.request_id, str) or not self.request_id:
                raise ApiContractValidationError("error request_id must be a nonempty string")
            if len(self.request_id) > MAX_ERROR_REQUEST_ID_LENGTH:
                raise ApiContractValidationError("error request_id exceeds the maximum length")
            if any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in self.request_id
            ):
                raise ApiContractValidationError(
                    "error request_id must not contain control characters"
                )

    @classmethod
    def for_code(
        cls,
        code: ApiErrorCode,
        *,
        request_id: str | None = None,
    ) -> ApiErrorResponse:
        """Build an error envelope with the catalog message for ``code``."""
        return cls(code=code, message=ERROR_MESSAGES[code], request_id=request_id)

    @property
    def http_status(self) -> int:
        """The reserved HTTP status for this error code."""
        return ERROR_HTTP_STATUS[self.code]
