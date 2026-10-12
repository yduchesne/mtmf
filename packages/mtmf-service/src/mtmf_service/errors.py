"""Public PR 15 error mapping for the PR 17 HTTP trust boundary.

Every failure that reaches the HTTP surface becomes exactly one static PR
15 ``ApiErrorResponse`` envelope. No exception text, SQL, token claim,
JWKS detail, Tenant-existence distinction, or Python stack trace is ever
echoed. Mapping is by *semantics*: a dependency outage is a 503, an
internal fault is a 500, and an authorization-semantic DENY never
disguises a transport failure.
"""

from __future__ import annotations

from mtmf_api.errors import ERROR_HTTP_STATUS, ApiContractValidationError, ApiErrorCode
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.domain.errors import SessionContextError, TenantBoundaryError
from mtmf_core.persistence.errors import PersistenceError
from mtmf_service.authentication.config import AuthenticationConfigError
from mtmf_service.settings import ServiceConfigurationError

__all__ = [
    "PublicError",
    "map_authentication_error",
    "map_exception",
]


class PublicError(Exception):
    """A failure already resolved to a stable public PR 15 error code.

    Raised by the transport boundary for conditions it detects directly
    (missing credential, oversized body, unsupported media type, rate
    limiting) and for the deliberately coarse internal/dependency faults.
    """

    __slots__ = ("code",)

    def __init__(self, code: ApiErrorCode) -> None:
        if not isinstance(code, ApiErrorCode):
            raise TypeError("code must be an ApiErrorCode")
        self.code = code
        super().__init__(code.value)

    @property
    def http_status(self) -> int:
        """The frozen HTTP status for this error code."""
        return ERROR_HTTP_STATUS[self.code]


#: Categories that mean a trusted dependency (issuer/JWKS/attestation/DB)
#: was unavailable, which is a 503 rather than a caller error.
_DEPENDENCY_FAILURES = frozenset(
    {
        AuthenticationFailure.ATTESTATION_UNAVAILABLE,
        AuthenticationFailure.ATTESTATION_DRIFT,
        AuthenticationFailure.INFRASTRUCTURE,
    }
)

#: Categories that mean the verified Application/registration/subscription
#: is not eligible for the requested ordinary Tenant.
_APPLICATION_ELIGIBILITY_FAILURES = frozenset(
    {
        AuthenticationFailure.UNKNOWN_APPLICATION,
        AuthenticationFailure.INELIGIBLE_REGISTRATION,
        AuthenticationFailure.INELIGIBLE_SUBSCRIPTION,
    }
)


def map_authentication_error(error: AuthenticationError) -> ApiErrorCode:
    """Map a typed PR 14 failure to exactly one public PR 15 error code.

    The token ``slot`` (when present) separates an invalid service
    credential (401) from invalid acting-user proof (403); persisted
    Application/registration/subscription ineligibility is a 403
    ``INELIGIBLE_APPLICATION``; an issuer/attestation/database outage is a
    503. There is no fall-through that could yield a grant.
    """
    failure = error.failure
    if failure in _DEPENDENCY_FAILURES:
        return ApiErrorCode.DEPENDENCY_UNAVAILABLE
    if failure in _APPLICATION_ELIGIBILITY_FAILURES:
        return ApiErrorCode.INELIGIBLE_APPLICATION
    if failure is AuthenticationFailure.INVALID_REQUEST:
        return ApiErrorCode.INVALID_REQUEST
    if error.slot == "service":
        return ApiErrorCode.UNAUTHENTICATED
    if failure in (
        AuthenticationFailure.UNKNOWN_SUBJECT,
        AuthenticationFailure.INACTIVE_ACTOR,
        AuthenticationFailure.INELIGIBLE_TENANT,
        AuthenticationFailure.ROOT_FORBIDDEN,
        AuthenticationFailure.CROSS_CLIENT,
        AuthenticationFailure.WRONG_TOKEN_CLASS,
        AuthenticationFailure.INVALID_TOKEN,
        AuthenticationFailure.EXPIRED_TOKEN,
        AuthenticationFailure.IMMATURE_TOKEN,
        AuthenticationFailure.WRONG_AUDIENCE,
        AuthenticationFailure.UNTRUSTED_ISSUER,
    ):
        return ApiErrorCode.UNTRUSTED_ACTOR
    # An unclassified/legacy authentication failure is treated as an
    # unavailable dependency rather than a caller fault; it never grants.
    return ApiErrorCode.DEPENDENCY_UNAVAILABLE


def map_exception(error: Exception) -> ApiErrorCode:
    """Map an arbitrary raised exception to a stable public error code.

    Unknown/internal faults become ``INTERNAL_ERROR`` (500); they are
    never presented as a per-item DENY or a partially useful 200.
    """
    if isinstance(error, PublicError):
        return error.code
    if isinstance(error, ApiContractValidationError):
        # A structural response-conformance failure is a server fault, not
        # a request fault; distinguish it before the generic contract error.
        from mtmf_api.conformance import ResponseConformanceError

        if isinstance(error, ResponseConformanceError):
            return ApiErrorCode.INTERNAL_ERROR
        return ApiErrorCode.INVALID_REQUEST
    if isinstance(error, AuthenticationError):
        return map_authentication_error(error)
    if isinstance(error, (SessionContextError, TenantBoundaryError)):
        return ApiErrorCode.UNTRUSTED_ACTOR
    if isinstance(error, (AuthenticationConfigError, ServiceConfigurationError)):
        return ApiErrorCode.INTERNAL_ERROR
    if isinstance(error, PersistenceError):
        return ApiErrorCode.DEPENDENCY_UNAVAILABLE
    return ApiErrorCode.INTERNAL_ERROR
