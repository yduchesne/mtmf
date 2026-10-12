"""Service runtime configuration for the PR 17 HTTP PDP.

The configuration is explicit and fail-closed. There is exactly one
approved deployment profile today: the **development** profile, which
requires the PR 14 development issuer fixture and never claims production
transport security. The production profile is deliberately disabled
until the production issuer/root authentication and recovery release
gates are separately approved; selecting it fails startup instead of
silently accepting development defaults.

No secret value lives here: the development issuer/admin credentials are
owned by the PR 14 ``IssuerConfig`` transport seam, and the HTTP process
itself never holds bootstrap/migrator credentials.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "DeploymentMode",
    "ServiceConfigurationError",
    "ServiceSettings",
]


class DeploymentMode(StrEnum):
    """The explicit deployment profile of the running service."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class ServiceConfigurationError(ValueError):
    """The service configuration is missing, ambiguous, or unsafe."""


#: The frozen PR 15 default request byte bound, reused as the initial HTTP
#: maximum unless an authoritative document prescribes another value.
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024

#: Header carrying the independently verified acting-user access token.
#: PR 14 owns verification; PR 17 owns only this transport carrier. The
#: header is never trusted without PR 14 verification and is never used
#: for a service token.
USER_AUTHORIZATION_HEADER = "X-MTMF-User-Authorization"


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    """Validated, immutable service runtime settings."""

    deployment_mode: DeploymentMode = DeploymentMode.DEVELOPMENT
    #: Maximum accepted request body in bytes (streamed byte count, not
    #: merely ``Content-Length``).
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    #: Normative snapshot lifetimes (PR 12 decision T3).
    default_ttl_seconds: int = 60
    max_ttl_seconds: int = 300
    sensitive_ttl_seconds: int = 15
    #: Transport carrier for the separately verified acting-user token.
    user_authorization_header: str = USER_AUTHORIZATION_HEADER
    #: Per-peer in-process token-bucket limiter (no cluster-global claim).
    rate_limit_per_minute: int = 600
    rate_limit_burst: int = 60
    #: Bounded operation timeouts.
    authentication_timeout_seconds: float = 5.0
    evaluation_timeout_seconds: float = 15.0
    #: Hard cap on synchronous evaluations admitted at one time. A permit is
    #: held until the underlying worker actually completes, not merely until
    #: the HTTP deadline, so a timed-out but still-running evaluation cannot
    #: let unbounded work accumulate. Saturation is a deterministic 503.
    max_in_flight_evaluations: int = 40
    #: Development loopback binding only. Production transport security is
    #: a separate release gate.
    host: str = "127.0.0.1"
    port: int = 28001
    #: Permit the development container to bind a wildcard interface. The
    #: host publication must still be loopback-scoped in the MTMF Compose
    #: override; this is never enabled by the production profile.
    allow_container_bind: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.deployment_mode, DeploymentMode):
            raise ServiceConfigurationError("deployment_mode must be a DeploymentMode")
        if self.max_request_bytes < 1:
            raise ServiceConfigurationError("max_request_bytes must be positive")
        if not 0 < self.sensitive_ttl_seconds <= self.default_ttl_seconds <= self.max_ttl_seconds:
            raise ServiceConfigurationError(
                "snapshot TTLs must satisfy 0 < sensitive <= default <= max"
            )
        if self.max_ttl_seconds > 300:
            raise ServiceConfigurationError("the maximum snapshot lifetime is 300 seconds")
        if not self.user_authorization_header:
            raise ServiceConfigurationError("the user authorization header must be configured")
        if self.rate_limit_per_minute < 1 or self.rate_limit_burst < 1:
            raise ServiceConfigurationError("rate limits must be positive")
        if self.authentication_timeout_seconds <= 0 or self.evaluation_timeout_seconds <= 0:
            raise ServiceConfigurationError("operation timeouts must be positive")
        if self.max_in_flight_evaluations < 1:
            raise ServiceConfigurationError("max_in_flight_evaluations must be positive")

    def validate_startup(self) -> None:
        """Fail startup for an unsupported or unsafe deployment profile.

        :raises ServiceConfigurationError: when the production profile is
            selected (no production issuer trust or root recovery gate is
            approved) or the development binding is not loopback-only.
        """
        if self.deployment_mode is DeploymentMode.PRODUCTION:
            raise ServiceConfigurationError(
                "the production HTTP profile is disabled until the production issuer "
                "trust and root authentication/recovery release gates are approved"
            )
        loopback_only = {"127.0.0.1", "localhost", "::1"}
        if self.host not in loopback_only and not self.allow_container_bind:
            raise ServiceConfigurationError(
                "the development HTTP profile may bind loopback only; remote traffic "
                "requires the disabled production transport profile"
            )

    @classmethod
    def from_env(cls) -> ServiceSettings:
        """Build validated settings from explicit environment values."""
        mode_text = (os.environ.get("MTMF_SERVICE_DEPLOYMENT_MODE", "development") or "").strip()
        try:
            mode = DeploymentMode(mode_text)
        except ValueError as exc:
            raise ServiceConfigurationError(
                f"unknown MTMF_SERVICE_DEPLOYMENT_MODE {mode_text!r}"
            ) from exc
        return cls(
            deployment_mode=mode,
            max_request_bytes=int(
                os.environ.get("MTMF_SERVICE_MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES))
            ),
            default_ttl_seconds=int(os.environ.get("MTMF_SERVICE_DEFAULT_TTL_SECONDS", "60")),
            max_ttl_seconds=int(os.environ.get("MTMF_SERVICE_MAX_TTL_SECONDS", "300")),
            sensitive_ttl_seconds=int(os.environ.get("MTMF_SERVICE_SENSITIVE_TTL_SECONDS", "15")),
            user_authorization_header=(
                os.environ.get("MTMF_SERVICE_USER_AUTHORIZATION_HEADER", USER_AUTHORIZATION_HEADER)
                or USER_AUTHORIZATION_HEADER
            ),
            rate_limit_per_minute=int(os.environ.get("MTMF_SERVICE_RATE_LIMIT_PER_MINUTE", "600")),
            rate_limit_burst=int(os.environ.get("MTMF_SERVICE_RATE_LIMIT_BURST", "60")),
            host=os.environ.get("MTMF_SERVICE_HOST", "127.0.0.1"),
            port=int(os.environ.get("MTMF_SERVICE_PORT", "28001")),
            allow_container_bind=os.environ.get("MTMF_SERVICE_ALLOW_CONTAINER_BIND", "") == "1",
            max_in_flight_evaluations=int(
                os.environ.get("MTMF_SERVICE_MAX_IN_FLIGHT_EVALUATIONS", "40")
            ),
        )
