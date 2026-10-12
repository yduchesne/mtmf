"""Development-only issuer configuration for the PR 14 service layer.

The approved scope is the pinned Keycloak 26.8.0 local development issuer;
production issuer trust is out of scope. Configuration fails closed: a
non-loopback issuer, equal service/user audiences, or a missing required
value is rejected at construction.
"""

from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass

__all__ = ["AuthenticationConfigError", "IssuerConfig"]


class AuthenticationConfigError(ValueError):
    """The development authentication configuration is missing or unsafe."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise AuthenticationConfigError(f"required configuration {name} is not set")
    return value


def _is_loopback(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    return host in {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    """Validated development issuer and trust-baseline configuration."""

    issuer: str
    service_audience: str
    user_audience: str
    jwks_uri: str
    expected_manifest_path: str
    admin_base_url: str
    admin_realm: str
    admin_username: str
    admin_password: str
    algorithm: str = "RS256"
    transport_timeout_seconds: float = 5.0
    max_token_bytes: int = 8192
    max_jwks_bytes: int = 262144
    jwks_cache_seconds: float = 300.0
    jwks_min_refresh_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.algorithm != "RS256":
            raise AuthenticationConfigError("only the reviewed RS256 algorithm is supported")
        if self.service_audience == self.user_audience:
            raise AuthenticationConfigError("service and user audiences must differ")
        if not _is_loopback(self.issuer) or not _is_loopback(self.admin_base_url):
            raise AuthenticationConfigError(
                "the development issuer and admin base must be loopback; "
                "production trust is out of scope"
            )
        if not self.jwks_uri.startswith(self.issuer.rstrip("/") + "/"):
            raise AuthenticationConfigError("jwks_uri must belong to the configured issuer")
        if self.transport_timeout_seconds <= 0 or self.jwks_cache_seconds <= 0:
            raise AuthenticationConfigError("transport timeout and JWKS cache must be positive")
        if self.max_token_bytes <= 0 or self.max_jwks_bytes <= 0:
            raise AuthenticationConfigError("token and JWKS size bounds must be positive")

    @classmethod
    def from_env(cls) -> IssuerConfig:
        """Build a validated configuration from explicit environment values."""
        issuer = _required("MTMF_AUTH_ISSUER").rstrip("/")
        realm = _required("MTMF_AUTH_ADMIN_REALM")
        return cls(
            issuer=issuer,
            service_audience=_required("MTMF_AUTH_SERVICE_AUDIENCE"),
            user_audience=_required("MTMF_AUTH_USER_AUDIENCE"),
            jwks_uri=_required("MTMF_AUTH_JWKS_URI"),
            expected_manifest_path=_required("MTMF_AUTH_EXPECTED_MANIFEST"),
            admin_base_url=_required("MTMF_AUTH_ADMIN_BASE").rstrip("/"),
            admin_realm=realm,
            admin_username=_required("MTMF_AUTH_ADMIN_USERNAME"),
            admin_password=_required("MTMF_AUTH_ADMIN_PASSWORD"),
            transport_timeout_seconds=float(
                os.environ.get("MTMF_AUTH_TIMEOUT_SECONDS", "5") or "5"
            ),
            jwks_cache_seconds=float(
                os.environ.get("MTMF_AUTH_JWKS_CACHE_SECONDS", "300") or "300"
            ),
        )
