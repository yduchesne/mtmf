"""Provider-neutral authentication ports.

Implementations live in the owning package: cryptographic/JWKS transport,
configuration, and live issuer attestation are ``mtmf-service`` concerns;
this module defines only the seams the provider-neutral actor-composition
service depends on.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mtmf_core.authentication.contracts import (
    IssuerProfile,
    VerifiedAccessToken,
)

__all__ = ["ConfigurationAttestor", "TokenVerifier"]


@runtime_checkable
class TokenVerifier(Protocol):
    """Verify one raw access token against a trusted issuer profile.

    Implementations must return a fully validated, detached
    :class:`VerifiedAccessToken` or raise
    :class:`~mtmf_core.authentication.contracts.AuthenticationError`. They
    must never return a partially validated token.
    """

    def verify(self, token: str, profile: IssuerProfile) -> VerifiedAccessToken:
        """Verify signature, issuer, audience, class, and temporal claims."""
        ...


@runtime_checkable
class ConfigurationAttestor(Protocol):
    """Attest the live issuer configuration against a trusted baseline.

    Implementations must perform a fresh live read for every call (no
    positive caching) and raise
    :class:`~mtmf_core.authentication.contracts.AuthenticationError` with
    ``ATTESTATION_UNAVAILABLE`` or ``ATTESTATION_DRIFT`` on any failure,
    drift, timeout, or unreadable baseline.
    """

    def attest(self, profile: IssuerProfile) -> None:
        """Fail closed on any unavailable, unreadable, or drifted config."""
        ...
