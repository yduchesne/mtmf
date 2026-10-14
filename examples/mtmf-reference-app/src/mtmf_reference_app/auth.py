"""Independent end-user access-token verification for the reference app.

The reference application is a real Policy Enforcement Point: it must
authenticate the inbound end user **itself**, at its own boundary, before it
constructs any trusted actor context. It reuses a vetted public JWT/JWKS
library (PyJWT) rather than copying MTMF's private trust logic, and it imports
no MTMF trust code.

Every check fails closed: missing/malformed tokens, an untrusted issuer, a
wrong audience, an ID/refresh token, an unexpected algorithm, an expired token,
or an unreachable/invalid JWKS endpoint all raise :class:`AuthenticationError`.
A decoded-but-unverified payload is never trusted. Tokens are never logged or
persisted.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import ssl
from dataclasses import dataclass
from typing import ClassVar

import jwt

from mtmf_reference_app.config import ReferenceAppConfig

__all__ = [
    "AuthenticationError",
    "SessionKeyDeriver",
    "UserTokenVerifier",
    "VerifiedUser",
]

#: Accepted JWT header ``typ`` values. Keycloak marks access tokens ``Bearer``
#: (or ``at+jwt``); ID tokens (``ID``), refresh tokens (``Refresh``), and logout
#: tokens (``Logout``) are explicitly rejected as end-user access tokens.
_ACCEPTED_TOKEN_TYPES: frozenset[str] = frozenset({"bearer", "at+jwt", "jwt"})

#: Pin the asymmetric signature algorithm. Keycloak's development realm uses
#: RS256; accepting an unbounded algorithm set would be a downgrade risk.
_ALGORITHMS: tuple[str, ...] = ("RS256",)

#: Bounded clock-skew allowance for exp/nbf/iat.
_LEEWAY_SECONDS = 30.0


class AuthenticationError(Exception):
    """The inbound end-user access token is missing, invalid, or unverifiable.

    The message is intentionally generic and never contains token material,
    claim values, or the underlying library error.
    """


@dataclass(frozen=True, slots=True)
class VerifiedUser:
    """The cryptographically verified immutable identity of an end user."""

    issuer: str
    subject: str


class UserTokenVerifier:
    """Verify end-user access tokens against the pinned trusted issuer's JWKS."""

    __slots__ = ("_audience", "_issuer", "_jwks_client", "_leeway")

    def __init__(self, config: ReferenceAppConfig) -> None:
        self._issuer = config.issuer
        self._audience = config.user_audience
        self._leeway = _LEEWAY_SECONDS
        ssl_context = ssl.create_default_context(cafile=str(config.ca_bundle))
        self._jwks_client = jwt.PyJWKClient(
            config.jwks_uri,
            cache_keys=True,
            max_cached_keys=8,
            cache_jwk_set=True,
            lifespan=config.jwks_cache_seconds,
            timeout=config.jwks_timeout_seconds,
            ssl_context=ssl_context,
        )

    def verify(self, token: str) -> VerifiedUser:
        """Return the verified ``(issuer, subject)`` or raise fail-closed.

        :raises AuthenticationError: for a missing/blank token, an unexpected
            token type or algorithm, an unverifiable signature/JWKS, a wrong
            issuer/audience, a missing required claim, or a temporal failure.
        """
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError("an end-user access token is required")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("the end-user access token is malformed") from exc
        token_type = header.get("typ")
        if not isinstance(token_type, str) or token_type.lower() not in _ACCEPTED_TOKEN_TYPES:
            raise AuthenticationError("the token is not an end-user access token")
        if header.get("alg") not in _ALGORITHMS:
            raise AuthenticationError("the token uses an unsupported signature algorithm")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("the end-user access token could not be verified") from exc
        subject = claims.get("sub")
        issuer = claims.get("iss")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("the end-user access token has no usable subject")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self._issuer:
            raise AuthenticationError("the end-user access token issuer is not trusted")
        return VerifiedUser(issuer=issuer.rstrip("/"), subject=subject)


class SessionKeyDeriver:
    """Derive an opaque, process-local session key from a verified token.

    The key is a keyed digest of the verified access token under a fresh,
    process-local, domain-separated secret. Raw tokens and digests are never
    logged or persisted, there is no caller-supplied session key, and a restart
    invalidates every derived key. The derivation is only meaningful once the
    signature/claims have already been verified by :class:`UserTokenVerifier`.
    """

    __slots__ = ("_secret",)
    _DOMAIN: ClassVar[bytes] = b"mtmf-reference-app:session-key:v1\x00"

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)

    def derive(self, verified_token: str) -> str:
        """Return a non-reversible, request-scoped session key."""
        return hmac.new(
            self._secret, self._DOMAIN + verified_token.encode("utf-8"), hashlib.sha256
        ).hexdigest()
