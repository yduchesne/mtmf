"""Bounded, fail-closed RS256 access-token verification for the dev issuer.

Transport-only concerns live here: bounded JWKS retrieval/caching, duplicate
claim and duplicate-``kid`` rejection, fixed-algorithm decoding, and strict
issuer/audience/temporal validation. The provider-neutral class predicates
and actor composition remain in ``mtmf-core``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt as pyjwt

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
    VerifiedAccessToken,
)

__all__ = ["JwksKeyProvider", "PyJWTTokenVerifier"]

_JWKS_TIMEOUT = 5.0


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object, rejecting any duplicate member name."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "duplicate JSON claim or JWKS member"
            )
        result[key] = value
    return result


def loads_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate object members."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


class _JwksTransport(Protocol):
    def get(self, url: str, *, timeout: float, max_bytes: int) -> bytes:
        """Return bounded response bytes or raise."""
        ...


class _UrllibJwksTransport:
    """Bounded urllib transport that rejects redirects."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
        ) -> None:
            return None

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(self._NoRedirect())

    def get(self, url: str, *, timeout: float, max_bytes: int) -> bytes:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                data = response.read(max_bytes + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "JWKS transport failed"
            ) from exc
        if len(data) > max_bytes:
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "JWKS response exceeded the size bound"
            )
        return bytes(data)


class JwksKeyProvider:
    """Bounded, duplicate-``kid``-rejecting JWKS key provider with a small cache."""

    def __init__(
        self,
        jwks_uri: str,
        *,
        timeout: float = _JWKS_TIMEOUT,
        max_bytes: int = 262144,
        cache_seconds: float = 300.0,
        min_refresh_seconds: float = 5.0,
        transport: _JwksTransport | None = None,
    ) -> None:
        self._uri = jwks_uri
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._cache_seconds = cache_seconds
        self._min_refresh_seconds = min_refresh_seconds
        self._transport = transport or _UrllibJwksTransport()
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0

    def get_jwk(self, kid: str) -> dict[str, Any]:
        """Return the single JWK for ``kid`` or fail closed."""
        now = time.monotonic()
        if self._keys and kid in self._keys and now - self._fetched_at < self._cache_seconds:
            return self._keys[kid]
        self._refresh(now)
        if kid not in self._keys:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "the signing key is not trusted"
            )
        return self._keys[kid]

    def _refresh(self, now: float) -> None:
        if now - self._last_attempt < self._min_refresh_seconds:
            return
        self._last_attempt = now
        try:
            raw = self._transport.get(self._uri, timeout=self._timeout, max_bytes=self._max_bytes)
        except AuthenticationError:
            raise
        except Exception as exc:  # any transport failure is fail-closed
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "JWKS transport failed"
            ) from exc
        payload = loads_strict(raw.decode())
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
            raise AuthenticationError(
                AuthenticationFailure.INFRASTRUCTURE, "JWKS document is malformed"
            )
        keys: dict[str, dict[str, Any]] = {}
        for jwk in payload["keys"]:
            if not isinstance(jwk, dict):
                raise AuthenticationError(
                    AuthenticationFailure.INFRASTRUCTURE, "JWKS key is malformed"
                )
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                raise AuthenticationError(
                    AuthenticationFailure.INFRASTRUCTURE, "JWKS key is missing a kid"
                )
            if kid in keys:
                raise AuthenticationError(
                    AuthenticationFailure.INFRASTRUCTURE, "JWKS contains a duplicate kid"
                )
            keys[kid] = jwk
        self._keys = keys
        self._fetched_at = now


class PyJWTTokenVerifier:
    """RS256 verifier implementing the provider-neutral ``TokenVerifier`` port."""

    def __init__(
        self,
        key_provider: JwksKeyProvider,
        *,
        max_token_bytes: int = 8192,
        leeway_seconds: int = 0,
    ) -> None:
        self._keys = key_provider
        self._max_token_bytes = max_token_bytes
        self._leeway = leeway_seconds

    def verify(self, token: str, profile: IssuerProfile) -> VerifiedAccessToken:
        """Verify one access token or raise a typed authentication failure."""
        if not token:
            raise AuthenticationError(AuthenticationFailure.INVALID_REQUEST, "token is required")
        if len(token.encode()) > self._max_token_bytes:
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "token is oversized")
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "not a compact JWS")
        header = loads_strict(_b64url_text(parts[0]))
        if not isinstance(header, dict):
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "malformed JOSE header")
        # Parse the payload strictly before signature verification so that a
        # duplicate JSON member is rejected. The parsed value is used only for
        # structural validation; authentication claims come exclusively from
        # the signature-verified ``pyjwt.decode`` result below.
        payload = loads_strict(_b64url_text(parts[1]))
        if not isinstance(payload, dict):
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "malformed JWS payload")
        if set(header) & {"jku", "x5u", "jwk"}:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "untrusted key URL in header"
            )
        if header.get("crit"):
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "unsupported critical header"
            )
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in profile.algorithms or not isinstance(kid, str) or not kid:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "unexpected algorithm or key id"
            )
        jwk = self._keys.get_jwk(kid)
        try:
            key: Any = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        except AuthenticationError:
            raise
        except Exception as exc:  # malformed key material must fail closed
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "unusable signing key"
            ) from exc
        try:
            claims = pyjwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=profile.issuer,
                audience=profile.audience,
                leeway=self._leeway,
                options={"require": ["exp", "iat"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise AuthenticationError(AuthenticationFailure.EXPIRED_TOKEN, "token expired") from exc
        except pyjwt.ImmatureSignatureError as exc:
            raise AuthenticationError(
                AuthenticationFailure.IMMATURE_TOKEN, "token is not yet valid"
            ) from exc
        except pyjwt.InvalidAudienceError as exc:
            raise AuthenticationError(
                AuthenticationFailure.WRONG_AUDIENCE, "audience did not match"
            ) from exc
        except pyjwt.InvalidIssuerError as exc:
            raise AuthenticationError(
                AuthenticationFailure.UNTRUSTED_ISSUER, "issuer did not match"
            ) from exc
        except pyjwt.PyJWTError as exc:
            raise AuthenticationError(
                AuthenticationFailure.INVALID_TOKEN, "token validation failed"
            ) from exc
        return _to_verified(claims, profile)


def _b64url_text(segment: str) -> str:
    import base64
    import binascii
    import re

    if not segment or re.fullmatch(r"[A-Za-z0-9_-]+", segment) is None:
        raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "malformed JWS segment")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode()).decode()
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise AuthenticationError(
            AuthenticationFailure.INVALID_TOKEN, "malformed JWS segment"
        ) from exc


def _to_verified(claims: dict[str, Any], profile: IssuerProfile) -> VerifiedAccessToken:
    subject = claims.get("sub")
    azp = claims.get("azp")
    token_type = claims.get("typ")
    if not isinstance(subject, str) or not subject:
        raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "subject is missing")
    if not isinstance(azp, str) or not azp:
        raise AuthenticationError(
            AuthenticationFailure.INVALID_TOKEN, "authorized party is missing"
        )
    if token_type != "Bearer":
        raise AuthenticationError(
            AuthenticationFailure.WRONG_TOKEN_CLASS, "the token is not an access token"
        )
    raw_client_id = claims.get("client_id")
    if raw_client_id is not None and (not isinstance(raw_client_id, str) or not raw_client_id):
        raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN, "client_id is malformed")
    audiences = claims.get("aud")
    audience_set = frozenset([audiences] if isinstance(audiences, str) else audiences or [])
    return VerifiedAccessToken(
        issuer=profile.issuer,
        subject=subject,
        audiences=audience_set,
        azp=azp,
        client_id=raw_client_id,
        token_type=token_type,
        issued_at=datetime.fromtimestamp(int(claims["iat"]), tz=UTC),
        expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=UTC),
        not_before=(
            datetime.fromtimestamp(int(claims["nbf"]), tz=UTC) if "nbf" in claims else None
        ),
    )
