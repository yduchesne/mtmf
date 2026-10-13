"""OAuth 2.0 Client Credentials service-token manager.

The manager acquires a *service* access token from the configured trusted
authorization server using exactly one documented client-authentication
method (``client_id``/``client_secret`` in the form body, i.e.
``client_secret_post``). It never requests, stores, or uses an OAuth
refresh token. It caches per client instance in monotonic time, renews
proactively within a bounded leeway, and uses a single-flight lock so
concurrent callers trigger at most one grant.

The manager performs no authorization decision: a token is authentication
material only.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable
from typing import Any

from mtmf_client.config import ClientConfig
from mtmf_client.errors import ClientAuthenticationError, MtmfClientError
from mtmf_client.transport import HttpTransport

__all__ = ["ServiceTokenManager"]

#: A service access token is a bounded opaque string. A larger value is a
#: malformed issuer response, never a usable credential.
_MAX_ACCESS_TOKEN_LENGTH = 16 * 1024

_FORM_GRANT_TYPE = "client_credentials"


def _reject_constant(value: str) -> Any:
    """Reject JSON ``NaN``/``Infinity`` constants."""
    raise ValueError(f"non-finite JSON constant: {value}")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _load_json_object(text: str) -> dict[str, Any]:
    """Parse a token response into a JSON object or fail closed."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except ValueError as exc:
        raise ClientAuthenticationError("the token endpoint returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ClientAuthenticationError("the token endpoint returned a non-object JSON value")
    return value


class ServiceTokenManager:
    """Per-client-instance service access-token cache and single-flight renewal."""

    __slots__ = (
        "_config",
        "_expires_at",
        "_lock",
        "_monotonic_clock",
        "_token",
        "_transport",
    )

    def __init__(
        self,
        config: ClientConfig,
        transport: HttpTransport,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._transport = transport
        self._monotonic_clock = monotonic_clock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at = 0.0

    def get_token(self) -> str:
        """Return a valid service token, acquiring or renewing it as needed.

        :raises ClientAuthenticationError: when no valid token can be obtained.
        """
        with self._lock:
            now = float(self._monotonic_clock())
            if self._token is not None and now < self._expires_at:
                return self._token
            return self._acquire_locked(now)

    def _acquire_locked(self, now: float) -> str:
        """Perform one client-credentials grant. Caller holds the lock."""
        secret = self._config.read_client_secret()
        form: dict[str, str] = {
            "grant_type": _FORM_GRANT_TYPE,
            "client_id": self._config.client_id,
            "client_secret": secret,
        }
        if self._config.scope is not None:
            form["scope"] = self._config.scope
        if self._config.audience is not None:
            form["audience"] = self._config.audience
        try:
            response = self._transport.post_form(self._config.token_endpoint, data=form)
        except MtmfClientError as exc:
            raise ClientAuthenticationError("the token endpoint request failed") from exc
        if response.is_redirect:
            raise ClientAuthenticationError("the token endpoint attempted a redirect")
        if response.status_code != 200:
            raise ClientAuthenticationError("the token endpoint rejected the client credential")
        if response.content_type not in ("application/json", None):
            raise ClientAuthenticationError(
                "the token endpoint returned an unexpected content type"
            )
        payload = _load_json_object(response.body.decode("utf-8", errors="replace"))
        token = payload.get("access_token")
        if not isinstance(token, str) or not token or len(token) > _MAX_ACCESS_TOKEN_LENGTH:
            raise ClientAuthenticationError("the token endpoint returned an invalid access token")
        token_type = payload.get("token_type")
        if not isinstance(token_type, str) or token_type.strip().lower() != "bearer":
            raise ClientAuthenticationError("the token endpoint returned an unsupported token type")
        expires_in = payload.get("expires_in")
        if (
            not isinstance(expires_in, (int, float))
            or isinstance(expires_in, bool)
            or not math.isfinite(expires_in)
            or expires_in <= 0
        ):
            raise ClientAuthenticationError("the token endpoint returned an invalid lifetime")
        lifetime = max(0.0, float(expires_in) - float(self._config.renewal_leeway_seconds))
        self._token = token
        self._expires_at = now + lifetime
        return token
