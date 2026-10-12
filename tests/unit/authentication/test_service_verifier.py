"""Unit acceptance tests for the bounded RS256 token verifier.

Tokens are minted locally with an isolated RSA key pair and a fake JWKS
network transport, so cryptographic verification actually runs without a
live issuer.
"""

from __future__ import annotations

import json
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
)
from mtmf_service.authentication.jwt_verifier import (
    JwksKeyProvider,
    PyJWTTokenVerifier,
    loads_strict,
)

ISS = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
JWKS_URI = f"{ISS}/protocol/openid-connect/certs"
SERVICE_AUD = "mtmf-service-api"
USER_AUD = "mtmf-user-api"
KID = "test-kid-1"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeTransport:
    """Deterministic JWKS transport returning a fixed document."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls = 0

    def get(self, url: str, *, timeout: float, max_bytes: int) -> bytes:
        self.calls += 1
        return json.dumps(self.payload).encode()


def _jwk(kid: str = KID) -> dict[str, Any]:
    body = json.loads(
        pyjwt.algorithms.RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key())  # type: ignore[arg-type]
    )
    return {"kid": kid, "use": "sig", "alg": "RS256", **body}


def _provider(payload: dict[str, Any]) -> JwksKeyProvider:
    return JwksKeyProvider(
        JWKS_URI, transport=FakeTransport(payload), cache_seconds=300, min_refresh_seconds=0
    )


def _verifier(payload: dict[str, Any] | None = None) -> PyJWTTokenVerifier:
    jwks = payload or {"keys": [_jwk()]}
    return PyJWTTokenVerifier(_provider(jwks), max_token_bytes=8192)


def _mint(
    *,
    aud: str = SERVICE_AUD,
    sub: str = "subject-1",
    azp: str = "client-1",
    typ: str = "Bearer",
    client_id: str | None = None,
    iat: int | None = None,
    exp: int | None = None,
    nbf: int | None = None,
    alg: str = "RS256",
    headers: dict[str, Any] | None = None,
    key: Any = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": ISS,
        "aud": aud,
        "sub": sub,
        "azp": azp,
        "typ": typ,
        "iat": now if iat is None else iat,
        "exp": now + 300 if exp is None else exp,
    }
    if client_id is not None:
        payload["client_id"] = client_id
    if nbf is not None:
        payload["nbf"] = nbf
    merged_headers = {"kid": KID}
    merged_headers.update(headers or {})
    return pyjwt.encode(
        payload, key if key is not None else _PRIVATE_KEY, algorithm=alg, headers=merged_headers
    )


def _service_profile() -> IssuerProfile:
    return IssuerProfile(issuer=ISS, audience=SERVICE_AUD, jwks_uri=JWKS_URI)


def _user_profile() -> IssuerProfile:
    return IssuerProfile(issuer=ISS, audience=USER_AUD, jwks_uri=JWKS_URI)


def test_service_token_is_verified_and_classified():
    token = _mint(client_id="client-1")
    verified = _verifier().verify(token, _service_profile())
    assert verified.is_service_class is True
    assert verified.is_user_class is False


def test_user_token_is_verified_and_classified():
    token = _mint(aud=USER_AUD)
    verified = _verifier().verify(token, _user_profile())
    assert verified.is_user_class is True
    assert verified.is_service_class is False


def test_id_token_is_rejected_as_access_token():
    token = _mint(typ="ID", aud=USER_AUD)
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _user_profile())
    assert exc.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS


def test_refresh_token_is_rejected_as_access_token():
    token = _mint(typ="Refresh", alg="HS256", key="symmetric-secret")
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _user_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_wrong_audience_is_rejected():
    token = _mint(aud=USER_AUD)
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.WRONG_AUDIENCE


def test_expired_token_is_rejected_with_zero_leeway():
    token = _mint(exp=int(time.time()) - 1)
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.EXPIRED_TOKEN


def test_future_issued_at_is_rejected():
    token = _mint(iat=int(time.time()) + 600)
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.IMMATURE_TOKEN


def test_future_not_before_is_rejected():
    token = _mint(nbf=int(time.time()) + 600)
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.IMMATURE_TOKEN


def test_unknown_kid_is_rejected():
    token = _mint(headers={"kid": "unknown"})
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_duplicate_jwks_kid_is_rejected():
    with pytest.raises(AuthenticationError) as exc:
        _verifier({"keys": [_jwk(), _jwk()]}).verify(_mint(), _service_profile())
    assert exc.value.failure is AuthenticationFailure.INFRASTRUCTURE


def test_untrusted_header_key_url_is_rejected():
    token = _mint(headers={"jku": "https://evil.example/jwks", "kid": KID})
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_oversized_token_is_rejected():
    token = _mint() + "." + "A" * 9000
    with pytest.raises(AuthenticationError) as exc:
        PyJWTTokenVerifier(_provider({"keys": [_jwk()]}), max_token_bytes=256).verify(
            token, _service_profile()
        )
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_duplicate_json_claim_is_rejected():
    with pytest.raises(AuthenticationError) as exc:
        loads_strict('{"azp":"a","azp":"b"}')
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_provider_neutral_class_properties():
    service = _verifier().verify(_mint(client_id="client-1"), _service_profile())
    user = _verifier().verify(_mint(aud=USER_AUD), _user_profile())
    assert service.is_service_class and not service.is_user_class
    assert user.is_user_class and not user.is_service_class
