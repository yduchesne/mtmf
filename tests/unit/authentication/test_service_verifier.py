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


def _sign_raw_payload(payload_text: str) -> str:
    """Sign an arbitrary raw payload segment with the trusted test key."""
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = _b64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": KID, "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload = _b64.urlsafe_b64encode(payload_text.encode()).rstrip(b"=")
    signing_input = header + b"." + payload
    signature = _PRIVATE_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_b64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def test_duplicate_payload_claim_is_rejected_before_verification():
    now = int(time.time())
    payload = (
        '{"iss":"'
        + ISS
        + '","aud":"'
        + SERVICE_AUD
        + '","sub":"s","azp":"a","azp":"b","typ":"Bearer","iat":'
        + str(now)
        + ',"exp":'
        + str(now + 300)
        + "}"
    )
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(_sign_raw_payload(payload), _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_malformed_base64_segment_is_rejected():
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify("aa!.bb.cc", _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_forged_signature_is_rejected():
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = pyjwt.encode(
        {
            "iss": ISS,
            "aud": SERVICE_AUD,
            "sub": "s",
            "azp": "c",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
        },
        other_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(forged, _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_wrong_issuer_is_rejected():
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": "https://evil.example",
            "aud": SERVICE_AUD,
            "sub": "s",
            "azp": "c",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
        },
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.UNTRUSTED_ISSUER


def test_missing_required_time_claims_are_rejected():
    for omitted in ("exp", "iat"):
        now = int(time.time())
        payload = {
            "iss": ISS,
            "aud": SERVICE_AUD,
            "sub": "s",
            "azp": "c",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
        }
        del payload[omitted]
        token = pyjwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
        with pytest.raises(AuthenticationError) as exc:
            _verifier().verify(token, _service_profile())
        assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_none_and_symmetric_algorithms_are_rejected():
    now = int(time.time())
    payload = {
        "iss": ISS,
        "aud": SERVICE_AUD,
        "sub": "s",
        "azp": "c",
        "typ": "Bearer",
        "iat": now,
        "exp": now + 300,
    }
    for alg, key in (("HS256", "symmetric-secret"), ("none", "")):
        token = pyjwt.encode(payload, key, algorithm=alg, headers={"kid": KID})
        with pytest.raises(AuthenticationError) as exc:
            _verifier().verify(token, _service_profile())
        assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_jwks_transport_outage_fails_closed():
    class FailingTransport:
        def get(self, url: str, *, timeout: float, max_bytes: int) -> bytes:
            raise OSError("network down")

    verifier = PyJWTTokenVerifier(
        JwksKeyProvider(JWKS_URI, transport=FailingTransport(), min_refresh_seconds=0)
    )
    with pytest.raises(AuthenticationError) as exc:
        verifier.verify(_mint(), _service_profile())
    assert exc.value.failure is AuthenticationFailure.INFRASTRUCTURE


def test_jwks_key_rotation_refreshes_on_unknown_kid():
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    state = {"current": _jwk("old-kid")}

    class RotatingTransport:
        def get(self, url: str, *, timeout: float, max_bytes: int) -> bytes:
            return json.dumps({"keys": [state["current"]]}).encode()

    provider = JwksKeyProvider(JWKS_URI, transport=RotatingTransport(), min_refresh_seconds=0)
    verifier = PyJWTTokenVerifier(provider)
    verifier.verify(_mint(headers={"kid": "old-kid"}), _service_profile())
    state["current"] = {
        "kid": "new-kid",
        "use": "sig",
        "alg": "RS256",
        **json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(rotated.public_key())),
    }
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": ISS,
            "aud": SERVICE_AUD,
            "sub": "s",
            "azp": "c",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
        },
        rotated,
        algorithm="RS256",
        headers={"kid": "new-kid"},
    )
    verifier.verify(token, _service_profile())


def test_class_predicates_reject_mismatched_binding_and_injected_claims():
    # Service class requires client_id == azp.
    mismatched = _verifier().verify(_mint(client_id="other-client"), _service_profile())
    assert mismatched.is_service_class is False
    # User class requires no client_id.
    injected = _verifier().verify(_mint(aud=USER_AUD, client_id="client-1"), _user_profile())
    assert injected.is_user_class is False


def _unsigned_user_payload(*, azp: str | None) -> str:
    now = int(time.time())
    claims = {
        "iss": ISS,
        "aud": USER_AUD,
        "sub": "user-1",
        "typ": "Bearer",
        "iat": now,
        "exp": now + 300,
    }
    if azp is not None:
        claims["azp"] = azp
    return json.dumps(claims)


def test_dc05_local_key_missing_azp_is_rejected_with_signature_proof():
    """DC05-LOCAL-KEY: an isolated test key signs a real missing-azp token.

    This is explicitly NOT issuer evidence; the Keycloak-signed DC05 remains
    NOT EXECUTED.
    """
    token = _sign_raw_payload(_unsigned_user_payload(azp=None))
    # Prove the signature verifies normally against the trusted test public key.
    proven = pyjwt.decode(
        token,
        _PRIVATE_KEY.public_key(),
        algorithms=["RS256"],
        audience=USER_AUD,
        issuer=ISS,
        leeway=0,
        options={"require": ["exp", "iat"]},
    )
    assert "azp" not in proven
    # The shipped production verifier rejects it with the intended typed failure.
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _user_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN
    # Positive control: the same key/profile with azp verifies.
    assert (
        _verifier()
        .verify(_sign_raw_payload(_unsigned_user_payload(azp="client-1")), _user_profile())
        .is_user_class
    )


def test_dc05_local_key_negative_controls():
    token = _sign_raw_payload(_unsigned_user_payload(azp="client-1"))
    # Tampered signature.
    tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    with pytest.raises(AuthenticationError):
        _verifier().verify(tampered, _user_profile())
    # Missing sub.
    no_sub = _sign_raw_payload(
        json.dumps(
            {
                "iss": ISS,
                "aud": USER_AUD,
                "azp": "c",
                "typ": "Bearer",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
            }
        )
    )
    with pytest.raises(AuthenticationError):
        _verifier().verify(no_sub, _user_profile())
    # Duplicate azp.
    dup = (
        '{"iss":"' + ISS + '","aud":"' + USER_AUD + '","sub":"u","azp":"a","azp":"b",'
        '"typ":"Bearer","iat":'
        + str(int(time.time()))
        + ',"exp":'
        + str(int(time.time()) + 300)
        + "}"
    )
    with pytest.raises(AuthenticationError):
        _verifier().verify(_sign_raw_payload(dup), _user_profile())
    # Wrong audience.
    with pytest.raises(AuthenticationError):
        _verifier().verify(token, _service_profile())
    # Untrusted key (kid not in JWKS).
    with pytest.raises(AuthenticationError):
        _verifier().verify(_mint(headers={"kid": "untrusted"}), _service_profile())


def test_unsupported_critical_header_is_rejected():
    token = _mint(headers={"kid": KID, "crit": ["custom"]})
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(token, _service_profile())
    assert exc.value.failure is AuthenticationFailure.INVALID_TOKEN


def test_malformed_jwks_is_rejected():
    with pytest.raises(AuthenticationError) as unusable:
        _verifier({"keys": [{"kid": KID, "kty": "RSA"}]}).verify(_mint(), _service_profile())
    assert unusable.value.failure is AuthenticationFailure.INVALID_TOKEN
    with pytest.raises(AuthenticationError) as malformed:
        _verifier({"keys": "not-a-list"}).verify(_mint(), _service_profile())
    assert malformed.value.failure is AuthenticationFailure.INFRASTRUCTURE


def test_tokens_are_never_exposed_in_errors_or_repr():
    token = _mint(client_id="client-1")
    verified = _verifier().verify(token, _service_profile())
    assert token not in repr(verified)
    bad = _mint(headers={"kid": "unknown"})
    with pytest.raises(AuthenticationError) as exc:
        _verifier().verify(bad, _service_profile())
    assert bad not in str(exc.value)
