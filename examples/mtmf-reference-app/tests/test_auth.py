"""U04/U10 authentication-adjacent unit behavior."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from helpers import make_config
from mtmf_reference_app.auth import (
    AuthenticationError,
    SessionKeyDeriver,
    UserTokenVerifier,
)


def _unsigned_token(header: dict[str, str], claims: dict[str, str]) -> str:
    def _b64(value: dict[str, str]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(claims)}.signature"


def test_blank_token_is_rejected(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    with pytest.raises(AuthenticationError):
        verifier.verify("   ")


def test_malformed_token_is_rejected(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    with pytest.raises(AuthenticationError):
        verifier.verify("not-a-jwt")


def test_id_token_is_rejected_without_network(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    token = _unsigned_token({"alg": "RS256", "typ": "ID"}, {"sub": "x"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_refresh_token_is_rejected_without_network(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    token = _unsigned_token({"alg": "RS256", "typ": "Refresh"}, {"sub": "x"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_unexpected_algorithm_is_rejected(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    token = _unsigned_token({"alg": "none", "typ": "Bearer"}, {"sub": "x"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_session_keys_are_scoped_and_not_shared() -> None:
    deriver = SessionKeyDeriver()
    first = deriver.derive("token-one")
    assert first != deriver.derive("token-two")
    assert first == deriver.derive("token-one")
    other = SessionKeyDeriver()
    assert other.derive("token-one") != first


@dataclass
class _SigningKey:
    key: str


class _FakeJwksClient:
    """Return a known public key for any token (signature is still verified)."""

    def __init__(self, public_pem: str) -> None:
        self._public_pem = public_pem

    def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
        return _SigningKey(key=self._public_pem)


def _rsa_material() -> tuple[Any, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private, public_pem


def _signed(
    private: Any,
    *,
    issuer: str = "https://issuer.example.test/realms/app",
    audience: str = "app-api",
    expires_in: int = 300,
    subject: str | None = "user-subject",
    typ: str = "Bearer",
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    if subject is not None:
        claims["sub"] = subject
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"typ": typ, "kid": "k1"})


def _verifier(tmp_path: Path, public_pem: str) -> UserTokenVerifier:
    verifier = UserTokenVerifier(make_config(tmp_path))
    verifier._jwks_client = _FakeJwksClient(public_pem)
    return verifier


def test_successful_verification_returns_subject(tmp_path: Path) -> None:
    private, public_pem = _rsa_material()
    verifier = _verifier(tmp_path, public_pem)
    verified = verifier.verify(_signed(private))
    assert verified.subject == "user-subject"
    assert verified.issuer == "https://issuer.example.test/realms/app"


def test_wrong_audience_is_rejected(tmp_path: Path) -> None:
    private, public_pem = _rsa_material()
    verifier = _verifier(tmp_path, public_pem)
    with pytest.raises(AuthenticationError):
        verifier.verify(_signed(private, audience="other-api"))


def test_wrong_issuer_is_rejected(tmp_path: Path) -> None:
    private, public_pem = _rsa_material()
    verifier = _verifier(tmp_path, public_pem)
    with pytest.raises(AuthenticationError):
        verifier.verify(_signed(private, issuer="https://evil.example.test/realms/app"))


def test_expired_token_is_rejected(tmp_path: Path) -> None:
    private, public_pem = _rsa_material()
    verifier = _verifier(tmp_path, public_pem)
    with pytest.raises(AuthenticationError):
        verifier.verify(_signed(private, expires_in=-3600))


def test_missing_subject_is_rejected(tmp_path: Path) -> None:
    private, public_pem = _rsa_material()
    verifier = _verifier(tmp_path, public_pem)
    with pytest.raises(AuthenticationError):
        verifier.verify(_signed(private, subject=None))


def test_unsigned_alg_is_rejected_before_key_lookup(tmp_path: Path) -> None:
    verifier = UserTokenVerifier(make_config(tmp_path))
    token = _unsigned_token({"alg": "RS256", "typ": "Logout"}, {"sub": "x"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)
