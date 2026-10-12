"""Unit tests for the development-only issuer configuration profile."""

from __future__ import annotations

import pytest

from mtmf_service.authentication.config import AuthenticationConfigError, IssuerConfig

ISS = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"


def _config(**overrides: object) -> IssuerConfig:
    base: dict[str, object] = {
        "issuer": ISS,
        "service_audience": "mtmf-service-api",
        "user_audience": "mtmf-user-api",
        "jwks_uri": f"{ISS}/protocol/openid-connect/certs",
        "expected_manifest_path": "dev/keycloak/expected-realm-security.json",
        "admin_base_url": "https://127.0.0.1:28443",
        "admin_realm": "mtmf-pr14-dev",
        "admin_username": "admin",
        "admin_password": "secret",
    }
    base.update(overrides)
    return IssuerConfig(**base)  # type: ignore[arg-type]


def test_distinct_audiences_are_accepted_by_default():
    _config()


def test_equal_audiences_are_rejected_without_explicit_shared_profile():
    with pytest.raises(AuthenticationConfigError):
        _config(user_audience="mtmf-service-api")


def test_equal_audiences_are_allowed_only_with_the_shared_profile_flag():
    config = _config(user_audience="mtmf-service-api", allow_shared_audience=True)
    assert config.service_audience == config.user_audience
    assert config.allow_shared_audience is True


def test_non_loopback_issuer_is_rejected():
    with pytest.raises(AuthenticationConfigError):
        _config(issuer="https://idp.example.com/realms/x", jwks_uri="https://idp.example.com/k")


def test_jwks_must_belong_to_the_issuer():
    with pytest.raises(AuthenticationConfigError):
        _config(jwks_uri="https://127.0.0.1:28443/other/certs")


def test_non_rs256_algorithm_is_rejected():
    with pytest.raises(AuthenticationConfigError):
        _config(algorithm="HS256")
