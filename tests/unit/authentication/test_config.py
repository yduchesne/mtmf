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
        "attestation_client_id": "mtmf-attestation-reader",
        "attestation_client_secret": "mtmf-attestation-reader-dev-secret",
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


def test_canonical_development_issuer_is_accepted():
    canonical = "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"
    config = _config(
        issuer=canonical,
        jwks_uri=f"{canonical}/protocol/openid-connect/certs",
        admin_base_url="https://keycloak.mtmf.test:28443",
    )
    assert config.issuer == canonical


def test_canonical_lookalike_issuer_is_rejected():
    with pytest.raises(AuthenticationConfigError):
        _config(
            issuer="https://evil.keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
            jwks_uri="https://evil.keycloak.mtmf.test:28443/certs",
            admin_base_url="https://evil.keycloak.mtmf.test:28443",
        )


def test_jwks_must_belong_to_the_issuer():
    with pytest.raises(AuthenticationConfigError):
        _config(jwks_uri="https://127.0.0.1:28443/other/certs")


def test_non_rs256_algorithm_is_rejected():
    with pytest.raises(AuthenticationConfigError):
        _config(algorithm="HS256")


def test_missing_attestation_reader_credential_is_rejected():
    with pytest.raises(AuthenticationConfigError):
        _config(attestation_client_id="", attestation_client_secret="")


def _env(**overrides: str) -> dict[str, str]:
    base = {
        "MTMF_AUTH_ISSUER": ISS,
        "MTMF_AUTH_SERVICE_AUDIENCE": "mtmf-service-api",
        "MTMF_AUTH_USER_AUDIENCE": "mtmf-user-api",
        "MTMF_AUTH_JWKS_URI": f"{ISS}/protocol/openid-connect/certs",
        "MTMF_AUTH_EXPECTED_MANIFEST": "dev/keycloak/expected-realm-security.json",
        "MTMF_AUTH_ADMIN_BASE": "https://127.0.0.1:28443",
        "MTMF_AUTH_ADMIN_REALM": "mtmf-pr14-dev",
        "MTMF_AUTH_ATTESTATION_CLIENT_ID": "mtmf-attestation-reader",
        "MTMF_AUTH_ATTESTATION_CLIENT_SECRET": "reader-secret",
    }
    base.update(overrides)
    return base


def test_attestation_client_secret_from_file(monkeypatch, tmp_path):
    secret_file = tmp_path / "reader.secret"
    secret_file.write_text("file-secret", encoding="utf-8")
    env = _env()
    env.pop("MTMF_AUTH_ATTESTATION_CLIENT_SECRET")
    env["MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE"] = str(secret_file)
    monkeypatch.setattr("os.environ", env)
    assert IssuerConfig.from_env().attestation_client_secret == "file-secret"


def test_runtime_rejects_admin_password_only(monkeypatch):
    env = _env()
    env.pop("MTMF_AUTH_ATTESTATION_CLIENT_ID")
    env.pop("MTMF_AUTH_ATTESTATION_CLIENT_SECRET")
    env["MTMF_AUTH_ADMIN_USERNAME"] = "admin"
    env["MTMF_AUTH_ADMIN_PASSWORD"] = "admin-password"
    monkeypatch.setattr("os.environ", env)
    with pytest.raises(AuthenticationConfigError):
        IssuerConfig.from_env()
