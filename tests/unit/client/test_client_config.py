"""Configuration and secret-reference tests (plan matrix CL-U02, CL-U03, CL-U04)."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

import pytest
from client_helpers import (
    APP_ID,
    BASE_URL,
    FakeServer,
    StaticSecret,
    build_client,
    make_config,
)

from mtmf_client import (
    ClientConfig,
    ClientConfigurationError,
    FileSecretProvider,
)


def test_cl_u02_valid_config_constructs_without_network() -> None:
    server = FakeServer()
    client, config, _ = build_client(server)
    try:
        assert server.token_calls == 0
        assert server.evaluate_calls == 0
        assert config.base_url == BASE_URL
        assert config.application_id == APP_ID
        assert config.client_id == "mtmf-evidence-same-client"
    finally:
        client.close()


def test_cl_u02_config_defaults_are_conservative() -> None:
    config = make_config()
    assert config.max_snapshot_ttl_seconds == 15
    assert config.clock_uncertainty_seconds == 0.0
    assert config.scope is None
    assert config.audience is None


@pytest.mark.parametrize(
    "override",
    [
        {"base_url": "http://pdp.mtmf.test"},
        {"base_url": "https://user:pass@pdp.mtmf.test"},
        {"base_url": "https://pdp.mtmf.test/#fragment"},
        {"base_url": "https:///no-host"},
        {"base_url": ""},
        {"token_endpoint": "http://keycloak.test/token"},
        {"token_endpoint": "https://keycloak.test/token#frag"},
        {"expected_issuer": "http://issuer.test"},
    ],
)
def test_cl_u03_rejects_unsafe_endpoints(override: dict[str, object]) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(**override)


def test_cl_u03_trailing_slash_is_normalized() -> None:
    config = make_config(base_url=BASE_URL + "/")
    assert config.base_url == BASE_URL


@pytest.mark.parametrize(
    "override",
    [
        {"client_id": ""},
        {"client_id": "   "},
        {"scope": ""},
        {"audience": ""},
        {"connect_timeout": 0},
        {"read_timeout": -1},
        {"write_timeout": 0},
        {"pool_timeout": 0},
        {"max_response_bytes": 0},
        {"renewal_leeway_seconds": -1},
        {"max_snapshot_ttl_seconds": 0},
        {"max_snapshot_ttl_seconds": 301},
        {"clock_uncertainty_seconds": -1},
        {"application_id": None},
    ],
)
def test_cl_u02_rejects_invalid_values(override: dict[str, object]) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(**override)


def test_cl_u04_requires_exactly_one_secret_source(tmp_path: Path) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=None)
    path = tmp_path / "does-not-matter-secret"
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=StaticSecret(), client_secret_file=path)


def test_cl_u04_rejects_missing_and_unsafe_secret_files(tmp_path: Path) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=None, client_secret_file=tmp_path / "missing")
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=None, client_secret_file=tmp_path)
    unsafe = tmp_path / "unsafe-secret"
    unsafe.write_text("shhh", encoding="utf-8")
    os.chmod(unsafe, 0o644)
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=None, client_secret_file=unsafe)


def test_cl_u04_secret_file_read_is_bounded_and_redacted(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    path.write_text("top-secret-value\n", encoding="utf-8")
    os.chmod(path, 0o600)
    config = make_config(secret_provider=None, client_secret_file=path)
    assert config.read_client_secret() == "top-secret-value"
    assert "top-secret-value" not in repr(config)
    assert "top-secret-value" not in repr(FileSecretProvider(path))
    assert "top-secret-value" not in str(config)


def test_cl_u04_empty_secret_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "empty-secret"
    path.write_text("   \n", encoding="utf-8")
    os.chmod(path, 0o600)
    config = make_config(secret_provider=None, client_secret_file=path)
    with pytest.raises(ClientConfigurationError):
        config.read_client_secret()


def test_cl_u04_secret_provider_repr_is_suppressed() -> None:
    config = make_config(secret_provider=StaticSecret("provider-secret"))
    assert "provider-secret" not in repr(config)
    assert config.read_client_secret() == "provider-secret"


def test_cl_u04_ca_bundle_must_be_a_regular_file(tmp_path: Path) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(ca_bundle=str(tmp_path / "nope"))
    with pytest.raises(ClientConfigurationError):
        make_config(ca_bundle=tmp_path)
    with pytest.raises(ClientConfigurationError):
        make_config(ca_bundle=123)  # type: ignore[arg-type]


def test_cl_u04_secret_file_must_be_a_pathlib_path(tmp_path: Path) -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(secret_provider=None, client_secret_file=str(tmp_path / "secret"))  # type: ignore[arg-type]


def test_cl_u04_unreadable_secret_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    path.write_text("value", encoding="utf-8")
    os.chmod(path, 0o600)
    provider = FileSecretProvider(path)
    path.unlink()
    with pytest.raises(ClientConfigurationError):
        provider.read()


def test_cl_u02_application_id_requires_non_nil_uuid() -> None:
    with pytest.raises(ClientConfigurationError):
        make_config(application_id=UUID(int=0))
    with pytest.raises(ClientConfigurationError):
        make_config(application_id="not-a-uuid")


def test_config_is_immutable() -> None:
    config = make_config()
    with pytest.raises((AttributeError, TypeError)):
        config.client_id = "other"  # type: ignore[misc]
    assert isinstance(config, ClientConfig)
