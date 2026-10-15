"""U01/U05 config and fixture-mapping validation."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from helpers import APPLICATION_ID, TENANT_ID, make_config, write_config_files
from mtmf_reference_app.config import (
    ConfigurationError,
    ReferenceAppConfig,
    load_fixture_mapping,
)


def test_valid_config_round_trips(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    assert config.application_id == APPLICATION_ID
    assert config.fixture_mapping.binding_for("allowed-subject") is not None
    assert config.jwks_uri.endswith("/protocol/openid-connect/certs")


def test_renewal_leeway_defaults_and_is_configurable(tmp_path: Path) -> None:
    assert make_config(tmp_path).renewal_leeway_seconds == 30.0
    overridden = make_config(tmp_path, {"MTMF_REFERENCE_APP_RENEWAL_LEEWAY_SECONDS": "45"})
    assert overridden.renewal_leeway_seconds == 45.0


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("MTMF_REFERENCE_APP_ISSUER", "http://issuer.example.test/realms/app"),
        ("MTMF_REFERENCE_APP_ISSUER", ""),
        ("MTMF_REFERENCE_APP_MTMF_BASE_URL", "https://user:pw@mtmf.example.test"),
        ("MTMF_REFERENCE_APP_TOKEN_ENDPOINT", "http://issuer.example.test/token"),
        ("MTMF_REFERENCE_APP_APPLICATION_ID", "not-a-uuid"),
        ("MTMF_REFERENCE_APP_APPLICATION_ID", "00000000-0000-0000-0000-000000000000"),
        ("MTMF_REFERENCE_APP_CLIENT_ID", ""),
        ("MTMF_REFERENCE_APP_CLIENT_SECRET_FILE", "/does/not/exist"),
        ("MTMF_REFERENCE_APP_CA_BUNDLE", "/does/not/exist"),
        ("MTMF_REFERENCE_APP_FIXTURE_MAPPING_PATH", "/does/not/exist"),
    ],
)
def test_invalid_configuration_fails_closed(tmp_path: Path, key: str, value: str) -> None:
    with pytest.raises(ConfigurationError):
        make_config(tmp_path, {key: value})


def test_missing_required_value_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        make_config(tmp_path, {"MTMF_REFERENCE_APP_ISSUER": None})


def test_wide_secret_permissions_are_rejected(tmp_path: Path) -> None:
    env = write_config_files(tmp_path)
    os.chmod(env["MTMF_REFERENCE_APP_CLIENT_SECRET_FILE"], 0o644)
    with pytest.raises(ConfigurationError):
        ReferenceAppConfig.from_env(env)


def test_application_id_must_match_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        make_config(
            tmp_path,
            {"MTMF_REFERENCE_APP_APPLICATION_ID": "99999999-9999-4999-8999-999999999999"},
        )


def test_fixture_mapping_rejects_wrong_version(tmp_path: Path) -> None:
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"version": 2}), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_fixture_mapping(path)


def test_fixture_mapping_rejects_empty_subjects(tmp_path: Path) -> None:
    path = tmp_path / "map.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "application_id": str(APPLICATION_ID),
                "tenant_id": str(TENANT_ID),
                "subjects": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_fixture_mapping(path)


def test_fixture_mapping_rejects_cross_tenant_subject(tmp_path: Path) -> None:
    path = tmp_path / "map.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "application_id": str(APPLICATION_ID),
                "tenant_id": str(TENANT_ID),
                "subjects": {"subject": "22222222-2222-4222-8222-222222222222"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_fixture_mapping(path)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"version": 1, "application_id": "bad", "tenant_id": str(TENANT_ID), "subjects": {}},
        {"version": 1, "application_id": str(APPLICATION_ID), "tenant_id": "bad"},
        {"version": 1, "application_id": str(APPLICATION_ID), "tenant_id": str(TENANT_ID)},
        {
            "version": 1,
            "application_id": str(APPLICATION_ID),
            "tenant_id": str(TENANT_ID),
            "subjects": {"": str(TENANT_ID)},
        },
        {
            "version": 1,
            "application_id": str(APPLICATION_ID),
            "tenant_id": str(TENANT_ID),
            "subjects": {"subject": 7},
        },
    ],
)
def test_fixture_mapping_malformed_payloads(tmp_path: Path, payload: object) -> None:
    path = tmp_path / "map.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_fixture_mapping(path)


def test_private_file_must_be_regular(tmp_path: Path) -> None:
    env = write_config_files(tmp_path)
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(ConfigurationError):
        ReferenceAppConfig.from_env(
            {**env, "MTMF_REFERENCE_APP_CLIENT_SECRET_FILE": str(directory)}
        )


def test_nonpositive_numeric_configuration_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        make_config(tmp_path, {"MTMF_REFERENCE_APP_MTMF_TIMEOUT_SECONDS": "0"})
    with pytest.raises(ConfigurationError):
        make_config(tmp_path, {"MTMF_REFERENCE_APP_JWKS_CACHE_SECONDS": "not-a-number"})


def test_fragment_url_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        make_config(
            tmp_path,
            {"MTMF_REFERENCE_APP_ISSUER": "https://issuer.example.test/realms/app#frag"},
        )
