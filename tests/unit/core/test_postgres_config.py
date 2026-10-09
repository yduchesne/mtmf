"""Unit tests for explicit MTMF PostgreSQL configuration (no database).

The fail-closed configuration boundary is a security-relevant invariant:
MTMF integration tooling must never guess, probe for, or fall back to
another PostgreSQL instance when ``MTMF_*`` configuration is missing,
malformed, or ambiguous.
"""

from __future__ import annotations

import pytest

from mtmf_core.persistence.postgres.config import (
    DEFAULT_PORT,
    PostgresConfig,
    PostgresConfigError,
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "MTMF_DATABASE_URL",
        "MTMF_POSTGRES_HOST",
        "MTMF_POSTGRES_PORT",
        "MTMF_POSTGRES_DB",
        "MTMF_POSTGRES_USER",
        "MTMF_POSTGRES_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)


def _components() -> dict[str, str]:
    return {
        "MTMF_POSTGRES_HOST": "127.0.0.1",
        "MTMF_POSTGRES_PORT": "25432",
        "MTMF_POSTGRES_DB": "mtmf",
        "MTMF_POSTGRES_USER": "mtmf",
        "MTMF_POSTGRES_PASSWORD": "mtmf-dev-password",
    }


def test_missing_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PostgresConfigError):
        PostgresConfig.from_env()


def test_each_required_component_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "MTMF_POSTGRES_HOST",
        "MTMF_POSTGRES_DB",
        "MTMF_POSTGRES_USER",
        "MTMF_POSTGRES_PASSWORD",
    ):
        monkeypatch.setattr("os.environ", {**_components(), name: ""})
        with pytest.raises(PostgresConfigError):
            PostgresConfig.from_env()
        monkeypatch.undo()


def test_complete_component_configuration_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.environ", _components())
    config = PostgresConfig.from_env()
    assert config.host == "127.0.0.1"
    assert config.port == DEFAULT_PORT
    assert config.database == "mtmf"
    assert config.user == "mtmf"


def test_port_defaults_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    components = {**_components(), "MTMF_POSTGRES_PORT": ""}
    monkeypatch.setattr("os.environ", components)
    assert PostgresConfig.from_env().port == DEFAULT_PORT

    monkeypatch.setattr("os.environ", {**_components(), "MTMF_POSTGRES_PORT": "not-a-port"})
    with pytest.raises(PostgresConfigError):
        PostgresConfig.from_env()

    for bad in ("0", "70000", "-1"):
        monkeypatch.setattr("os.environ", {**_components(), "MTMF_POSTGRES_PORT": bad})
        with pytest.raises(PostgresConfigError):
            PostgresConfig.from_env()


def test_ambiguous_url_and_components_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "os.environ",
        {
            **_components(),
            "MTMF_DATABASE_URL": "postgresql+psycopg://mtmf:pw@127.0.0.1:25432/mtmf",
        },
    )
    with pytest.raises(PostgresConfigError):
        PostgresConfig.from_env()


def test_database_url_form(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "os.environ",
        {"MTMF_DATABASE_URL": "postgresql+psycopg://alice:s3cr3t@dbhost:6000/mtmfdb"},
    )
    config = PostgresConfig.from_env()
    assert config.user == "alice"
    assert config.password == "s3cr3t"
    assert config.host == "dbhost"
    assert config.port == 6000
    assert config.database == "mtmfdb"
    assert "alice:s3cr3t@dbhost:6000" in config.sqlalchemy_url


def test_database_url_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    for bad_url in (
        "mysql://u:p@host/db",
        "postgresql+psycopg://host/db",
        "postgresql+psycopg://",
        "postgresql+psycopg://u:p@host",
    ):
        monkeypatch.setattr("os.environ", {"MTMF_DATABASE_URL": bad_url})
        with pytest.raises(PostgresConfigError):
            PostgresConfig.from_env()


def test_special_characters_survive_derived_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "os.environ",
        {
            **_components(),
            "MTMF_POSTGRES_PASSWORD": "p@s s w:ord/with$ch%ars",
            "MTMF_POSTGRES_USER": "mt mf",
        },
    )
    config = PostgresConfig.from_env()
    dsn = config.psycopg_dsn
    assert "host=" in dsn and "dbname=mtmf" in dsn
    # psycopg conninfo single-quotes values with spaces; the SQLAlchemy
    # URL percent-encodes them. Both remain safe for transport.
    assert "user='mt mf'" in dsn
    assert "p%40s%20s%20w%3Aord%2Fwith%24ch%25ars" in config.sqlalchemy_url
    assert "mt%20mf" in config.sqlalchemy_url
    assert " " not in config.sqlalchemy_url  # everything is percent-encoded
