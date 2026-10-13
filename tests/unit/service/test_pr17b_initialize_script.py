"""Unit tests for PR 17-B Compose wiring and the initializer entry point."""

from __future__ import annotations

import importlib.util
import io
import sys
import urllib.error
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

from mtmf_service.development_bootstrap import BootstrapError

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Import the production initializer entry point exactly as the integration
#: suite does, so these tests exercise the real module object.
_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-initialize.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_initialize_unit", _SCRIPT)
assert _spec is not None and _spec.loader is not None
_script = importlib.util.module_from_spec(_spec)
sys.modules["mtmf_dev_initialize_unit"] = _script
_spec.loader.exec_module(_script)


def _compose() -> dict[str, Any]:
    with (REPO_ROOT / "compose.dev.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


# --------------------------------------------------------------------------
# U24/U26 Compose wiring
# --------------------------------------------------------------------------


def test_u24_initializer_forwards_dev_user_and_tenant_configuration():
    initializer = _compose()["services"]["initializer"]
    environment = initializer["environment"]
    for name in (
        "MTMF_DEV_USER_USERNAME",
        "MTMF_DEV_USER_EMAIL",
        "MTMF_DEV_USER_CREATE",
        "MTMF_DEV_USER_PASSWORD_FILE",
        "MTMF_DEV_USER_SUBJECT",
        "MTMF_DEV_TENANT_KEY",
        "MTMF_DEV_TENANT_NAME",
    ):
        assert name in environment, name
    # The fabricated subject default must be gone.
    assert "mtmf-dev-user" not in environment["MTMF_DEV_USER_SUBJECT"]
    assert environment["MTMF_DEV_USER_CREATE"].endswith(":-false}")


def test_u24_initializer_mounts_secret_directory_read_only():
    initializer = _compose()["services"]["initializer"]
    mounts = initializer.get("volumes", [])
    assert any(str(mount).endswith(":/run/mtmf-secrets:ro") for mount in mounts)


def test_u26_service_never_receives_privileged_or_provisioning_configuration():
    service_environment = _compose()["services"]["service"]["environment"]
    forbidden_fragments = (
        "MTMF_MIGRATOR_",
        "MTMF_DEV_USER_",
        "MTMF_DEV_APPLICATION_KEYS",
        "MTMF_AUTH_ADMIN_PASSWORD",
        "MTMF_AUTH_ADMIN_USERNAME",
        "MTMF_PR14_KC_ADMIN_PASSWORD",
        "MTMF_PR14_KC_ADMIN_USERNAME",
    )
    for name in service_environment:
        for fragment in forbidden_fragments:
            assert fragment not in name, f"{name} leaks {fragment} to the HTTP service"


# --------------------------------------------------------------------------
# entry-point / fixture behavior
# --------------------------------------------------------------------------


def test_preflight_issuer_normalizes_transport_failures_without_leaking():
    provisioner = _script.KeycloakCredentialProvisioner(
        base_url="https://127.0.0.1:28443",
        realm="mtmf-pr14-dev",
        admin_username="admin",
        admin_password="secret-admin-password",
    )

    def http_error(method: str, path: str, body: Any = None) -> Any:
        raise urllib.error.HTTPError(
            "https://127.0.0.1:28443/realms/master", 400, "bad", {}, io.BytesIO(b"secret")
        )

    provisioner._request = http_error  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="HTTP 400") as excinfo:
        provisioner.preflight_issuer("https://127.0.0.1:28443/realms/mtmf-pr14-dev")
    assert "secret-admin-password" not in str(excinfo.value)

    with pytest.raises(BootstrapError, match="trust anchor is empty"):
        provisioner.preflight_issuer("")

    def network_error(method: str, path: str, body: Any = None) -> Any:
        raise urllib.error.URLError("connection refused")

    provisioner._request = network_error  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="could not be completed"):
        provisioner.preflight_issuer("https://127.0.0.1:28443/realms/mtmf-pr14-dev")


def test_test_failpoint_is_inert_by_default_and_triggers_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(_script.TEST_FAILPOINT_ENV, raising=False)
    _script._reach_test_failpoint("after-user-verify")  # inert
    monkeypatch.setenv(_script.TEST_FAILPOINT_ENV, "after-user-verif")
    _script._reach_test_failpoint("after-user-verify")  # inert near miss
    monkeypatch.setenv(_script.TEST_FAILPOINT_ENV, "some-other-failpoint")
    _script._reach_test_failpoint("after-user-verify")  # inert different value
    monkeypatch.setenv(_script.TEST_FAILPOINT_ENV, "after-user-verify")
    with pytest.raises(SystemExit) as excinfo:
        _script._reach_test_failpoint("after-user-verify")
    assert excinfo.value.code == 99


def test_entry_point_failpoint_stops_before_any_mtmf_write(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_development_env(monkeypatch, MTMF_DEV_TEST_FAILPOINT="after-user-verify")
    monkeypatch.setattr(_script, "PostgresProvisioner", lambda config: _FakeProvisioner(config))
    monkeypatch.setattr(_script, "KeycloakCredentialProvisioner", _FakeKeycloak)

    def explode(**kwargs: Any) -> None:
        raise AssertionError("the MTMF bootstrap must not run after the failpoint")

    monkeypatch.setattr(_script, "DevelopmentBootstrap", explode)
    with pytest.raises(SystemExit) as excinfo:
        _script.main([])
    assert excinfo.value.code == 99


def test_dev_fixture_uses_the_verified_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MTMF_AUTH_ISSUER", "https://127.0.0.1:28443/realms/mtmf-pr14-dev")
    monkeypatch.setenv("MTMF_AUTH_SERVICE_AUDIENCE", "mtmf-service-api")
    monkeypatch.setenv("MTMF_AUTH_USER_AUDIENCE", "mtmf-user-api")
    fixture = _script._dev_fixture("keycloak-real-sub")
    assert fixture.user.subject == "keycloak-real-sub"


def test_no_fabricated_default_subject_remains_in_source():
    source = _SCRIPT.read_text(encoding="utf-8")
    assert "mtmf-dev-user" not in source
    assert 'MTMF_DEV_USER_SUBJECT", "' not in source


class _FakeProvisioner:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.migrated = False

    def apply_migrations_and_verify(self) -> None:
        self.migrated = True


class _FakeKeycloak:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.realm = kwargs["realm"]
        self.preflight: str | None = None
        self.users = [{"id": "real-kc-sub", "username": "dev-user", "enabled": True}]

    def preflight_issuer(self, expected_issuer: str) -> None:
        self.preflight = expected_issuer

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        if method == "GET":
            return list(self.users)
        return None


class _RecordingBootstrap:
    captured: ClassVar[dict[str, Any]] = {}

    def __init__(
        self,
        *,
        mode: Any,
        fixture: Any,
        provisioning: Any,
        credentials: Any,
        lock: Any,
    ) -> None:
        _RecordingBootstrap.captured["subject"] = fixture.user.subject
        _RecordingBootstrap.captured["mode"] = mode

    def run(self) -> None:
        _RecordingBootstrap.captured["ran"] = True


def _set_development_env(monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
    base = {
        "MTMF_SERVICE_DEPLOYMENT_MODE": "development",
        "MTMF_AUTH_ISSUER": "https://127.0.0.1:28443/realms/mtmf-pr14-dev",
        "MTMF_AUTH_ADMIN_REALM": "mtmf-pr14-dev",
        "MTMF_DEV_USER_USERNAME": "dev-user",
        "MTMF_MIGRATOR_DATABASE_URL": "postgresql://mtmf_migrator:x@127.0.0.1:25432/mtmf",
    }
    base.update(extra)
    for name, value in base.items():
        monkeypatch.setenv(name, value)


def test_u16_production_profile_is_refused_before_any_keycloak_or_db_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "production")

    def explode(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("no privileged object may be constructed in the production profile")

    monkeypatch.setattr(_script, "PostgresProvisioner", explode)
    monkeypatch.setattr(_script, "KeycloakCredentialProvisioner", explode)
    assert _script.main([]) == 2


def test_u23_migrations_only_never_touches_keycloak_user_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_development_env(monkeypatch)
    fake = _FakeProvisioner(None)
    monkeypatch.setattr(_script, "PostgresProvisioner", lambda config: fake)

    def explode(**kwargs: Any) -> None:
        raise AssertionError("migrations-only must not construct the Keycloak client")

    monkeypatch.setattr(_script, "KeycloakCredentialProvisioner", explode)
    assert _script.main(["--migrations-only"]) == 0
    assert fake.migrated is True


def test_entry_point_binds_verified_subject_not_fixture_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_development_env(monkeypatch)
    _RecordingBootstrap.captured = {}
    monkeypatch.setattr(_script, "PostgresProvisioner", lambda config: _FakeProvisioner(config))
    monkeypatch.setattr(_script, "KeycloakCredentialProvisioner", _FakeKeycloak)
    monkeypatch.setattr(_script, "DevelopmentBootstrap", _RecordingBootstrap)
    assert _script.main([]) == 0
    assert _RecordingBootstrap.captured["subject"] == "real-kc-sub"
    assert _RecordingBootstrap.captured["ran"] is True


def test_entry_point_fails_closed_when_assertion_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_development_env(monkeypatch, MTMF_DEV_USER_SUBJECT="wrong-sub")
    monkeypatch.setattr(_script, "PostgresProvisioner", lambda config: _FakeProvisioner(config))
    monkeypatch.setattr(_script, "KeycloakCredentialProvisioner", _FakeKeycloak)

    def explode(**kwargs: Any) -> None:
        raise BootstrapError("no MTMF binding")

    monkeypatch.setattr(_script, "DevelopmentBootstrap", explode)
    assert _script.main([]) == 1
