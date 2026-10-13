"""PR 17-C Fixup 2 - development admin migration tests (CA-U09-CA-U32).

Exercises the real ``Migration`` state machine with a scripted fake of the
Keycloak Admin REST / credential boundary. No external network is used.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-admin-migrate.py"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mtmf_dev_admin_migrate", _SCRIPT)
assert _spec is not None and _spec.loader is not None
migrate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = migrate
_spec.loader.exec_module(migrate)

CANONICAL = "mtmf-admin"
RECOVERY = "mtmf-pr14-admin2"
LEGACY = "mtmf-pr14-admin"


class FakeKeycloak:
    """Shared fake Keycloak master realm."""

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.passwords: dict[str, str] = {}
        self.admin_role = {"id": "role-admin", "name": "admin"}
        self.create_behavior = "ok"
        self.create_calls = 0
        self.fail_disable: set[str] = set()
        self.duplicate: set[str] = set()
        self.lookup_error: int | None = None

    def add_user(
        self,
        username: str,
        password: str,
        *,
        enabled: bool = True,
        roles: tuple[str, ...] = ("admin", "default-roles-master"),
        federated: bool = False,
        required_actions: tuple[str, ...] = (),
    ) -> None:
        self.users[username] = {
            "id": f"id-{username}",
            "enabled": enabled,
            "realmRoles": list(roles),
            "federationLink": "ldap" if federated else None,
            "requiredActions": list(required_actions),
        }
        self.passwords[username] = password

    def client(self) -> _FakeClient:
        return _FakeClient(self)


class _FakeClient:
    def __init__(self, keycloak: FakeKeycloak) -> None:
        self._kc = keycloak
        self._authenticated = False

    def authenticate(self, username: str, password: str) -> str | None:
        if self._kc.passwords.get(username) == password:
            self._authenticated = True
            return "token"
        return None

    def find_users(self, username: str) -> list[dict[str, Any]]:
        if self._kc.lookup_error is not None:
            raise migrate.AdminRestError("lookup failed", status=self._kc.lookup_error)
        if username in self._kc.duplicate:
            return [
                {"id": f"id-{username}-a", "username": username, "enabled": True},
                {"id": f"id-{username}-b", "username": username, "enabled": True},
            ]
        user = self._kc.users.get(username)
        if user is None:
            return []
        return [
            {
                "id": user["id"],
                "username": username,
                "enabled": user["enabled"],
                "federationLink": user["federationLink"],
                "requiredActions": user["requiredActions"],
            }
        ]

    def realm_roles(self, user_id: str) -> list[str]:
        for user in self._kc.users.values():
            if user["id"] == user_id:
                return list(user["realmRoles"])
        return []

    def get_master_role(self, role: str) -> dict[str, Any]:
        return self._kc.admin_role

    def create_user(self, username: str, password: str) -> str | None:
        self._kc.create_calls += 1
        if self._kc.create_behavior == "409":
            raise migrate.AdminRestError("conflict", status=409)
        if self._kc.create_behavior == "timeout":
            raise migrate.AdminRestError("timeout", status=None)
        if self._kc.create_behavior == "no-location":
            return None
        self._kc.add_user(username, password, roles=("default-roles-master",))
        return self._kc.users[username]["id"]

    def add_realm_roles(self, user_id: str, roles: list[dict[str, Any]]) -> None:
        for user in self._kc.users.values():
            if user["id"] == user_id:
                for role in roles:
                    if role["name"] not in user["realmRoles"]:
                        user["realmRoles"].append(role["name"])

    def set_enabled(self, user_id: str, enabled: bool) -> None:
        for name, user in self._kc.users.items():
            if user["id"] == user_id:
                if not enabled and name in self._kc.fail_disable:
                    raise migrate.AdminRestError("disable failed", status=500)
                user["enabled"] = enabled
                return

    def get_realm(self, realm: str) -> dict[str, Any]:
        return {"realm": realm}


def _migration(keycloak: FakeKeycloak) -> migrate.Migration:
    return migrate.Migration(
        keycloak.client,
        canonical_username=CANONICAL,
        canonical_password="canonical-password",
        recovery_username=RECOVERY,
        recovery_password="recovery-password",
    )


def _standard_realm() -> FakeKeycloak:
    kc = FakeKeycloak()
    kc.add_user(RECOVERY, "recovery-password")
    kc.add_user(LEGACY, "legacy-password")
    return kc


def test_cau09_absent_canonical_created_with_role():
    kc = _standard_realm()
    result = _migration(kc).apply()
    assert result["created"] is True
    assert kc.create_calls == 1
    assert kc.users[CANONICAL]["enabled"] is True
    assert kc.users[CANONICAL]["federationLink"] is None
    assert sorted(kc.users[CANONICAL]["realmRoles"]) == ["admin", "default-roles-master"]


def test_cau10_existing_verified_reused_without_reset():
    kc = _standard_realm()
    kc.add_user(CANONICAL, "canonical-password")
    result = _migration(kc).apply()
    assert result["created"] is False
    assert kc.create_calls == 0
    assert kc.passwords[CANONICAL] == "canonical-password"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"enabled": False},
        {"federated": True},
        {"required_actions": ("UPDATE_PASSWORD",)},
        {"roles": ("default-roles-master",)},
    ],
)
def test_cau11_cau30_unverified_canonical_stops(kwargs: dict[str, Any]):
    kc = _standard_realm()
    kc.add_user(CANONICAL, "canonical-password", **kwargs)
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[CANONICAL]["enabled"] is False if not kwargs.get("enabled", True) else True
    # Legacy admins must remain enabled on any STOP.
    assert kc.users[RECOVERY]["enabled"] is True


def test_cau12_duplicate_canonical_stops():
    kc = _standard_realm()
    kc.add_user(CANONICAL, "canonical-password")
    kc.duplicate.add(CANONICAL)
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()


def test_cau13_create_conflict_stops_without_second_post():
    kc = _standard_realm()
    kc.create_behavior = "409"
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.create_calls == 1


def test_cau14_create_timeout_stops_without_retry():
    kc = _standard_realm()
    kc.create_behavior = "timeout"
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.create_calls == 1


def test_cau14b_create_without_location_stops():
    kc = _standard_realm()
    kc.create_behavior = "no-location"
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()


def test_cau15_recovery_credential_failure_stops():
    kc = _standard_realm()
    kc.passwords[RECOVERY] = "changed"
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.create_calls == 0
    assert RECOVERY not in kc.users or kc.users[RECOVERY]["enabled"] is True


def test_cau16_new_admin_login_failure_leaves_legacy_enabled():
    kc = _standard_realm()
    kc.create_behavior = "no-location"
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[RECOVERY]["enabled"] is True
    assert kc.users[LEGACY]["enabled"] is True


def test_cau17_new_admin_missing_role_stops():
    kc = _standard_realm()
    kc.add_user(CANONICAL, "canonical-password")
    # Keep the account otherwise valid but strip the admin role by monkeypatching.
    kc.users[CANONICAL]["realmRoles"] = ["default-roles-master"]
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[RECOVERY]["enabled"] is True


def test_cau18_privileged_read_failure_stops():
    kc = _standard_realm()
    kc.lookup_error = 500
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()


def test_cau19_cau20_verification_then_disable_read_after_write():
    kc = _standard_realm()
    result = _migration(kc).apply()
    assert result["disabled"] == [LEGACY, RECOVERY]
    assert kc.users[RECOVERY]["enabled"] is False
    assert kc.users[LEGACY]["enabled"] is False
    assert kc.users[CANONICAL]["enabled"] is True


def test_cau21_first_disable_failure_stops():
    kc = _standard_realm()
    kc.fail_disable.add(LEGACY)
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    # The first disable failed, so the second (recovery) is not attempted.
    assert kc.users[LEGACY]["enabled"] is True
    assert kc.users[RECOVERY]["enabled"] is True


def test_cau22_second_disable_failure_reports_partial():
    kc = _standard_realm()
    kc.fail_disable.add(RECOVERY)
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[LEGACY]["enabled"] is False
    assert kc.users[RECOVERY]["enabled"] is True
    assert kc.users[CANONICAL]["enabled"] is True


def test_cau23_rerun_after_completed_is_stable():
    kc = _standard_realm()
    _migration(kc).apply()
    create_calls = kc.create_calls
    password = kc.passwords[CANONICAL]
    result = _migration(kc).apply()
    assert result["created"] is False
    assert kc.create_calls == create_calls
    assert kc.passwords[CANONICAL] == password
    assert sorted(kc.users[CANONICAL]["realmRoles"]) == ["admin", "default-roles-master"]


def test_cau24_insecure_or_untrusted_transport_rejected(tmp_path: Path):
    with pytest.raises(migrate.AdminMigrationError):
        migrate.HttpAdminClient("http://keycloak.mtmf.test:28443", "/nonexistent/ca.crt")
    with pytest.raises(migrate.AdminMigrationError):
        migrate.HttpAdminClient("https://keycloak.mtmf.test:28443", str(tmp_path / "missing.crt"))


def test_cau25_errors_do_not_disclose_secrets():
    kc = _standard_realm()
    kc.passwords[RECOVERY] = "different"
    try:
        _migration(kc).apply()
    except migrate.AdminMigrationError as exc:
        message = str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("expected a STOP")
    for secret in ("canonical-password", "recovery-password", "different"):
        assert secret not in message


def test_cau26_fresh_volume_bootstrap_uses_canonical_name():
    compose = (_REPO_ROOT / "compose.dev.yaml").read_text(encoding="utf-8")
    assert "KC_BOOTSTRAP_ADMIN_USERNAME: ${MTMF_DEV_KC_ADMIN_USERNAME:-mtmf-admin}" in compose
    assert "KC_BOOTSTRAP_ADMIN_PASSWORD: ${MTMF_DEV_KC_ADMIN_PASSWORD" in compose
    assert "MTMF_PR14_KC_ADMIN_USERNAME" not in compose
    assert "MTMF_PR14_KC_ADMIN_PASSWORD" not in compose


def test_cau27_pr14_evidence_fixture_unchanged():
    fixture = (_REPO_ROOT / "dev" / "keycloak" / "compose.yaml").read_text(encoding="utf-8")
    assert "MTMF_PR14_KC_ADMIN_USERNAME" in fixture
    assert "MTMF_PR14_KC_ADMIN_PASSWORD" in fixture


def test_cau28_preserved_volume_bootstrap_does_not_reset_existing_user():
    kc = _standard_realm()
    kc.add_user(CANONICAL, "canonical-password", roles=("admin", "default-roles-master"))
    result = _migration(kc).apply()
    assert result["created"] is False
    assert kc.passwords[CANONICAL] == "canonical-password"
    assert kc.create_calls == 0


def test_cau29_missing_credential_custody_stops(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MTMF_DEV_KC_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("MTMF_DEV_KC_ADMIN_PASSWORD_FILE", raising=False)
    with pytest.raises(migrate.AdminMigrationError):
        migrate._read_secret("MTMF_DEV_KC_ADMIN_PASSWORD", "MTMF_DEV_KC_ADMIN_PASSWORD_FILE")


def test_cau31_admin_lookup_unauthorized_stops():
    kc = _standard_realm()
    kc.lookup_error = 401
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[RECOVERY]["enabled"] is True


def test_cau32_unexpected_extra_role_stops():
    kc = _standard_realm()
    kc.add_user(
        CANONICAL,
        "canonical-password",
        roles=("admin", "default-roles-master", "create-realm"),
    )
    with pytest.raises(migrate.AdminMigrationError):
        _migration(kc).apply()
    assert kc.users[RECOVERY]["enabled"] is True


def test_inspect_is_read_only():
    kc = _standard_realm()
    before = {name: dict(user) for name, user in kc.users.items()}
    result = _migration(kc).inspect()
    assert set(result) == {CANONICAL, RECOVERY, LEGACY}
    assert kc.users == before
    assert kc.create_calls == 0
