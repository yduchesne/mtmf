"""Unit tests for the PR 17-B development Keycloak user provisioner."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from mtmf_service.development_bootstrap import BootstrapError
from mtmf_service.development_user import (
    DevUserConfig,
    DevUserConfigurationError,
    KeycloakDevUserProvisioner,
    load_dev_user_password,
)

REALM = "mtmf-pr14-dev"


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeTransport:
    """A deterministic, call-recording Admin REST double."""

    def __init__(self, users: list[dict[str, Any]] | None = None) -> None:
        self.users = [dict(user) for user in (users or [])]
        self.calls: list[tuple[str, str, Any]] = []
        self.post_hook: Any = None

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        self.calls.append((method, path, body))
        if method == "GET":
            return [dict(user) for user in self.users]
        if method == "POST":
            if self.post_hook is not None:
                self.post_hook(self, body)
            return None
        raise AssertionError(f"unexpected method {method!r}")


def _user(
    username: str = "dev-user",
    *,
    subject: str = "subject-123",
    enabled: bool = True,
    email: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {"id": subject, "username": username, "enabled": enabled}
    if email is not None:
        row["email"] = email
    row.update(extra)
    return row


def _config(
    *,
    username: str = "dev-user",
    email: str | None = None,
    create: bool = False,
    password_file: Path | None = None,
    expected_subject: str | None = None,
) -> DevUserConfig:
    return DevUserConfig(
        username=username,
        email=email,
        create=create,
        password_file=password_file,
        expected_subject=expected_subject,
    )


def _http_error(code: int = 401, body: bytes = b'{"error":"admin-password=SUPERSECRET"}') -> Any:
    return urllib.error.HTTPError(
        "https://127.0.0.1:28443/admin", code, "failure", {}, io.BytesIO(body)
    )


def _provisioner(transport: FakeTransport) -> KeycloakDevUserProvisioner:
    return KeycloakDevUserProvisioner(transport, REALM, lookup_attempts=1, retry_delay=0)


def _secure_password_file(tmp_path: Path, content: str = "dev-pass-123") -> Path:
    target = tmp_path / "dev-user-password"
    target.write_text(content)
    target.chmod(0o600)
    return target


# --------------------------------------------------------------------------
# U01-U05 happy paths
# --------------------------------------------------------------------------


def test_u01_existing_user_returns_real_id_without_mutation():
    transport = FakeTransport([_user(subject="kc-sub-1")])
    subject = _provisioner(transport).ensure_user(_config())
    assert subject == "kc-sub-1"
    assert [call[0] for call in transport.calls] == ["GET"]
    assert transport.calls[0][1].endswith(
        "/realms/mtmf-pr14-dev/users?username=dev-user&exact=true"
    )


def test_u02_missing_user_create_once_and_reread(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        fake.users.append(_user(body["username"], subject="kc-sub-new", email=body.get("email")))

    transport.post_hook = hook
    subject = _provisioner(transport).ensure_user(
        _config(create=True, password_file=_secure_password_file(tmp_path))
    )
    assert subject == "kc-sub-new"
    assert [call[0] for call in transport.calls] == ["GET", "POST", "GET"]
    post_body = transport.calls[1][2]
    assert post_body["credentials"] == [
        {"type": "password", "value": "dev-pass-123", "temporary": False}
    ]


def test_u03_matching_expected_subject_is_accepted():
    transport = FakeTransport([_user(subject="kc-sub-1")])
    subject = _provisioner(transport).ensure_user(_config(expected_subject="kc-sub-1"))
    assert subject == "kc-sub-1"


def test_u04_existing_user_never_reads_password_file(tmp_path: Path):
    # A directory as the password path would fail if it were ever opened.
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    transport = FakeTransport([_user(subject="kc-sub-1")])
    subject = _provisioner(transport).ensure_user(_config(create=True, password_file=directory))
    assert subject == "kc-sub-1"
    assert [call[0] for call in transport.calls] == ["GET"]


def test_u05_repeated_invocation_is_stable():
    transport = FakeTransport([_user(subject="kc-sub-1")])
    provisioner = _provisioner(transport)
    assert provisioner.ensure_user(_config()) == "kc-sub-1"
    assert provisioner.ensure_user(_config()) == "kc-sub-1"
    assert [call[0] for call in transport.calls] == ["GET", "GET"]


# --------------------------------------------------------------------------
# U06-U10 fail-closed lookup paths
# --------------------------------------------------------------------------


def test_u06_missing_user_with_creation_disabled_fails_before_post():
    transport = FakeTransport([])
    with pytest.raises(BootstrapError, match="creation is not enabled"):
        _provisioner(transport).ensure_user(_config(create=False))
    assert [call[0] for call in transport.calls] == ["GET"]


def test_u07_expected_subject_mismatch_fails():
    transport = FakeTransport([_user(subject="kc-sub-1")])
    with pytest.raises(BootstrapError, match="assertion does not match"):
        _provisioner(transport).ensure_user(_config(expected_subject="other-sub"))


def test_u08_email_mismatch_or_disabled_fails_without_repair():
    email_transport = FakeTransport([_user(email="someone-else@example.invalid")])
    with pytest.raises(BootstrapError, match="email does not match"):
        _provisioner(email_transport).ensure_user(_config(email="expected@example.invalid"))
    assert [call[0] for call in email_transport.calls] == ["GET"]

    disabled_transport = FakeTransport([_user(enabled=False)])
    with pytest.raises(BootstrapError, match="disabled"):
        _provisioner(disabled_transport).ensure_user(_config())
    assert [call[0] for call in disabled_transport.calls] == ["GET"]


def test_u09_multiple_exact_users_is_ambiguous():
    transport = FakeTransport([_user(subject="a"), _user(subject="b")])
    with pytest.raises(BootstrapError, match="multiple Keycloak users"):
        _provisioner(transport).ensure_user(_config())


def test_u10_fuzzy_only_matches_are_treated_as_absent():
    transport = FakeTransport([_user(username="dev-user-other", subject="fuzzy")])
    with pytest.raises(BootstrapError, match="creation is not enabled"):
        _provisioner(transport).ensure_user(_config(create=False))
    # The fuzzy record is never selected even when creation is enabled.
    transport.post_hook = None
    with pytest.raises(BootstrapError):
        _provisioner(transport).ensure_user(_config(create=True))


# --------------------------------------------------------------------------
# U11 password file safety
# --------------------------------------------------------------------------


def test_u11_unsafe_password_files_are_rejected_before_creation(tmp_path: Path):
    cases: list[Path] = []
    missing = tmp_path / "missing"
    cases.append(missing)

    empty = tmp_path / "empty"
    empty.write_text("")
    empty.chmod(0o600)
    cases.append(empty)

    insecure = tmp_path / "insecure"
    insecure.write_text("secret")
    insecure.chmod(0o644)
    cases.append(insecure)

    directory = tmp_path / "directory"
    directory.mkdir()
    cases.append(directory)

    real = tmp_path / "real"
    real.write_text("secret")
    real.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    cases.append(link)

    for path in cases:
        transport = FakeTransport([])
        with pytest.raises(DevUserConfigurationError):
            _provisioner(transport).ensure_user(_config(create=True, password_file=path))
        assert [call[0] for call in transport.calls] == ["GET"], path


def test_u11_missing_password_configuration_is_rejected():
    transport = FakeTransport([])
    with pytest.raises(DevUserConfigurationError, match="PASSWORD_FILE is not configured"):
        _provisioner(transport).ensure_user(_config(create=True, password_file=None))


def test_load_password_strips_one_trailing_newline(tmp_path: Path):
    target = _secure_password_file(tmp_path, "secret-value\n")
    assert load_dev_user_password(target) == "secret-value"


# --------------------------------------------------------------------------
# U12 configuration validation
# --------------------------------------------------------------------------


def test_u12_invalid_configuration_is_rejected_without_io():
    with pytest.raises(DevUserConfigurationError, match="USERNAME is required"):
        DevUserConfig.from_env({})
    with pytest.raises(DevUserConfigurationError, match="non-empty username"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "   "})
    with pytest.raises(DevUserConfigurationError, match="control characters"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev\x00user"})
    with pytest.raises(DevUserConfigurationError, match="URL-reserved"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev/user"})
    with pytest.raises(DevUserConfigurationError, match="canonical lowercase"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "Dev-User"})
    with pytest.raises(DevUserConfigurationError, match="exactly 'true' or 'false'"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_CREATE": "yes"})
    with pytest.raises(DevUserConfigurationError, match="non-empty subject"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_SUBJECT": "  "})


def test_u12_valid_configuration_defaults():
    config = DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev-user"})
    assert config == _config()
    assert config.create is False
    assert config.password_file is None
    assert config.expected_subject is None


def test_u12_empty_compose_subject_is_absent_and_real_assertion_is_kept():
    assert (
        DevUserConfig.from_env(
            {"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_SUBJECT": ""}
        ).expected_subject
        is None
    )
    assert (
        DevUserConfig.from_env(
            {"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_SUBJECT": "kc-sub"}
        ).expected_subject
        == "kc-sub"
    )


# --------------------------------------------------------------------------
# U13-U14 transport and response failures
# --------------------------------------------------------------------------


@pytest.mark.parametrize("code", [401, 403, 404, 500, 503])
def test_u13_http_status_fails_closed_and_redacted(code: int):
    transport = FakeTransport([])
    transport.post_hook = None
    transport.request = lambda method, path, body=None: _raise(_http_error(code))  # type: ignore[method-assign]
    with pytest.raises(BootstrapError) as excinfo:
        _provisioner(transport).ensure_user(_config())
    message = str(excinfo.value)
    assert str(code) in message
    assert "SUPERSECRET" not in message
    assert "admin-password" not in message


def _raise(error: BaseException) -> Any:
    raise error


def test_u13_network_failure_fails_closed():
    transport = FakeTransport([])

    def failing(method: str, path: str, body: Any = None) -> Any:
        raise urllib.error.URLError("connection refused")

    transport.request = failing  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="could not be completed"):
        _provisioner(transport).ensure_user(_config())


def test_u14_malformed_responses_are_rejected():
    not_a_list = FakeTransport([])
    not_a_list.request = lambda method, path, body=None: {"unexpected": True}  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="invalid response"):
        _provisioner(not_a_list).ensure_user(_config())

    non_dict_row = FakeTransport([])
    non_dict_row.request = lambda method, path, body=None: ["not-a-dict"]  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="invalid record"):
        _provisioner(non_dict_row).ensure_user(_config())

    missing_id = FakeTransport([])
    missing_id.request = lambda method, path, body=None: [{"username": "dev-user"}]  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="stable identifier"):
        _provisioner(missing_id).ensure_user(_config())

    wrong_enabled = FakeTransport([])
    wrong_enabled.request = lambda method, path, body=None: [  # type: ignore[method-assign]
        {"id": "x", "username": "dev-user", "enabled": "yes"}
    ]
    with pytest.raises(BootstrapError, match="enabled state"):
        _provisioner(wrong_enabled).ensure_user(_config())

    malformed_json = FakeTransport([])

    def raise_json(method: str, path: str, body: Any = None) -> Any:
        raise json.JSONDecodeError("bad", "", 0)

    malformed_json.request = raise_json  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="malformed"):
        _provisioner(malformed_json).ensure_user(_config())


def test_u14_federated_and_managed_accounts_are_rejected():
    federated = FakeTransport([_user(federationLink="ldap://example")])
    with pytest.raises(BootstrapError, match="federated or managed"):
        _provisioner(federated).ensure_user(_config())

    managed = FakeTransport([_user(serviceAccountClientId="svc")])
    with pytest.raises(BootstrapError, match="federated or managed"):
        _provisioner(managed).ensure_user(_config())

    brokered = FakeTransport([_user(origin="github")])
    with pytest.raises(BootstrapError, match="federated or managed"):
        _provisioner(brokered).ensure_user(_config())


# --------------------------------------------------------------------------
# U17-U22 edge cases
# --------------------------------------------------------------------------


def test_u17_fuzzy_neighbours_are_filtered_but_exact_is_used():
    transport = FakeTransport(
        [
            _user(username="dev", subject="near-1"),
            _user(username="dev-user", subject="exact"),
        ]
    )
    assert _provisioner(transport).ensure_user(_config()) == "exact"


def test_u18_special_username_is_url_encoded():
    transport = FakeTransport([_user(username="dev+user@example", subject="exact")])
    subject = _provisioner(transport).ensure_user(_config(username="dev+user@example"))
    assert subject == "exact"
    assert transport.calls[0][1].endswith("username=dev%2Buser%40example&exact=true")


def test_u19_conflict_after_commit_is_reconciled_with_a_single_post(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        fake.users.append(_user(body["username"], subject="kc-raced"))
        raise _http_error(409, b'{"errorMessage":"User exists"}')

    transport.post_hook = hook
    subject = _provisioner(transport).ensure_user(
        _config(create=True, password_file=_secure_password_file(tmp_path))
    )
    assert subject == "kc-raced"
    assert [call[0] for call in transport.calls] == ["GET", "POST", "GET"]


def test_u19_timeout_after_commit_is_reconciled(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        fake.users.append(_user(body["username"], subject="kc-timeout"))
        raise urllib.error.URLError("timed out")

    transport.post_hook = hook
    subject = _provisioner(transport).ensure_user(
        _config(create=True, password_file=_secure_password_file(tmp_path))
    )
    assert subject == "kc-timeout"
    assert [call[0] for call in transport.calls] == ["GET", "POST", "GET"]


def test_u19_uncertain_create_without_matching_user_fails(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        raise _http_error(500, b"backend unavailable")

    transport.post_hook = hook
    with pytest.raises(BootstrapError, match="could not be created or verified"):
        _provisioner(transport).ensure_user(
            _config(create=True, password_file=_secure_password_file(tmp_path))
        )


def test_u20_partial_create_without_verification_reports_failure(tmp_path: Path):
    transport = FakeTransport([])
    # The POST succeeds but the user cannot be read back; fail closed.
    transport.post_hook = lambda fake, body: None
    with pytest.raises(BootstrapError, match="could not be created or verified"):
        _provisioner(transport).ensure_user(
            _config(create=True, password_file=_secure_password_file(tmp_path))
        )


def test_lookup_retries_a_transient_zero_then_succeeds():
    class EventuallyConsistent(FakeTransport):
        def __init__(self) -> None:
            super().__init__([])
            self._reads = 0

        def request(self, method: str, path: str, body: Any | None = None) -> Any:
            if method == "GET":
                self._reads += 1
                return [] if self._reads < 3 else [_user(subject="kc-late")]
            return super().request(method, path, body)

    transport = EventuallyConsistent()
    provisioner = KeycloakDevUserProvisioner(transport, REALM, lookup_attempts=3, retry_delay=0)
    assert provisioner.ensure_user(_config()) == "kc-late"
    assert transport._reads == 3


def test_u22_existing_user_with_unreadable_password_file_succeeds(tmp_path: Path):
    missing = tmp_path / "gone"
    transport = FakeTransport([_user(subject="kc-sub-1")])
    assert (
        _provisioner(transport).ensure_user(_config(create=True, password_file=missing))
        == "kc-sub-1"
    )


def test_u25_error_body_secret_is_never_included(tmp_path: Path):
    secret = "password-never-logged-123456"
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        assert body["credentials"][0]["value"] == secret
        raise _http_error(400, f'{{"errorMessage":"{secret}"}}'.encode())

    transport.post_hook = hook
    with pytest.raises(BootstrapError) as excinfo:
        _provisioner(transport).ensure_user(
            _config(create=True, password_file=_secure_password_file(tmp_path, secret))
        )
    assert secret not in str(excinfo.value)


# --------------------------------------------------------------------------
# additional safety-branch coverage
# --------------------------------------------------------------------------


def test_constructor_rejects_empty_realm_and_bad_attempts():
    transport = FakeTransport([])
    with pytest.raises(DevUserConfigurationError, match="realm is required"):
        KeycloakDevUserProvisioner(transport, "")
    with pytest.raises(DevUserConfigurationError, match="lookup_attempts"):
        KeycloakDevUserProvisioner(transport, REALM, lookup_attempts=0)


def test_config_rejects_long_username_invalid_email_and_control_password_path():
    with pytest.raises(DevUserConfigurationError, match="too long"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "a" * 300})
    with pytest.raises(DevUserConfigurationError, match="illegal characters"):
        DevUserConfig.from_env(
            {"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_EMAIL": "bad email@example"}
        )
    with pytest.raises(DevUserConfigurationError, match="not a valid email"):
        DevUserConfig.from_env(
            {"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_EMAIL": "no-at-sign"}
        )
    with pytest.raises(DevUserConfigurationError, match="PASSWORD_FILE contains illegal"):
        DevUserConfig.from_env(
            {"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_PASSWORD_FILE": "a\x00b"}
        )
    with pytest.raises(DevUserConfigurationError, match="whitespace or control"):
        DevUserConfig.from_env({"MTMF_DEV_USER_USERNAME": "dev", "MTMF_DEV_USER_SUBJECT": "a\tb"})


def test_config_create_true_and_empty_optional_values():
    config = DevUserConfig.from_env(
        {
            "MTMF_DEV_USER_USERNAME": "dev",
            "MTMF_DEV_USER_CREATE": "TRUE",
            "MTMF_DEV_USER_EMAIL": "  ",
            "MTMF_DEV_USER_PASSWORD_FILE": "  ",
        }
    )
    assert config.create is True
    assert config.email is None
    assert config.password_file is None


def test_email_match_and_none_expected_email_paths():
    matching = FakeTransport([_user(email="dev@example.invalid")])
    assert _provisioner(matching).ensure_user(_config(email="DEV@example.invalid")) == "subject-123"
    absent = FakeTransport([_user()])
    with pytest.raises(BootstrapError, match="email does not match"):
        _provisioner(absent).ensure_user(_config(email="dev@example.invalid"))


def test_create_includes_email_verification(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        fake.users.append(_user(body["username"], subject="kc-email", email=body.get("email")))

    transport.post_hook = hook
    subject = _provisioner(transport).ensure_user(
        _config(
            create=True, email="dev@example.invalid", password_file=_secure_password_file(tmp_path)
        )
    )
    assert subject == "kc-email"
    assert transport.calls[1][2]["emailVerified"] is True


def test_read_rows_none_payload_is_absent():
    transport = FakeTransport([])
    transport.request = lambda method, path, body=None: None  # type: ignore[method-assign]
    with pytest.raises(BootstrapError, match="creation is not enabled"):
        _provisioner(transport).ensure_user(_config(create=False))


def test_missing_username_and_bad_email_type_are_rejected():
    from mtmf_service import development_user as du

    with pytest.raises(BootstrapError, match="missing its username"):
        du._validate_user({"id": "x", "enabled": True})

    bad_email = FakeTransport([])
    bad_email.request = lambda method, path, body=None: [  # type: ignore[method-assign]
        {"id": "x", "username": "dev-user", "enabled": True, "email": 7}
    ]
    with pytest.raises(BootstrapError, match="invalid email value"):
        _provisioner(bad_email).ensure_user(_config())


def test_create_malformed_response_reports_redacted_reason(tmp_path: Path):
    transport = FakeTransport([])

    def hook(fake: FakeTransport, body: dict[str, Any]) -> None:
        raise json.JSONDecodeError("bad", "", 0)

    transport.post_hook = hook
    with pytest.raises(BootstrapError, match="the Keycloak response was malformed"):
        _provisioner(transport).ensure_user(
            _config(create=True, password_file=_secure_password_file(tmp_path))
        )


def test_retry_delay_is_exercised(monkeypatch: pytest.MonkeyPatch):
    slept: list[float] = []
    monkeypatch.setattr("mtmf_service.development_user.time.sleep", slept.append)
    transport = FakeTransport([])
    provisioner = KeycloakDevUserProvisioner(transport, REALM, lookup_attempts=2, retry_delay=0.5)
    with pytest.raises(BootstrapError):
        provisioner.ensure_user(_config(create=False))
    assert slept == [0.5]


def test_password_file_rejects_oversize_nul_and_non_utf8(tmp_path: Path):
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"a" * 9000)
    oversized.chmod(0o600)
    with pytest.raises(DevUserConfigurationError, match="too large"):
        load_dev_user_password(oversized)

    nul = tmp_path / "nul"
    nul.write_bytes(b"abc\x00def")
    nul.chmod(0o600)
    with pytest.raises(DevUserConfigurationError, match="invalid bytes"):
        load_dev_user_password(nul)

    non_utf8 = tmp_path / "non-utf8"
    non_utf8.write_bytes(b"\xff\xfe\xfd")
    non_utf8.chmod(0o600)
    with pytest.raises(DevUserConfigurationError, match="not valid UTF-8"):
        load_dev_user_password(non_utf8)


def test_password_file_strips_crlf_and_rejects_blank_after_trim(tmp_path: Path):
    crlf = _secure_password_file(tmp_path, "secret\r\n")
    assert load_dev_user_password(crlf) == "secret"

    newline_only = _secure_password_file(tmp_path, "\n")
    with pytest.raises(DevUserConfigurationError, match="empty"):
        load_dev_user_password(newline_only)


def test_password_file_unreadable_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = _secure_password_file(tmp_path)

    def explode(self: Path) -> bytes:
        raise OSError("denied")

    monkeypatch.setattr(Path, "read_bytes", explode)
    with pytest.raises(DevUserConfigurationError, match="not readable"):
        load_dev_user_password(target)
