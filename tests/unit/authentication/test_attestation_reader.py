"""Least-privilege client-credentials attestation reader tests (SEC-01)."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_service.authentication.attestation import HttpAdminRestReader

BASE = "https://127.0.0.1:28443"
REALM = "mtmf-pr14-dev"


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


class FakeOpener:
    """Scripted opener that records requests and returns queued responses."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float | None = None) -> FakeResponse:
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeResponse(item if isinstance(item, bytes) else json.dumps(item).encode())


def _reader(opener: FakeOpener, *, max_bytes: int = 262144) -> HttpAdminRestReader:
    return HttpAdminRestReader(
        BASE, REALM, "mtmf-attestation-reader", "reader-secret", opener=opener, max_bytes=max_bytes
    )


def test_u01_client_credentials_token_then_bearer_get():
    opener = FakeOpener([{"access_token": "tok"}, {"realm": REALM}])
    assert _reader(opener).get(f"/admin/realms/{REALM}") == {"realm": REALM}
    token_request = opener.requests[0]
    assert token_request.full_url == f"{BASE}/realms/{REALM}/protocol/openid-connect/token"
    assert token_request.get_method() == "POST"
    body = token_request.data.decode()
    assert "grant_type=client_credentials" in body
    assert "password" not in body and "admin-cli" not in body
    get_request = opener.requests[1]
    assert get_request.get_header("Authorization") == "Bearer tok"


def test_u05_non_https_base_rejected_before_any_credential():
    with pytest.raises(AuthenticationError) as exc:
        HttpAdminRestReader("http://127.0.0.1:28443", REALM, "c", "s")
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_u05_non_loopback_base_rejected():
    with pytest.raises(AuthenticationError):
        HttpAdminRestReader("https://idp.example.test", REALM, "c", "s")


def test_u03_missing_reader_credential_rejected():
    with pytest.raises(AuthenticationError):
        HttpAdminRestReader(BASE, REALM, "", "s")
    with pytest.raises(AuthenticationError):
        HttpAdminRestReader(BASE, REALM, "c", "")


def test_u06_transport_error_is_typed_unavailable():
    opener = FakeOpener([urllib.error.URLError("connection refused")])
    with pytest.raises(AuthenticationError) as exc:
        _reader(opener).get(f"/admin/realms/{REALM}")
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_u07_empty_or_malformed_token_is_typed_unavailable():
    for payload in (b"", b"{not json", b'{"access_token": ""}', b"[]"):
        opener = FakeOpener([payload])
        with pytest.raises(AuthenticationError) as exc:
            _reader(opener).get(f"/admin/realms/{REALM}")
        assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_u08_oversized_response_is_bounded():
    opener = FakeOpener([{"access_token": "tok"}, b"x" * 50])
    with pytest.raises(AuthenticationError) as exc:
        _reader(opener, max_bytes=10).get(f"/admin/realms/{REALM}")
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_u11_duplicate_json_member_in_configuration_is_rejected():
    opener = FakeOpener([{"access_token": "tok"}, b'{"realm": "a", "realm": "b"}'])
    with pytest.raises(AuthenticationError) as exc:
        _reader(opener).get(f"/admin/realms/{REALM}")
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_u26_errors_never_contain_the_secret():
    opener = FakeOpener([urllib.error.HTTPError(BASE, 403, "forbidden", {}, None)])
    with pytest.raises(AuthenticationError) as exc:
        _reader(opener).get(f"/admin/realms/{REALM}")
    assert "reader-secret" not in str(exc.value)
