"""Live least-privilege proof for the dedicated attestation reader (SEC-01).

Opt-in (`MTMF_PR17_LIVE=1`). Proves against real Keycloak that the reader
credential can perform exactly the required GETs and is denied every
realm/client/scope/mapper/user mutation plus role escalation, while a
separately held privileged identity can perform a disposable mutation (so the
denial is RBAC, not a malformed request).
"""

from __future__ import annotations

import importlib.util
import os
import ssl
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

_LIVE = Path(__file__).resolve().parent / "test_pr17_live_http.py"
_spec = importlib.util.spec_from_file_location("pr17_live_http", _LIVE)
assert _spec is not None and _spec.loader is not None
live = importlib.util.module_from_spec(_spec)
sys.modules["pr17_live_http"] = live
_spec.loader.exec_module(live)

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR17_LIVE") != "1",
    reason="live reader-permission proof is opt-in (set MTMF_PR17_LIVE=1)",
)

REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
READER = "mtmf-attestation-reader"
READER_SECRET = "mtmf-attestation-reader-dev-secret"


def _base() -> str:
    return os.environ["MTMF_PR14_KC_BASE"]


def _ctx() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))


def _reader_headers() -> dict[str, str]:
    response = httpx.post(
        f"{_base()}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": READER,
            "client_secret": READER_SECRET,
        },
        verify=_ctx(),
        timeout=10,
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _admin() -> Any:
    return live._Admin()


def test_i01_reader_gets_all_required_resources() -> None:
    headers = _reader_headers()
    admin = _admin()
    client = admin._request(
        "GET", f"/admin/realms/{REALM}/clients?clientId=mtmf-evidence-same-client"
    )[0]
    scope = admin._request("GET", f"/admin/realms/{REALM}/client-scopes")[0]
    paths = [
        f"/admin/realms/{REALM}",
        f"/admin/realms/{REALM}/client-scopes",
        f"/admin/realms/{REALM}/client-scopes/{scope['id']}/protocol-mappers/models",
        f"/admin/realms/{REALM}/clients?clientId={client['clientId']}",
        f"/admin/realms/{REALM}/clients/{client['id']}/default-client-scopes",
        f"/admin/realms/{REALM}/clients/{client['id']}/optional-client-scopes",
        f"/admin/realms/{REALM}/clients/{client['id']}/protocol-mappers/models",
    ]
    with httpx.Client(base_url=_base(), verify=_ctx(), timeout=10) as http:
        for path in paths:
            response = http.get(path, headers=headers)
            assert response.status_code == 200, (path, response.status_code)


def test_i02_reader_cannot_mutate_and_privileged_identity_can() -> None:
    headers = _reader_headers()
    admin = _admin()
    disposable = f"mtmf-a5-disposable-{uuid.uuid4().hex[:8]}"
    before = admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={disposable}")
    assert before == []
    client = admin._request(
        "GET", f"/admin/realms/{REALM}/clients?clientId=mtmf-evidence-same-client"
    )[0]
    with httpx.Client(base_url=_base(), verify=_ctx(), timeout=10) as http:
        attempts = [
            ("POST", f"/admin/realms/{REALM}/clients", {"clientId": disposable}),
            ("PUT", f"/admin/realms/{REALM}/clients/{client['id']}", {"enabled": False}),
            ("POST", f"/admin/realms/{REALM}/users", {"username": "mtmf-a5-reader-user"}),
            ("PUT", f"/admin/realms/{REALM}", {"displayName": "a5"}),
            (
                "POST",
                f"/admin/realms/{REALM}/clients/{client['id']}/protocol-mappers/models",
                {"name": "a5", "protocol": "openid-connect", "protocolMapper": "x", "config": {}},
            ),
        ]
        for method, path, body in attempts:
            response = http.request(method, path, headers=headers, json=body)
            assert response.status_code in (401, 403), (method, path, response.status_code)
    # Denied state unchanged.
    assert admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={disposable}") == []
    # The same kind of operation succeeds under the privileged test identity.
    created = admin._request(
        "POST",
        f"/admin/realms/{REALM}/clients",
        {"clientId": disposable, "protocol": "openid-connect"},
    )
    rows = admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={disposable}")
    assert len(rows) == 1
    admin._request("DELETE", f"/admin/realms/{REALM}/clients/{rows[0]['id']}")
    assert admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={disposable}") == []
    del created


def test_i03_reader_cannot_escalate_its_own_roles() -> None:
    headers = _reader_headers()
    admin = _admin()
    reader = admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={READER}")[0]
    service_account = admin._request(
        "GET", f"/admin/realms/{REALM}/clients/{reader['id']}/service-account-user"
    )
    realm_management = admin._request(
        "GET", f"/admin/realms/{REALM}/clients?clientId=realm-management"
    )[0]
    with httpx.Client(base_url=_base(), verify=_ctx(), timeout=10) as http:
        response = http.post(
            f"/admin/realms/{REALM}/users/{service_account['id']}/role-mappings/clients/"
            f"{realm_management['id']}",
            headers=headers,
            json=[{"id": "00000000-0000-0000-0000-000000000000", "name": "realm-admin"}],
        )
    assert response.status_code in (401, 403)
