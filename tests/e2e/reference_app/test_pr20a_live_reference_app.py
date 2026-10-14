"""PR 20A deployed, black-box reference-application acceptance (L01-L05).

This suite is **opt-in** and explicitly configured. It connects to an
already-deployed reference app over loopback HTTP; it never imports the app's
ASGI object, never starts an in-process MTMF service, and never fabricates a
signed JWT. Genuine Keycloak-issued end-user access tokens are obtained through
the approved test fixture mechanism (scripted Authorization Code + PKCE).

Enable it with ``MTMF_PR20A_LIVE=1`` and the ``MTMF_PR20A_*`` acceptance
environment produced by ``scripts/pr20a-reference-acceptance.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

if os.environ.get("MTMF_PR20A_LIVE", "").strip() != "1":
    pytest.skip(
        "PR 20A live acceptance requires MTMF_PR20A_LIVE=1 and a deployed stack",
        allow_module_level=True,
    )

_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
_ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = _ev
_spec.loader.exec_module(_ev)

REALM = "mtmf-dev"
REDIRECT_URI = "http://127.0.0.1:28400/callback"
REDIRECT_PORT = 28400


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"PR 20A live acceptance requires {name}")
    return value


def _reference_base() -> str:
    value = _require("MTMF_PR20A_REFERENCE_APP_URL").rstrip("/")
    if value != "http://127.0.0.1:29511":
        raise RuntimeError("PR 20A acceptance targets exactly http://127.0.0.1:29511")
    return value


def _kc_base() -> str:
    return _require("MTMF_PR20A_KC_BASE").rstrip("/")


def _ca_file() -> str:
    return _require("MTMF_PR20A_CA_FILE")


def _client_id() -> str:
    return _require("MTMF_PR20A_CLIENT_ID")


def _client_secret() -> str:
    return _require("MTMF_PR20A_CLIENT_SECRET")


def _user_password() -> str:
    return _require("MTMF_PR20A_USER_PASSWORD")


def _issuer() -> Any:
    return _ev.Issuer(base=_kc_base(), realm=REALM, ca_file=_ca_file())


def _user_token(username: str) -> str:
    token = _ev.authorization_code_token(
        _issuer(),
        _client_id(),
        _client_secret(),
        username,
        _user_password(),
        REDIRECT_URI,
        REDIRECT_PORT,
    )
    return str(token["access_token"])


def _get(document_id: str, *, token: str | None) -> tuple[int, dict[str, Any] | None, str]:
    """Perform one reference-app GET and return (status, json|null, raw body)."""
    url = f"{_reference_base()}/v1/documents/{document_id}"
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = httpx.get(url, headers=headers, timeout=15.0, follow_redirects=False)
    body = response.text
    return response.status_code, _maybe_json(body), body


def _maybe_json(body: str) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _reference_logs() -> str:
    container = _require("MTMF_PR20A_REFERENCE_CONTAINER")
    result = subprocess.run(
        ["podman", "logs", container],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout + result.stderr


def _count(marker: str) -> int:
    return len(re.findall(re.escape(marker), _reference_logs()))


def test_l01_allowed_user_receives_exact_document() -> None:
    """L01: real MTMF ALLOW discloses exactly the seeded document."""
    document_id = _require("MTMF_PR20A_DOCUMENT_ID")
    token = _user_token(_require("MTMF_PR20A_ALLOWED_USERNAME"))
    status, payload, body = _get(document_id, token=token)
    assert status == 200, body
    assert payload == {
        "id": document_id,
        "title": _require("MTMF_PR20A_EXPECTED_TITLE"),
        "body": _require("MTMF_PR20A_EXPECTED_BODY"),
    }
    logs = _reference_logs()
    # Evidence of a real outbound MTMF evaluation and a locally enforced ALLOW,
    # plus proof that no credential material was rendered.
    assert "event=mtmf_evaluate document=" + document_id in logs
    assert "event=document_allowed document=" + document_id in logs
    assert _client_secret() not in logs


def test_l02_denied_same_tenant_user_is_policy_denied() -> None:
    """L02: a verified same-Tenant user without the grant is policy-denied."""
    document_id = _require("MTMF_PR20A_DOCUMENT_ID")
    token = _user_token(_require("MTMF_PR20A_DENIED_USERNAME"))
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(document_id, token=token)
    assert status == 403, body
    assert _require("MTMF_PR20A_EXPECTED_TITLE") not in body
    assert _require("MTMF_PR20A_EXPECTED_BODY") not in body
    # The DENY is authoritative MTMF policy, evidenced by a real evaluation.
    assert _count("event=mtmf_evaluate") == before + 1
    assert "event=access_denied" in _reference_logs()


def test_l03_missing_token_is_unauthenticated_without_evaluation() -> None:
    """L03: no inbound token -> 401 and no MTMF evaluation."""
    document_id = _require("MTMF_PR20A_DOCUMENT_ID")
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(document_id, token=None)
    assert status == 401, body
    assert _require("MTMF_PR20A_EXPECTED_BODY") not in body
    assert _count("event=mtmf_evaluate") == before


def test_l04_missing_document_is_local_404_without_evaluation() -> None:
    """L04: valid user, absent document -> local 404 and no evaluation."""
    token = _user_token(_require("MTMF_PR20A_ALLOWED_USERNAME"))
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get("d0c0a1e0-0009-4000-8000-000000000009", token=token)
    assert status == 404, body
    assert _count("event=mtmf_evaluate") == before


def test_l05_other_tenant_document_is_local_404() -> None:
    """L05: a valid user cannot change trusted Tenant context via the id."""
    token = _user_token(_require("MTMF_PR20A_ALLOWED_USERNAME"))
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_require("MTMF_PR20A_OTHER_TENANT_DOCUMENT_ID"), token=token)
    assert status == 404, body
    assert "other-tenant-body" not in body
    assert _count("event=mtmf_evaluate") == before
