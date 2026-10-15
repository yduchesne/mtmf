"""PR 20B deployed, black-box reference-consumer conformance (L20B/S/N/B/G).

This suite is **opt-in** and explicitly configured. It connects to the
already-deployed ``mtmf-pr20a-acceptance`` reference app over loopback HTTP; it
never imports the app's ASGI object, never starts an in-process MTMF service,
and never fabricates a signed JWT. Genuine Keycloak-issued end-user access
tokens are obtained through the approved fixture mechanism (scripted
Authorization Code + PKCE).

Lifecycle/subscription/Role transitions are performed through the privileged,
acceptance-only one-shot helper ``scripts/pr20b_fixture_transitions.py``, which
uses only existing sanctioned stored functions. Every destructive case restores
state before returning.

Enable with ``MTMF_PR20B_LIVE=1`` and the ``MTMF_PR20A_*``/``MTMF_PR20B_*``
environment produced by ``scripts/pr20b-reference-acceptance.py``.
"""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest

if os.environ.get("MTMF_PR20B_LIVE", "").strip() != "1":
    pytest.skip(
        "PR 20B live conformance requires MTMF_PR20B_LIVE=1 and a deployed stack",
        allow_module_level=True,
    )

_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
_ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = _ev
_spec.loader.exec_module(_ev)

TRANSITIONS = Path(__file__).resolve().parents[3] / "scripts" / "pr20b_fixture_transitions.py"
REALM = "mtmf-dev"
REDIRECT_URI = "http://127.0.0.1:28400/callback"
REDIRECT_PORT = 28400

#: Cached genuine end-user tokens with a short refresh window. The full
#: deployed suite outlives the Keycloak access-token lifespan, so a token must
#: never be reused beyond a small fraction of its validity.
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_TOKEN_CACHE_SECONDS = 120.0


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"PR 20B live conformance requires {name}")
    return value


def _reference_base() -> str:
    value = _require("MTMF_PR20A_REFERENCE_APP_URL").rstrip("/")
    if value != "http://127.0.0.1:29511":
        raise RuntimeError("PR 20B acceptance targets exactly http://127.0.0.1:29511")
    return value


def _issuer() -> Any:
    return _ev.Issuer(
        base=_require("MTMF_PR20A_KC_BASE").rstrip("/"),
        realm=REALM,
        ca_file=_require("MTMF_PR20A_CA_FILE"),
    )


def _user_token(username: str) -> str:
    cached = _TOKEN_CACHE.get(username)
    now = time.monotonic()
    if cached is not None and now - cached[1] < _TOKEN_CACHE_SECONDS:
        return cached[0]
    token = _ev.authorization_code_token(
        _issuer(),
        _require("MTMF_PR20A_CLIENT_ID"),
        _require("MTMF_PR20A_CLIENT_SECRET"),
        username,
        _require("MTMF_PR20A_USER_PASSWORD"),
        REDIRECT_URI,
        REDIRECT_PORT,
    )
    access = str(token["access_token"])
    _TOKEN_CACHE[username] = (access, now)
    return access


def _alice() -> str:
    return _user_token(_require("MTMF_PR20A_ALLOWED_USERNAME"))


def _bob() -> str:
    return _user_token(_require("MTMF_PR20A_DENIED_USERNAME"))


def _unverified_subject(token: str) -> str:
    """Extract the fixture ``sub`` (identifier only; trust is never asserted)."""
    payload = token.split(".")[1]
    padding = "=" * (-len(payload) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(payload + padding).decode("utf-8"))
    subject = decoded.get("sub")
    if not isinstance(subject, str) or not subject:
        raise RuntimeError("the fixture token has no subject")
    return subject


def _transition(command: str, subject: str) -> dict[str, Any]:
    """Run exactly one sanctioned acceptance-only fixture transition."""
    result = subprocess.run(
        [sys.executable, str(TRANSITIONS), command, "--subject", subject],
        env=os.environ,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise AssertionError(f"fixture transition {command!r} failed: {detail[-1:]}")
    return json.loads(result.stdout)


def _get(document_id: str, *, token: str | None) -> tuple[int, dict[str, Any] | None, str]:
    url = f"{_reference_base()}/v1/documents/{document_id}"
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = httpx.get(url, headers=headers, timeout=20.0, follow_redirects=False)
    return response.status_code, _maybe_json(response.text), response.text


def _get_with_headers(
    document_id: str, headers: dict[str, str]
) -> tuple[int, dict[str, Any] | None, str]:
    url = f"{_reference_base()}/v1/documents/{document_id}"
    response = httpx.get(url, headers=headers, timeout=20.0, follow_redirects=False)
    return response.status_code, _maybe_json(response.text), response.text


def _post_batch(
    document_ids: list[str], *, token: str | None, extra: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any] | None, str]:
    url = f"{_reference_base()}/v1/documents/batch-read"
    body: dict[str, Any] = {"document_ids": document_ids}
    if extra:
        body.update(extra)
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = httpx.post(url, json=body, headers=headers, timeout=20.0, follow_redirects=False)
    return response.status_code, _maybe_json(response.text), response.text


def _maybe_json(body: str) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _logs() -> str:
    container = _require("MTMF_PR20A_REFERENCE_CONTAINER")
    result = subprocess.run(
        ["podman", "logs", container], capture_output=True, text=True, check=False
    )
    return result.stdout + result.stderr


def _count(marker: str) -> int:
    return len(re.findall(re.escape(marker), _logs()))


@pytest.fixture(scope="module")
def alice_subject() -> str:
    return _unverified_subject(_alice())


@pytest.fixture(autouse=True)
def restore_fixture_state(alice_subject: str) -> Any:
    """Restore the baseline fixture state before and after every case."""
    for command in ("activate-tenant", "subscribe", "grant-role"):
        _transition(command, alice_subject)
    yield
    for command in ("activate-tenant", "subscribe", "grant-role"):
        _transition(command, alice_subject)


def _document() -> str:
    return _require("MTMF_PR20A_DOCUMENT_ID")


def _other_tenant_document() -> str:
    return _require("MTMF_PR20A_OTHER_TENANT_DOCUMENT_ID")


def _batch_document() -> str:
    return _require("MTMF_PR20B_BATCH_DOCUMENT_ID")


def _expected_title() -> str:
    return _require("MTMF_PR20A_EXPECTED_TITLE")


def _expected_body() -> str:
    return _require("MTMF_PR20A_EXPECTED_BODY")


# --- Part C: lifecycle and subscription ------------------------------------


def test_l20b_01_active_subscribed_permitted_allows() -> None:
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload == {
        "id": _document(),
        "title": _expected_title(),
        "body": _expected_body(),
    }
    assert "event=mtmf_evaluate document=" + _document() in _logs()


def test_l20b_02_unsubscribed_is_authoritatively_rejected() -> None:
    _transition("unsubscribe", _unverified_subject(_alice()))
    status, _payload, body = _get(_document(), token=_alice())
    assert status in (401, 403), body
    assert _expected_title() not in body
    assert _expected_body() not in body


def test_l20b_03_subscription_restore_recovers() -> None:
    _transition("unsubscribe", _unverified_subject(_alice()))
    _transition("subscribe", _unverified_subject(_alice()))
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()


def test_l20b_04_suspended_tenant_is_rejected() -> None:
    _transition("suspend-tenant", _unverified_subject(_alice()))
    status, _payload, body = _get(_document(), token=_alice())
    assert status in (401, 403, 503), body
    assert _expected_body() not in body


def test_l20b_05_reactivated_tenant_recovers() -> None:
    _transition("suspend-tenant", _unverified_subject(_alice()))
    _transition("activate-tenant", _unverified_subject(_alice()))
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()


def test_l20b_06_verified_unpermitted_user_is_denied() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=_bob())
    assert status == 403, body
    assert _expected_title() not in body
    assert _expected_body() not in body
    assert _count("event=mtmf_evaluate") == before + 1


def test_l20b_07_other_tenant_document_is_local_404() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_other_tenant_document(), token=_alice())
    assert status == 404, body
    assert "other-tenant-body" not in body
    assert _count("event=mtmf_evaluate") == before


def test_l20b_08_absent_token_is_401_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=None)
    assert status == 401, body
    assert _count("event=mtmf_evaluate") == before


# --- Part D: spoofing and identity binding ---------------------------------


def test_s01_spoofed_forwarding_header_without_authorization_is_401() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get_with_headers(
        _document(), {"X-MTMF-User-Authorization": f"Bearer {_alice()}"}
    )
    assert status == 401, body
    assert _count("event=mtmf_evaluate") == before


def test_s03_arbitrary_context_headers_are_ignored() -> None:
    headers = {
        "Authorization": f"Bearer {_alice()}",
        "X-Tenant-ID": "00000000-0000-4000-8000-000000000000",
        "X-Application-ID": "00000000-0000-4000-8000-000000000000",
        "X-Actor-ID": "00000000-0000-4000-8000-000000000000",
        "X-Session-ID": "00000000-0000-4000-8000-000000000000",
    }
    status, payload, body = _get_with_headers(_document(), headers)
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()


def test_s04_body_context_spoof_is_rejected_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _post_batch(
        [_document()],
        token=_alice(),
        extra={"tenant_id": "00000000-0000-4000-8000-000000000000"},
    )
    assert status == 400, body
    assert _count("event=mtmf_evaluate") == before


# --- Part B: deployed batch route ------------------------------------------


def test_b01_batch_all_allow_returns_ordered_documents() -> None:
    status, payload, body = _post_batch([_document(), _batch_document()], token=_alice())
    assert status == 200, body
    assert payload is not None
    documents = payload["documents"]
    assert [item["id"] for item in documents] == [_document(), _batch_document()]


def test_b02_batch_all_deny_discloses_nothing() -> None:
    status, _payload, body = _post_batch([_document(), _batch_document()], token=_bob())
    assert status == 403, body
    assert _expected_body() not in body
    assert _require("MTMF_PR20B_BATCH_BODY") not in body


def test_b03_batch_with_cross_tenant_document_is_local_404() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _post_batch([_document(), _other_tenant_document()], token=_alice())
    assert status == 404, body
    assert _count("event=mtmf_evaluate") == before


def test_b04_batch_invalid_input_is_400_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _post_batch([_document(), _document()], token=_alice())
    assert status == 400, body
    assert _count("event=mtmf_evaluate") == before


# --- Part E: snapshot revocation (new-request behavior) --------------------


def test_n09_revoked_role_denies_the_next_request() -> None:
    subject = _unverified_subject(_alice())
    _transition("revoke-role", subject)
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=_alice())
    assert status == 403, body
    assert _expected_body() not in body
    assert _count("event=mtmf_evaluate") == before + 1


def test_n10_restored_role_allows_the_next_request() -> None:
    subject = _unverified_subject(_alice())
    _transition("revoke-role", subject)
    _transition("grant-role", subject)
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()


# --- Part G: concurrency and isolation -------------------------------------


def test_g01_concurrent_actors_do_not_mix_context_or_bodies() -> None:
    alice = _alice()
    bob = _bob()
    tasks = [("alice", alice)] * 16 + [("bob", bob)] * 16
    barrier = threading.Barrier(len(tasks))

    def _run(actor_token: tuple[str, str]) -> tuple[str, int, str]:
        actor, token = actor_token
        barrier.wait(timeout=30)
        status, _payload, body = _get(_document(), token=token)
        return actor, status, body

    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        results = list(pool.map(_run, tasks))
    alice_results = [r for r in results if r[0] == "alice"]
    bob_results = [r for r in results if r[0] == "bob"]
    assert all(status == 200 for _, status, _ in alice_results)
    assert all(status == 403 for _, status, _ in bob_results)
    assert all(_expected_body() in body for _, _, body in alice_results)
    assert all(_expected_body() not in body for _, _, body in bob_results)
    assert all(not 500 <= status < 600 for _, status, _ in results)


# ===========================================================================
# Follow-up 01: metadata operation, mixed-action batch, faults, and spoofing.
# ===========================================================================

METADATA_ACTION = "urn:mtmf:iam:actions:system:document:read-metadata"
CONTENT_ACTION = "urn:mtmf:iam:actions:system:document:read-object"
WRONG_AUDIENCE_CLIENT = "mtmf-evidence-user"
WRONG_AUDIENCE_SECRET = "mtmf-evidence-user-dev-secret"
SERVICE_CLIENT = "mtmf-evidence-service"
SERVICE_CLIENT_SECRET = "mtmf-evidence-service-dev-secret"


def _get_metadata(document_id: str, *, token: str | None) -> tuple[int, dict[str, Any] | None, str]:
    url = f"{_reference_base()}/v1/documents/{document_id}/metadata"
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = httpx.get(url, headers=headers, timeout=20.0, follow_redirects=False)
    return response.status_code, _maybe_json(response.text), response.text


def _post_access(
    operations: list[dict[str, str]],
    *,
    token: str | None,
    extra: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | None, str]:
    url = f"{_reference_base()}/v1/documents/batch-access"
    body: dict[str, Any] = {"operations": operations}
    if extra:
        body.update(extra)
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = httpx.post(url, json=body, headers=headers, timeout=20.0, follow_redirects=False)
    return response.status_code, _maybe_json(response.text), response.text


def _pair(document_id: str, operation: str) -> dict[str, str]:
    return {"document_id": document_id, "operation": operation}


def _set_fault(mode: str) -> None:
    path = Path(_require("MTMF_PR20B_CONTROL_FILE"))
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(mode, encoding="utf-8")
    os.replace(temporary, path)


@contextlib.contextmanager
def _fault(mode: str):  # type: ignore[no-untyped-def]
    _set_fault(mode)
    try:
        yield
    finally:
        _set_fault("none")


def _evidence_records() -> list[dict[str, Any]]:
    path = Path(_require("MTMF_PR20B_EVIDENCE_FILE"))
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _last_decisions() -> list[dict[str, Any]]:
    for record in reversed(_evidence_records()):
        decisions = record.get("decisions")
        if isinstance(decisions, list):
            return [item for item in decisions if isinstance(item, dict)]
    return []


def _last_fault() -> str | None:
    for record in reversed(_evidence_records()):
        fault = record.get("fault")
        if isinstance(fault, str):
            return fault
    return None


def _service_token() -> str:
    token = _ev.client_credentials_token(_issuer(), SERVICE_CLIENT, SERVICE_CLIENT_SECRET)
    return str(token["access_token"])


def _wrong_audience_token() -> str:
    token = _ev.authorization_code_token(
        _issuer(),
        WRONG_AUDIENCE_CLIENT,
        WRONG_AUDIENCE_SECRET,
        _require("MTMF_PR20A_ALLOWED_USERNAME"),
        _require("MTMF_PR20A_USER_PASSWORD"),
        REDIRECT_URI,
        REDIRECT_PORT,
    )
    return str(token["access_token"])


def _refresh_token() -> str:
    token = _ev.authorization_code_token(
        _issuer(),
        _require("MTMF_PR20A_CLIENT_ID"),
        _require("MTMF_PR20A_CLIENT_SECRET"),
        _require("MTMF_PR20A_ALLOWED_USERNAME"),
        _require("MTMF_PR20A_USER_PASSWORD"),
        REDIRECT_URI,
        REDIRECT_PORT,
    )
    return str(token["refresh_token"])


# --- Part D: metadata operation (M01-M04) ----------------------------------


def test_m01_bob_metadata_read_allows_id_title_only() -> None:
    status, payload, body = _get_metadata(_document(), token=_bob())
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()
    assert "body" not in (payload or {})
    assert _expected_body() not in body


def test_m02_bob_content_read_is_denied() -> None:
    status, _payload, body = _get(_document(), token=_bob())
    assert status == 403, body
    assert _expected_title() not in body
    assert _expected_body() not in body


def test_m03_alice_metadata_read_allows_id_title_only() -> None:
    status, payload, body = _get_metadata(_document(), token=_alice())
    assert status == 200, body
    assert payload is not None and payload["id"] == _document()
    assert "body" not in (payload or {})


def test_m04_alice_content_read_allows_full_document() -> None:
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload == {
        "id": _document(),
        "title": _expected_title(),
        "body": _expected_body(),
    }


# --- Part C: genuine mixed-action batch (M05-M12) --------------------------


def test_m05_bob_mixed_metadata_content_is_one_real_allow_deny() -> None:
    status, _payload, body = _post_access(
        [_pair(_document(), "metadata"), _pair(_document(), "content")], token=_bob()
    )
    assert status == 403, body
    assert "results" not in body
    assert _expected_body() not in body
    decisions = _last_decisions()
    assert [item.get("effect") for item in decisions] == ["ALLOW", "DENY"]
    assert [item.get("action") for item in decisions] == [METADATA_ACTION, CONTENT_ACTION]
    assert [item.get("request_id") for item in decisions] == [
        "document-access-0",
        "document-access-1",
    ]
    assert {item.get("resource_id") for item in decisions} == {_document()}


def test_m06_bob_mixed_content_metadata_is_one_real_deny_allow() -> None:
    status, _payload, body = _post_access(
        [_pair(_document(), "content"), _pair(_document(), "metadata")], token=_bob()
    )
    assert status == 403, body
    assert "results" not in body
    decisions = _last_decisions()
    assert [item.get("effect") for item in decisions] == ["DENY", "ALLOW"]
    assert [item.get("action") for item in decisions] == [CONTENT_ACTION, METADATA_ACTION]


def test_m07_alice_mixed_batch_allows_both_without_metadata_body() -> None:
    status, payload, body = _post_access(
        [_pair(_document(), "metadata"), _pair(_document(), "content")], token=_alice()
    )
    assert status == 200, body
    results = (payload or {})["results"]
    assert results[0]["operation"] == "metadata"
    assert "body" not in results[0]["document"]
    assert results[1]["operation"] == "content"
    assert results[1]["document"]["body"] == _expected_body()
    decisions = _last_decisions()
    assert [item.get("effect") for item in decisions] == ["ALLOW", "ALLOW"]


def test_m08_bob_metadata_only_batch_returns_no_body() -> None:
    status, payload, body = _post_access([_pair(_document(), "metadata")], token=_bob())
    assert status == 200, body
    result = (payload or {})["results"][0]
    assert result["operation"] == "metadata"
    assert "body" not in result["document"]


def test_m09_existing_batch_read_contract_unchanged() -> None:
    status, _payload, body = _post_batch([_document(), _batch_document()], token=_bob())
    assert status == 403, body
    assert _expected_body() not in body
    assert _require("MTMF_PR20B_BATCH_BODY") not in body


def test_m10_cross_tenant_batch_access_is_local_404() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _post_access(
        [_pair(_other_tenant_document(), "metadata")], token=_alice()
    )
    assert status == 404, body
    assert _count("event=mtmf_evaluate") == before


def test_m11_invalid_batch_access_is_400_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _post_access(
        [_pair(_document(), "metadata"), _pair(_document(), "metadata")], token=_alice()
    )
    assert status == 400, body
    assert _count("event=mtmf_evaluate") == before


def test_m12_restored_state_outcomes_are_stable() -> None:
    assert _get(_document(), token=_alice())[0] == 200
    assert _get(_document(), token=_bob())[0] == 403
    assert _get_metadata(_document(), token=_bob())[0] == 200


# --- Part B: deterministic remote faults (F01-F07) -------------------------


def test_f01_refused_connection_fails_closed() -> None:
    with _fault("refuse"):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == "refuse"
    assert status == 503, body
    assert _expected_title() not in body
    assert _expected_body() not in body


def test_f02_delayed_response_fails_closed() -> None:
    with _fault("delay"):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == "delay"
    assert status == 503, body
    assert _expected_body() not in body


@pytest.mark.parametrize("mode", ["http_502", "http_503"])
def test_f03_upstream_error_fails_closed(mode: str) -> None:
    with _fault(mode):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == mode
    assert status == 503, body
    assert _expected_body() not in body


def test_f04_non_json_success_fails_closed() -> None:
    with _fault("non_json"):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == "non_json"
    assert status == 503, body
    assert _expected_body() not in body


def test_f05_malformed_json_success_fails_closed() -> None:
    with _fault("malformed_json"):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == "malformed_json"
    assert status == 503, body
    assert _expected_body() not in body


def test_f06_mismatched_correlation_fails_closed() -> None:
    with _fault("mismatch"):
        status, _payload, body = _get(_document(), token=_alice())
        assert _last_fault() == "mismatch"
    assert status == 503, body
    assert _expected_body() not in body


def test_f07_healthy_recovery_after_each_fault() -> None:
    assert _last_fault() is None or _last_fault() != "none"
    status, payload, body = _get(_document(), token=_alice())
    assert status == 200, body
    assert payload is not None and payload["body"] == _expected_body()
    assert _get(_document(), token=_bob())[0] == 403
    assert _get_metadata(_document(), token=_bob())[0] == 200


# --- Part C: spoofing closure (S02/S05/S07/S08) ----------------------------


def test_s02_spoofed_alice_header_does_not_replace_bob() -> None:
    headers = {
        "Authorization": f"Bearer {_bob()}",
        "X-MTMF-User-Authorization": f"Bearer {_alice()}",
    }
    status, _payload, body = _get_with_headers(_document(), headers)
    assert status == 403, body
    assert _expected_body() not in body
    assert _get_with_headers(f"{_document()}/metadata", headers)[0] == 200


def test_s05a_tampered_signature_is_401_without_evaluation() -> None:
    token = _alice()
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=tampered)
    assert status == 401, body
    assert _count("event=mtmf_evaluate") == before


def test_s05b_wrong_audience_real_token_is_401_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=_wrong_audience_token())
    assert status == 401, body
    assert _count("event=mtmf_evaluate") == before


def test_s05c_wrong_token_type_is_401_without_evaluation() -> None:
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=_refresh_token())
    assert status == 401, body
    assert _count("event=mtmf_evaluate") == before


def test_s07_service_token_is_never_user_content() -> None:
    service_token = _service_token()
    _header, claims = _ev.decode_unverified(service_token)
    assert _ev.service_class_ok(claims)
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=service_token)
    assert status in (401, 403), body
    assert _expected_body() not in body
    assert _count("event=mtmf_evaluate") == before


def test_s08_unmapped_verified_subject_is_403_without_evaluation() -> None:
    unmapped = _user_token(_require("MTMF_PR20B_UNMAPPED_USERNAME"))
    before = _count("event=mtmf_evaluate")
    status, _payload, body = _get(_document(), token=unmapped)
    assert status == 403, body
    assert _expected_body() not in body
    assert _count("event=mtmf_evaluate") == before


# --- Part D: mixed-operation concurrency wave ------------------------------


def test_m13_mixed_operation_concurrency_has_no_cross_actor_mixing() -> None:
    alice = _alice()
    bob = _bob()
    tasks = (
        [("bob-metadata", bob, "metadata")] * 8
        + [("bob-content", bob, "content")] * 8
        + [("alice-metadata", alice, "metadata")] * 8
        + [("alice-content", alice, "content")] * 8
    )
    barrier = threading.Barrier(len(tasks))

    def _run(task: tuple[str, str, str]) -> tuple[str, int, str]:
        label, token, operation = task
        barrier.wait(timeout=30)
        if operation == "metadata":
            status, _payload, body = _get_metadata(_document(), token=token)
        else:
            status, _payload, body = _get(_document(), token=token)
        return label, status, body

    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        results = list(pool.map(_run, tasks))
    for label, status, body in results:
        assert status < 500, (label, status)
        if label == "bob-metadata":
            assert status == 200 and _expected_body() not in body
        elif label == "bob-content":
            assert status == 403 and _expected_body() not in body
        elif label == "alice-metadata":
            assert status == 200 and _expected_body() not in body
        else:
            assert status == 200 and _expected_body() in body
