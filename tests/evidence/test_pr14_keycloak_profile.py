"""Pure contract tests for the PR 14 Keycloak evidence harness.

These tests exercise only the sanitized, side-effect-free logic in
``scripts/pr14-keycloak-evidence.py``. They do not require a running
Keycloak, PostgreSQL, or any MTMF runtime role, and they are intentionally
outside the default ``tests/unit`` gate.

A live-issuer smoke test is provided but is skipped unless the explicit
opt-in environment variable ``MTMF_PR14_KC_LIVE_EVIDENCE=1`` and the
``MTMF_PR14_KC_*`` configuration are set. A skipped live test is never
counted as acceptance evidence.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "pr14-keycloak-evidence.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before execution so dataclasses can resolve the module by name.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evidence = _load_module()


def test_sanitize_claims_keeps_only_allowlisted_and_hashes_identifiers():
    payload = {
        "iss": "https://issuer.example/realms/x",
        "aud": ["mtmf-user-api"],
        "azp": "client-a",
        "typ": "Bearer",
        "exp": 123,
        "iat": 100,
        "sub": "user-123",
        "jti": "token-123",
        "email": "alice@example.invalid",
        "preferred_username": "alice",
        "secret_claim": "should-not-appear",
    }
    summary = evidence.sanitize_claims(payload)
    assert summary["iss"] == "https://issuer.example/realms/x"
    assert summary["aud"] == ["mtmf-user-api"]
    assert summary["azp"] == "client-a"
    assert summary["typ"] == "Bearer"
    assert summary["exp"] is True and summary["iat"] is True
    # Opaque identifiers are replaced with stable non-reversible hashes.
    assert summary["sub"] != "user-123"
    assert summary["sub"] == evidence._stable_hash("user-123")
    assert summary["email"] != "alice@example.invalid"
    # Unknown/unlisted claims never surface their values.
    assert "secret_claim" not in summary
    assert "secret_claim" in summary["_claim_names"]


def test_sanitize_header_never_leaks_raw_values():
    header = {"alg": "RS256", "typ": "JWT", "kid": "abc", "x5c": ["CERT"]}
    summary = evidence.sanitize_header(header)
    assert summary["alg"] == "RS256"
    assert summary["typ"] == "JWT"
    # The public key id is hashed, never surfaced raw.
    assert summary["kid"] == evidence._stable_hash("abc")
    assert summary["kid"] != "abc"
    assert "x5c" not in summary
    assert summary["_header_names"] == ["alg", "kid", "typ", "x5c"]


def test_form_action_and_hidden_fields_are_html_unescaped():
    page = (
        '<form action="https://kc/login-actions/authenticate?session_code=a&amp;execution=b">'
        '<input type="hidden" name="credentialId" value="">'
        '<input type="text" name="username">'
        "</form>"
    )
    assert (
        evidence._form_action(page)
        == "https://kc/login-actions/authenticate?session_code=a&execution=b"
    )
    assert evidence._form_hidden_fields(page) == {"credentialId": ""}


def test_looks_like_jwt():
    assert evidence._looks_like_jwt("a.b.c") is True
    assert evidence._looks_like_jwt("opaque-token") is False


def test_issuer_guard_rejects_nonlocal():
    issuer = evidence.Issuer(base="https://idp.example.com", realm="r")
    with pytest.raises(evidence.IssuerError):
        issuer.guard()
    local = evidence.Issuer(base="https://127.0.0.1:28443", realm="r")
    local.guard()  # must not raise


def test_issuer_ssl_context_is_none_without_ca_file():
    assert evidence.Issuer(base="https://127.0.0.1:28443", realm="r").ssl_context() is None


def test_evidence_artifact_is_secret_free():
    """The committed sanitized artifact must not contain secrets or raw tokens."""
    import json

    artifact = (
        Path(__file__).resolve().parents[2]
        / "dev"
        / "keycloak"
        / "evidence"
        / "pr14-keycloak-evidence.json"
    )
    if not artifact.exists():
        pytest.skip("sanitized evidence artifact not present")
    text = artifact.read_text()
    assert "BEGIN PRIVATE KEY" not in text
    assert "BEGIN RSA PRIVATE KEY" not in text
    secret_keys = {"access_token", "refresh_token", "id_token", "client_secret", "password"}

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in secret_keys:
                    # A non-empty scalar would be a leaked credential/token.
                    assert not isinstance(value, str) or not value, f"leaked {key}"
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json.loads(text))


def test_client_binding_ok_fails_closed_without_azp():
    assert evidence.client_binding_ok({"azp": "client"}) is True
    assert evidence.client_binding_ok({}) is False
    assert evidence.client_binding_ok({"azp": ""}) is False


def test_service_and_user_class_predicates_are_disjoint():
    service = {"typ": "Bearer", "azp": "client", "client_id": "client", "sub": "sa"}
    user = {"typ": "Bearer", "azp": "client", "sub": "human"}
    assert evidence.service_class_ok(service) is True
    assert evidence.user_class_ok(service) is False
    assert evidence.user_class_ok(user) is True
    assert evidence.service_class_ok(user) is False
    # Mismatched client_id/azp is not a service class.
    assert (
        evidence.service_class_ok({"typ": "Bearer", "azp": "a", "client_id": "b", "sub": "s"})
        is False
    )
    # ID/refresh classes match neither predicate.
    assert evidence.service_class_ok({"typ": "ID", "azp": "a", "sub": "s"}) is False
    assert evidence.user_class_ok({"typ": "Refresh", "azp": "a", "sub": "s"}) is False


@pytest.mark.skipif(
    os.environ.get("MTMF_PR14_KC_LIVE_EVIDENCE") != "1",
    reason="live Keycloak evidence is opt-in (set MTMF_PR14_KC_LIVE_EVIDENCE=1)",
)
def test_live_issuer_smoke():  # pragma: no cover - opt-in live gate
    issuer = evidence.Issuer(
        base=os.environ.get("MTMF_PR14_KC_BASE", "https://127.0.0.1:28443"),
        realm=os.environ.get("MTMF_PR14_KC_REALM", "mtmf-pr14-dev"),
        ca_file=os.environ.get("MTMF_PR14_KC_CA_FILE", ""),
    )
    assert evidence.wait_for_ready(issuer, attempts=5) is True
