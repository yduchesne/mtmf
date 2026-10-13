"""PR 17-C Fixup 3 - canonical development realm contract tests (CR-U01-CR-U30).

Exercises the real launcher/initializer/probe code paths and the standard-stack
configuration. The independent PR 14 evidence fixture keeps ``mtmf-pr14-dev``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "mtmf-dev-stack.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_stack_realm", _SCRIPT)
assert _spec is not None and _spec.loader is not None
stack = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = stack
_spec.loader.exec_module(stack)

_REALM = "mtmf-dev"
_ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
_JWKS = f"{_ISSUER}/protocol/openid-connect/certs"


def _load_initializer() -> Any:
    script = _REPO_ROOT / "scripts" / "mtmf-dev-initialize.py"
    spec = importlib.util.spec_from_file_location("mtmf_dev_initialize_realm", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _set_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    issuer: str | None = _ISSUER,
    jwks: str | None = _JWKS,
    realm: str | None = _REALM,
) -> None:
    if issuer is None:
        monkeypatch.delenv("MTMF_AUTH_ISSUER", raising=False)
    else:
        monkeypatch.setenv("MTMF_AUTH_ISSUER", issuer)
    if jwks is None:
        monkeypatch.delenv("MTMF_AUTH_JWKS_URI", raising=False)
    else:
        monkeypatch.setenv("MTMF_AUTH_JWKS_URI", jwks)
    if realm is None:
        monkeypatch.delenv("MTMF_AUTH_ADMIN_REALM", raising=False)
    else:
        monkeypatch.setenv("MTMF_AUTH_ADMIN_REALM", realm)


# --- CR-U01/U02/U03: canonical literals ------------------------------------


def test_cru01_canonical_realm_constant():
    assert stack.CANONICAL_KC_REALM == _REALM


def test_cru02_canonical_issuer_literal():
    assert stack.CANONICAL_KC_ISSUER == _ISSUER


def test_cru03_canonical_jwks_literal():
    assert stack.CANONICAL_KC_JWKS_URI == _JWKS


# --- CR-U04: valid config accepted -----------------------------------------


def test_cru04_valid_config_accepted_without_mutation(monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch)
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: pytest.fail("must not prepare"))
    assert stack._require_canonical_issuer() == _ISSUER


# --- CR-U05/U06/U07: old realm/issuer/jwks rejected ------------------------


@pytest.mark.parametrize(
    ("issuer", "jwks", "realm"),
    [
        ("https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev", _JWKS, _REALM),  # CR-U05
        (_ISSUER, _JWKS, "mtmf-pr14-dev"),  # CR-U06
        (
            _ISSUER,
            "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs",
            _REALM,
        ),  # CR-U07
    ],
)
def test_cru05_cru07_old_values_rejected(
    monkeypatch: pytest.MonkeyPatch, issuer: str, jwks: str, realm: str
):
    _set_env(monkeypatch, issuer=issuer, jwks=jwks, realm=realm)
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(stack.OrchestrationError):
        stack._require_canonical_issuer()


# --- CR-U08/U09/U10: missing values ----------------------------------------


@pytest.mark.parametrize(
    ("issuer", "jwks", "realm"),
    [
        (None, _JWKS, _REALM),  # CR-U08
        (_ISSUER, None, _REALM),  # CR-U09
        (_ISSUER, _JWKS, None),  # CR-U10
    ],
)
def test_cru08_cru10_missing_values_rejected(
    monkeypatch: pytest.MonkeyPatch, issuer: str | None, jwks: str | None, realm: str | None
):
    _set_env(monkeypatch, issuer=issuer, jwks=jwks, realm=realm)
    with pytest.raises(stack.OrchestrationError):
        stack._require_canonical_issuer()


# --- CR-U11/U12: realm case/whitespace -------------------------------------


@pytest.mark.parametrize("realm", ["MTMF-DEV", " mtmf-dev", "mtmf-dev ", "mtmf-dev\n"])
def test_cru11_cru12_realm_case_and_whitespace_rejected(
    monkeypatch: pytest.MonkeyPatch, realm: str
):
    _set_env(monkeypatch, realm=realm)
    with pytest.raises(stack.OrchestrationError):
        stack._require_canonical_issuer()


# --- CR-U13..U18: issuer malformations -------------------------------------


@pytest.mark.parametrize(
    "issuer",
    [
        _ISSUER + "/",  # CR-U13 trailing slash
        _ISSUER + "?x=1",  # CR-U14 query
        _ISSUER + "#frag",  # CR-U14 fragment
        "https://user:secret@keycloak.mtmf.test:28443/realms/mtmf-dev",  # CR-U15 userinfo
        "http://keycloak.mtmf.test:28443/realms/mtmf-dev",  # CR-U16 scheme
        "https://keycloak.mtmf.test:28444/realms/mtmf-dev",  # CR-U17 port
        "https://127.0.0.1:28443/realms/mtmf-dev",  # CR-U17 host
        "https://evil-keycloak.mtmf.test:28443/realms/mtmf-dev",  # CR-U18 prefix lookalike
        "https://keycloak.mtmf.test.evil.example/realms/mtmf-dev",  # CR-U18 suffix lookalike
    ],
)
def test_cru13_cru18_issuer_malformations_rejected(monkeypatch: pytest.MonkeyPatch, issuer: str):
    _set_env(monkeypatch, issuer=issuer)
    with pytest.raises(stack.OrchestrationError):
        stack._require_canonical_issuer()


# --- CR-U19: JWKS relative/foreign -----------------------------------------


@pytest.mark.parametrize(
    "jwks",
    [
        "/protocol/openid-connect/certs",
        "https://evil.example/protocol/openid-connect/certs",
        f"{_ISSUER}/protocol/openid-connect/certs-other",
        f"{_ISSUER}/realms/other/protocol/openid-connect/certs",
    ],
)
def test_cru19_jwks_malformations_rejected(monkeypatch: pytest.MonkeyPatch, jwks: str):
    _set_env(monkeypatch, jwks=jwks)
    with pytest.raises(stack.OrchestrationError):
        stack._require_canonical_issuer()


# --- CR-U20: malformed fail before cert/Compose/DB -------------------------


def test_cru20_malformed_rejected_before_side_effects(monkeypatch: pytest.MonkeyPatch):
    _set_env(
        monkeypatch,
        issuer="https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
    )
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "development")
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: pytest.fail("must not prepare"))
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(stack.OrchestrationError):
        stack.up()


# --- CR-U21: up-host-network has the same validation -----------------------


def test_cru21_up_host_network_same_validation(monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch, issuer="https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev")
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "development")
    monkeypatch.setenv("MTMF_DEV_KC_ADMIN_PASSWORD", "pw")
    monkeypatch.setenv("MTMF_AUTH_ADMIN_USERNAME", "mtmf-admin")
    monkeypatch.setenv("MTMF_AUTH_ADMIN_PASSWORD", "pw")
    monkeypatch.setenv("MTMF_RUNTIME_DATABASE_URL", "postgresql+psycopg://r:y@127.0.0.1/db")
    monkeypatch.setenv("MTMF_MIGRATOR_DATABASE_URL", "postgresql+psycopg://m:y@127.0.0.1/db")
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(stack.OrchestrationError):
        stack.up_host_network()


# --- CR-U22/U23: initializer realm defaults and mismatch -------------------


def test_cru22_initializer_fixture_defaults_to_mtmf_dev(monkeypatch: pytest.MonkeyPatch):
    initializer = _load_initializer()
    monkeypatch.delenv("MTMF_AUTH_ADMIN_REALM", raising=False)
    monkeypatch.setenv("MTMF_AUTH_ISSUER", _ISSUER)
    fixture = initializer._dev_fixture("subject-1")
    assert fixture.realm == _REALM
    source = (_REPO_ROOT / "scripts" / "mtmf-dev-initialize.py").read_text(encoding="utf-8")
    assert source.count('"MTMF_AUTH_ADMIN_REALM", "mtmf-dev"') == 2


@pytest.mark.parametrize(
    ("issuer", "realm"),
    [
        (_ISSUER, "mtmf-pr14-dev"),
        ("https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev", _REALM),
        ("https://keycloak.mtmf.test:28443/realms/mtmf-dev/", _REALM),
        (_ISSUER + "-other", _REALM),
    ],
)
def test_cru23_initializer_realm_issuer_mismatch_stops(issuer: str, realm: str) -> None:
    initializer = _load_initializer()
    with pytest.raises(initializer.BootstrapError):
        initializer._require_realm_matches_issuer(issuer, realm)


# --- CR-U24/U25: compose realm defaults ------------------------------------


def test_cru24_compose_initializer_realm_default():
    compose = (_REPO_ROOT / "compose.dev.yaml").read_text(encoding="utf-8")
    assert compose.count("MTMF_AUTH_ADMIN_REALM:-mtmf-dev") == 2
    assert "MTMF_AUTH_ADMIN_REALM:-mtmf-pr14-dev" not in compose


def test_cru25_compose_service_realm_default():
    compose = (_REPO_ROOT / "compose.dev.yaml").read_text(encoding="utf-8")
    assert "MTMF_AUTH_ADMIN_REALM: ${MTMF_AUTH_ADMIN_REALM:-mtmf-dev}" in compose


# --- CR-U26: canonical admin unchanged -------------------------------------


def test_cru26_canonical_admin_is_master_realm():
    assert stack.CANONICAL_DEV_ADMIN_USERNAME == "mtmf-admin"
    compose = (_REPO_ROOT / "compose.dev.yaml").read_text(encoding="utf-8")
    assert "KC_BOOTSTRAP_ADMIN_USERNAME: ${MTMF_DEV_KC_ADMIN_USERNAME:-mtmf-admin}" in compose
    # The master admin is not the end-user realm.
    assert _REALM != "mtmf-admin"


# --- CR-U27: standard setup passes --realm; PR14 fixture default unchanged --


def test_cru27_realm_setup_invocation_and_fixture_default():
    setup = (_REPO_ROOT / "dev" / "keycloak" / "setup-realm.py").read_text(encoding="utf-8")
    assert 'DEFAULT_REALM = "mtmf-pr14-dev"' in setup  # independent fixture unchanged
    docs = (_REPO_ROOT / "docs" / "DEVELOPMENT_SETUP.md").read_text(encoding="utf-8")
    assert "--realm mtmf-dev" in docs


# --- CR-U29: probe rejects the legacy issuer -------------------------------


def test_cru29_probe_rejects_legacy_issuer():
    probe_script = _REPO_ROOT / "scripts" / "mtmf-dev-probe.py"
    spec = importlib.util.spec_from_file_location("mtmf_dev_probe_realm", probe_script)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = probe
    spec.loader.exec_module(probe)
    assert probe.CANONICAL_ISSUER == _ISSUER
    assert probe.EXPECTED_JWKS_URI == _JWKS
    with pytest.raises(probe.ProbeError):
        probe._parse_issuer("https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev")


# --- CR-U30: diagnostics do not echo untrusted input -----------------------


def test_cru30_diagnostics_redact_untrusted_input(monkeypatch: pytest.MonkeyPatch):
    bad = "https://user:secret@keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"
    _set_env(monkeypatch, issuer=bad)
    with pytest.raises(stack.OrchestrationError) as exc:
        stack._require_canonical_issuer()
    message = str(exc.value)
    assert bad not in message
    assert "secret" not in message


# --- CR-U28: no routine password reset (cross-reference) -------------------


def test_cru28_initializer_has_no_routine_password_reset():
    # The development-user path never resets an existing account's password;
    # this is covered exhaustively by tests/unit/service/test_pr17b_development_user.py
    # and re-verified live in CR-I12 (repeated up preserves the sub/credentials).
    source = (
        _REPO_ROOT / "packages" / "mtmf-service" / "src" / "mtmf_service" / "development_user.py"
    )
    text = source.read_text(encoding="utf-8")
    assert "reset-password" not in text.split("def ensure_user", 1)[1]
