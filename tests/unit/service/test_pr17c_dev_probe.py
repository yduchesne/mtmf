"""PR 17-C canonical issuer probe tests (N02-N08, AM08-AM13).

The probe must fail closed on DNS, TCP, TLS, discovery-issuer and JWKS
failures, and must never disable TLS verification, accept a mismatched
issuer, or fetch any JWKS URI other than the exact canonical endpoint.
HTTP/TLS/DNS boundaries are faked here; the live paths are exercised by the
WSL/Podman acceptance.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-probe.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_probe", _SCRIPT)
assert _spec is not None and _spec.loader is not None
probe = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = probe
_spec.loader.exec_module(probe)

ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
EXPECTED_JWKS = f"{ISSUER}/protocol/openid-connect/certs"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
CA_FILE = str(Path(tempfile.gettempdir()) / "ca.crt")


def test_parse_issuer_exact_canonical():
    assert probe._parse_issuer(ISSUER) == ("keycloak.mtmf.test", 28443)


@pytest.mark.parametrize(
    "bad",
    [
        "https://evil-keycloak.mtmf.test:28443/realms/mtmf-dev",
        "https://keycloak.mtmf.test.evil.example/realms/mtmf-dev",
        "https://keycloak.mtmf.test:28444/realms/mtmf-dev",
        "http://keycloak.mtmf.test:28443/realms/mtmf-dev",
        "https://keycloak.mtmf.test:28443/realms/other",
        "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
        "https://user@keycloak.mtmf.test:28443/realms/mtmf-dev",
        "https://keycloak.mtmf.test:28443/realms/mtmf-dev/",
        "https://keycloak.mtmf.test:28443/realms/mtmf-dev?x=1",
        "https://keycloak.mtmf.test:28443/realms/mtmf-dev#frag",
    ],
)
def test_parse_issuer_rejects_noncanonical_variants(bad: str):
    with pytest.raises(probe.ProbeError):
        probe._parse_issuer(bad)


def test_unresolvable_host_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def _fail(*_args: object, **_kwargs: object) -> list[str]:
        raise probe.ProbeError("does not resolve")

    monkeypatch.setattr(probe, "resolve_host", _fail)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def test_tcp_failure_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(probe, "resolve_host", lambda _host: ["127.0.0.1"])
    monkeypatch.setattr(
        probe, "check_tcp", lambda *a, **k: (_ for _ in ()).throw(probe.ProbeError("no"))
    )
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    discovery: dict[str, Any],
    documents: dict[str, Any],
) -> list[str]:
    """Wire a fake network and return the list of fetched URLs."""
    fetched: list[str] = []
    monkeypatch.setattr(probe, "resolve_host", lambda _host: ["127.0.0.1"])
    monkeypatch.setattr(probe, "check_tcp", lambda *a, **k: None)
    monkeypatch.setattr(probe, "tls_context", lambda _ca: ssl.create_default_context())

    def _fetch(url: str, *_args: object, **_kwargs: object) -> bytes:
        fetched.append(url)
        return json.dumps(documents[url]).encode()

    monkeypatch.setattr(probe, "_fetch", _fetch)
    documents[DISCOVERY_URL] = discovery
    return fetched


def test_issuer_mismatch_fails_closed(monkeypatch: pytest.MonkeyPatch):
    documents: dict[str, Any] = {}
    fetched = _wire(
        monkeypatch, {"issuer": "https://evil.example/realms/x", "jwks_uri": "x"}, documents
    )
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)
    assert fetched == [DISCOVERY_URL]


def test_am13_wrong_issuer_input_rejected_before_network(monkeypatch: pytest.MonkeyPatch):
    def _fail(*_args: object, **_kwargs: object) -> None:
        pytest.fail("network must not be touched for a non-canonical issuer")

    monkeypatch.setattr(probe, "resolve_host", _fail)
    monkeypatch.setattr(probe, "check_tcp", _fail)
    monkeypatch.setattr(probe, "_fetch", _fail)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer("https://evil.example/realms/x", CA_FILE, namespace="host", timeout=1)


@pytest.mark.parametrize(
    "jwks_uri",
    [
        f"{ISSUER}.evil/protocol/openid-connect/certs",
        "https://evil.example/protocol/openid-connect/certs",
        "https://keycloak.mtmf.test.evil.example/protocol/openid-connect/certs",
        "https://keycloak.mtmf.test:28444/protocol/openid-connect/certs",
        f"{ISSUER}/protocol/openid-connect/certs-other",
        f"{ISSUER}/realms/other/protocol/openid-connect/certs",
        "/protocol/openid-connect/certs",
        f"{EXPECTED_JWKS}?x=1",
        f"{EXPECTED_JWKS}#frag",
        f"{ISSUER}/protocol/openid-connect/%63erts",
    ],
)
def test_am09_am12_bad_jwks_uri_rejected_without_fetch(
    monkeypatch: pytest.MonkeyPatch, jwks_uri: str
):
    documents: dict[str, Any] = {}
    fetched = _wire(monkeypatch, {"issuer": ISSUER, "jwks_uri": jwks_uri}, documents)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)
    assert fetched == [DISCOVERY_URL]  # JWKS endpoint never requested


def test_am08_exact_jwks_uri_is_fetched_once(monkeypatch: pytest.MonkeyPatch):
    documents: dict[str, Any] = {EXPECTED_JWKS: {"keys": [{"kid": "k1"}]}}
    fetched = _wire(monkeypatch, {"issuer": ISSUER, "jwks_uri": EXPECTED_JWKS}, documents)
    report = probe.check_issuer(ISSUER, CA_FILE, namespace="container", timeout=1)
    assert fetched == [DISCOVERY_URL, EXPECTED_JWKS]
    assert any("discovery issuer ==" in line for line in report.checks)
    assert any(f"discovery jwks_uri == {EXPECTED_JWKS}" in line for line in report.checks)
    assert any("1 key" in line for line in report.checks)


def test_empty_jwks_fails_closed(monkeypatch: pytest.MonkeyPatch):
    documents: dict[str, Any] = {EXPECTED_JWKS: {"keys": []}}
    _wire(monkeypatch, {"issuer": ISSUER, "jwks_uri": EXPECTED_JWKS}, documents)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def test_tcp_check_reports_unreachable(monkeypatch: pytest.MonkeyPatch):
    def _fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", _fail)
    with pytest.raises(probe.ProbeError):
        probe.check_tcp("keycloak.mtmf.test", 28443, timeout=0.1)
