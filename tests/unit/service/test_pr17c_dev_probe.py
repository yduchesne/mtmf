"""PR 17-C canonical issuer probe tests (N02, N03, N05, N06, N07, N08).

The probe must fail closed on DNS, TCP, TLS, discovery-issuer and JWKS
failures, and must never disable TLS verification or accept a mismatched
issuer. HTTP/TLS/DNS boundaries are faked here; the live paths are exercised
by the WSL/Podman acceptance.
"""

from __future__ import annotations

import importlib.util
import json
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

ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"
CA_FILE = str(Path(tempfile.gettempdir()) / "ca.crt")


def test_parse_issuer_requires_https_and_returns_canonical_port():
    assert probe._parse_issuer(ISSUER) == ("keycloak.mtmf.test", 28443)
    with pytest.raises(probe.ProbeError):
        probe._parse_issuer("http://keycloak.mtmf.test:28443/realms/x")


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


def _wire(monkeypatch: pytest.MonkeyPatch, discovery: dict[str, Any], documents: dict[str, Any]):
    monkeypatch.setattr(probe, "resolve_host", lambda _host: ["127.0.0.1"])
    monkeypatch.setattr(probe, "check_tcp", lambda *a, **k: None)
    monkeypatch.setattr(probe, "tls_context", lambda _ca: ssl.create_default_context())

    def _fetch(url: str, *_args: object, **_kwargs: object) -> bytes:
        return json.dumps(documents[url]).encode()

    monkeypatch.setattr(probe, "_fetch", _fetch)
    documents[f"{ISSUER}/.well-known/openid-configuration"] = discovery


def test_issuer_mismatch_fails_closed(monkeypatch: pytest.MonkeyPatch):
    documents: dict[str, Any] = {}
    _wire(monkeypatch, {"issuer": "https://evil.example/realms/x", "jwks_uri": "x"}, documents)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def test_foreign_jwks_uri_fails_closed(monkeypatch: pytest.MonkeyPatch):
    documents: dict[str, Any] = {}
    _wire(
        monkeypatch,
        {"issuer": ISSUER, "jwks_uri": "https://evil.example/certs"},
        documents,
    )
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def test_empty_jwks_fails_closed(monkeypatch: pytest.MonkeyPatch):
    jwks_uri = f"{ISSUER}/protocol/openid-connect/certs"
    documents: dict[str, Any] = {jwks_uri: {"keys": []}}
    _wire(monkeypatch, {"issuer": ISSUER, "jwks_uri": jwks_uri}, documents)
    with pytest.raises(probe.ProbeError):
        probe.check_issuer(ISSUER, CA_FILE, namespace="host", timeout=1)


def test_successful_preflight_records_non_secret_checks(monkeypatch: pytest.MonkeyPatch):
    jwks_uri = f"{ISSUER}/protocol/openid-connect/certs"
    documents: dict[str, Any] = {jwks_uri: {"keys": [{"kid": "k1"}]}}
    _wire(monkeypatch, {"issuer": ISSUER, "jwks_uri": jwks_uri}, documents)
    report = probe.check_issuer(ISSUER, CA_FILE, namespace="container", timeout=1)
    assert report.namespace == "container"
    assert any("discovery issuer ==" in line for line in report.checks)
    assert any("1 key" in line for line in report.checks)


def test_tcp_check_reports_unreachable(monkeypatch: pytest.MonkeyPatch):
    import socket

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", _fail)
    with pytest.raises(probe.ProbeError):
        probe.check_tcp("keycloak.mtmf.test", 28443, timeout=0.1)
