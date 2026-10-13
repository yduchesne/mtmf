"""PR 17-C development stack orchestration tests (N01, N04, N11, N12, N24).

The launcher must prepare the canonical certificate material, start the
MTMF-owned forwarder, preflight the canonical issuer from both namespaces,
and only then run the one-shot initializer and the restricted service. These
tests fake the subprocess/DNS/HTTP/TLS boundaries only.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-stack.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_stack_pr17c", _SCRIPT)
assert _spec is not None and _spec.loader is not None
stack = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = stack
_spec.loader.exec_module(stack)

ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"


def _set_development_env(monkeypatch: pytest.MonkeyPatch, issuer: str = ISSUER) -> None:
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "development")
    monkeypatch.setenv("MTMF_MIGRATOR_DATABASE_URL", "postgresql+psycopg://m:y@127.0.0.1/db")
    monkeypatch.setenv("MTMF_RUNTIME_DATABASE_URL", "postgresql+psycopg://r:y@127.0.0.1/db")
    monkeypatch.setenv("MTMF_AUTH_ISSUER", issuer)
    monkeypatch.setenv("MTMF_AUTH_ADMIN_BASE", "https://keycloak.mtmf.test:28443")


def _record(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    events: list[tuple[str, Any]] = []

    def fake_run(args: list[str], *, check: bool = True) -> None:
        events.append(("run", list(args)))

    monkeypatch.setattr(stack, "_run", fake_run)
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: events.append(("certs", None)))
    monkeypatch.setattr(stack, "_postgres_inspect", lambda: events.append(("postgres", None)))
    monkeypatch.setattr(
        stack, "_wait_keycloak_http", lambda *a: events.append(("keycloak-wait", a))
    )
    monkeypatch.setattr(stack, "_forwarder_ip", lambda: "10.89.0.7")
    monkeypatch.setattr(stack, "_probe_host", lambda *a: events.append(("probe-host", a)))
    monkeypatch.setattr(stack, "_probe_container", lambda *a: events.append(("probe-container", a)))
    monkeypatch.setattr(stack, "_wait_http", lambda *a, **k: events.append(("service-ready", a)))
    return events


def test_up_orders_certs_forwarder_probes_initializer_service(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_development_env(monkeypatch)
    events = _record(monkeypatch)
    assert stack.up() == 0
    labels = [label for label, _ in events]
    assert labels.index("certs") < labels.index("postgres")
    assert labels.index("postgres") < labels.index("probe-host")
    assert labels.index("probe-host") < labels.index("probe-container")
    assert labels.index("probe-container") < labels.index("service-ready")
    compose_ups = [
        args for label, args in events if label == "run" and "up" in args and "-d" in args
    ]
    assert any({"postgres", "keycloak", "forwarder"} <= set(args) for args in compose_ups)
    assert any("service" in args for args in compose_ups)
    initializer = [
        args for label, args in events if label == "run" and "run" in args and "initializer" in args
    ]
    assert initializer, "the one-shot initializer must run"


def test_up_rejects_non_canonical_issuer(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch, issuer="https://127.0.0.1:28443/realms/mtmf-pr14-dev")
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: pytest.fail("must not prepare"))
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(stack.OrchestrationError):
        stack.up()


def test_prepare_certificates_generates_then_hardens(monkeypatch: pytest.MonkeyPatch):
    ca_dir = str(Path(tempfile.gettempdir()) / "mtmf-pr17c-ca")
    monkeypatch.setenv("MTMF_DEV_CA_DIR", ca_dir)
    calls: list[list[str]] = []
    monkeypatch.setattr(stack, "_run", lambda args, *, check=True: calls.append(list(args)))
    stack._prepare_certificates()
    assert len(calls) == 2
    assert calls[0][-2:] == ["generate"] or "generate" in calls[0]
    assert "harden" in calls[1]
    assert all("--dir" in call for call in calls)
    assert all(ca_dir in call for call in calls)


def test_probe_container_pins_canonical_host_to_forwarder(monkeypatch: pytest.MonkeyPatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(stack, "_run", lambda args, *, check=True: calls.append(list(args)))
    monkeypatch.setenv("MTMF_DEV_FORWARDER_IP", "10.89.0.7")
    stack._probe_container(ISSUER)
    command = calls[0]
    assert command[:3] == ["podman", "run", "--rm"]
    assert "--add-host" in command
    add_index = command.index("--add-host")
    assert command[add_index + 1] == "keycloak.mtmf.test:10.89.0.7"
    assert ISSUER in command
    assert stack.CA_CERT_IN_CONTAINER in command


def test_database_url_rewrites_to_internal_service(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "MTMF_MIGRATOR_DATABASE_URL",
        "postgresql+psycopg://mtmf_migrator:pw@127.0.0.1:25432/mtmf",
    )
    rewritten = stack._database_url_for_containers("MTMF_MIGRATOR_DATABASE_URL")
    assert rewritten == "postgresql+psycopg://mtmf_migrator:pw@postgres:5432/mtmf"


def test_database_url_requires_a_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MTMF_MIGRATOR_DATABASE_URL", raising=False)
    with pytest.raises(stack.OrchestrationError):
        stack._database_url_for_containers("MTMF_MIGRATOR_DATABASE_URL")


def test_ca_cert_file_default_and_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MTMF_PR14_KC_CA_FILE", raising=False)
    ca_dir = str(Path(tempfile.gettempdir()) / "mtmf-ca-default")
    monkeypatch.setenv("MTMF_DEV_CA_DIR", ca_dir)
    assert stack._ca_cert_file() == Path(ca_dir) / "dev-ca.crt"
    monkeypatch.setenv("MTMF_PR14_KC_CA_FILE", "/somewhere/ca.crt")
    assert stack._ca_cert_file() == Path("/somewhere/ca.crt")


def test_preflight_runs_both_namespaces(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch)
    seen: list[str] = []
    monkeypatch.setattr(stack, "_probe_host", lambda issuer: seen.append("host"))
    monkeypatch.setattr(stack, "_probe_container", lambda issuer: seen.append("container"))
    assert stack.preflight() == 0
    assert seen == ["host", "container"]


def test_preflight_rejects_non_canonical_issuer(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch, issuer="https://idp.example.com/realms/x")
    monkeypatch.setattr(stack, "_probe_host", lambda issuer: pytest.fail("must not probe"))
    with pytest.raises(stack.OrchestrationError):
        stack.preflight()
