"""PR 17-C development stack orchestration tests (N01, N04, N11, N12, N24).

The launcher must prepare the canonical certificate material, start the
MTMF-owned forwarder, preflight the canonical issuer from both namespaces,
and only then run the one-shot initializer and the restricted service. These
tests fake the subprocess/DNS/HTTP/TLS boundaries only.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-stack.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_stack_pr17c", _SCRIPT)
assert _spec is not None and _spec.loader is not None
stack = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = stack
_spec.loader.exec_module(stack)

ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"

_REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_DEV = _REPO_ROOT / "compose.dev.yaml"
NSSWITCH = _REPO_ROOT / "dev" / "nsswitch.conf"

#: Canonical issuer variants that must be rejected before any side effect.
BAD_ISSUERS = [
    "https://evil-keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
    "https://keycloak.mtmf.test.evil.example/realms/mtmf-pr14-dev",
    "https://keycloak.mtmf.test:28444/realms/mtmf-pr14-dev",
    "http://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
    "https://keycloak.mtmf.test:28443/realms/other",
    "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/",
    "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev?x=1",
    "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev#frag",
    "https://user:secret@keycloak.mtmf.test:28443/realms/mtmf-pr14-dev",
    "https://127.0.0.1:28443/realms/mtmf-pr14-dev",
]


def _load_probe() -> Any:
    probe_script = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-probe.py"
    spec = importlib.util.spec_from_file_location("mtmf_dev_probe_for_constants", probe_script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


@pytest.mark.parametrize("bad", BAD_ISSUERS)
@pytest.mark.parametrize("entrypoint", ["up", "preflight"])
def test_am03_am07_rejected_before_side_effects(
    monkeypatch: pytest.MonkeyPatch, bad: str, entrypoint: str
):
    # Only the minimal environment is set: acceptance must happen before the
    # database URLs are read, certificate material is prepared, or Compose runs.
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "development")
    monkeypatch.setenv("MTMF_AUTH_ISSUER", bad)
    monkeypatch.delenv("MTMF_MIGRATOR_DATABASE_URL", raising=False)
    monkeypatch.delenv("MTMF_RUNTIME_DATABASE_URL", raising=False)
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: pytest.fail("must not prepare"))
    monkeypatch.setattr(stack, "_run", lambda *a, **k: pytest.fail("must not run"))
    monkeypatch.setattr(stack, "_probe_host", lambda *a: pytest.fail("must not probe"))
    monkeypatch.setattr(stack, "_probe_container", lambda *a: pytest.fail("must not probe"))
    with pytest.raises(stack.OrchestrationError) as exc:
        getattr(stack, entrypoint)()
    # AM07/AM24: the untrusted supplied value (which may contain credentials)
    # is never echoed in the failure diagnostic.
    message = str(exc.value)
    assert bad not in message
    assert "secret" not in message


def test_constants_agree_with_probe():
    probe = _load_probe()
    assert stack.CANONICAL_KC_ISSUER == probe.CANONICAL_ISSUER == ISSUER
    assert f"{ISSUER}/protocol/openid-connect/certs" == probe.EXPECTED_JWKS_URI


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


def test_probe_container_uses_static_resolver_override(monkeypatch: pytest.MonkeyPatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(stack, "_run", lambda args, *, check=True: calls.append(list(args)))
    stack._probe_container(ISSUER)
    command = calls[0]
    assert command[:3] == ["podman", "run", "--rm"]
    # LC07: DNS is made authoritative by the static override; no per-container
    # IP and no `--add-host` dynamic value is used.
    assert "--add-host" not in command
    nsswitch_index = command.index("-v")
    assert "dev/nsswitch.conf:/etc/nsswitch.conf:ro" in command[nsswitch_index + 1]
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


# --------------------------------------------------------------------------
# Amendment 2: stable Compose configuration and container lifecycle (LC01-LC16)
# --------------------------------------------------------------------------


def test_lc02_compose_model_has_no_dynamic_forwarder_input():
    text = COMPOSE_DEV.read_text(encoding="utf-8")
    assert "MTMF_DEV_FORWARDER_IP" not in text
    assert "extra_hosts" not in text


def test_lc05_lc06_initializer_and_service_mount_static_resolver_override():
    text = COMPOSE_DEV.read_text(encoding="utf-8")
    assert text.count("./dev/nsswitch.conf:/etc/nsswitch.conf:ro") == 2


def test_lc07_resolver_override_prefers_dns_over_files():
    content = NSSWITCH.read_text(encoding="utf-8")
    hosts_line = next(line for line in content.splitlines() if line.startswith("hosts:"))
    databases = hosts_line.split(":", 1)[1].split()
    assert databases[:2] == ["dns", "files"]


def test_lc08_no_forwarder_ip_discovery_or_guess_helper():
    # The dynamic IP is removed from launcher state entirely; a missing or
    # rebuilt forwarder is handled by the live probe, never a guessed/stale IP.
    assert not hasattr(stack, "_forwarder_ip")


def test_lc02_up_does_not_mutate_forwarder_ip(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch)
    monkeypatch.delenv("MTMF_DEV_FORWARDER_IP", raising=False)
    _record(monkeypatch)
    monkeypatch.setattr(stack, "_probe_until_stable", lambda probe, issuer, **k: probe(issuer))
    assert stack.up() == 0
    assert "MTMF_DEV_FORWARDER_IP" not in os.environ


def test_lc10_failed_preflight_blocks_initializer_and_service(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch)
    events = _record(monkeypatch)

    def _fail(_issuer: str) -> None:
        raise stack.OrchestrationError("canonical issuer probe failed")

    monkeypatch.setattr(stack, "_probe_until_stable", lambda probe, issuer, **k: probe(issuer))
    monkeypatch.setattr(stack, "_probe_host", _fail)
    with pytest.raises(stack.OrchestrationError):
        stack.up()
    run_args = [args for label, args in events if label == "run"]
    assert not any("initializer" in args for args in run_args)
    assert not any("service" in args for args in run_args)


def test_lc11_failed_initializer_blocks_service(monkeypatch: pytest.MonkeyPatch):
    _set_development_env(monkeypatch)
    events: list[tuple[str, Any]] = []

    def fake_run(args: list[str], *, check: bool = True) -> None:
        events.append(("run", list(args)))
        if "run" in args and "initializer" in args:
            raise stack.OrchestrationError("initializer failed")

    monkeypatch.setattr(stack, "_run", fake_run)
    monkeypatch.setattr(stack, "_prepare_certificates", lambda: None)
    monkeypatch.setattr(stack, "_postgres_inspect", lambda: None)
    monkeypatch.setattr(stack, "_wait_keycloak_http", lambda *a: None)
    monkeypatch.setattr(stack, "_probe_until_stable", lambda probe, issuer, **k: probe(issuer))
    monkeypatch.setattr(stack, "_probe_host", lambda *a: None)
    monkeypatch.setattr(stack, "_probe_container", lambda *a: None)
    with pytest.raises(stack.OrchestrationError):
        stack.up()
    run_args = [args for label, args in events if label == "run"]
    assert not any("up" in args and "service" in args for args in run_args)


def test_lc12_nonzero_command_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    with pytest.raises(stack.OrchestrationError):
        stack._run(["--not-a-real-option"])


def test_lc13_launcher_state_holds_no_container_ip(monkeypatch: pytest.MonkeyPatch):
    # A forwarder rebuild changes its address; because no IP is persisted in
    # the launcher or the Compose model, the next probe simply re-resolves the
    # MTMF network alias. Assert the launcher exposes no address cache.
    for name in ("_forwarder_ip", "_forwarder_address", "_FORWARDER_IP"):
        assert not hasattr(stack, name)


def test_lc14_secrets_are_redacted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MTMF_AUTH_ADMIN_PASSWORD", "supersecretvalue")
    redacted = stack._redact("value=supersecretvalue")
    assert "supersecretvalue" not in redacted
    assert "<redacted>" in redacted
