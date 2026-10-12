"""Ownership-verified host-network lifecycle tests (SEC-02, U19-U24)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-stack.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_stack", _SCRIPT)
assert _spec is not None and _spec.loader is not None
stack = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stack)


class _Result:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CommandSpy:
    """Records commands and returns scripted results based on command prefix."""

    def __init__(self, *, inspect: _Result | None = None, rm: _Result | None = None) -> None:
        self.commands: list[list[str]] = []
        self._inspect = inspect
        self._rm = rm

    def __call__(self, args: list[str], **kwargs: Any) -> _Result:
        self.commands.append(list(args))
        if args[:2] == ["podman", "inspect"]:
            return self._inspect or _Result(1, stderr="Error: no such container")
        if args[:3] == ["podman", "rm", "-f"]:
            return self._rm or _Result(0, stdout="container\n")
        return _Result(0)


def _owned_container() -> _Result:
    return _Result(
        0,
        stdout=json.dumps([{"Config": {"Labels": dict(stack.OWNERSHIP_LABELS)}}]),
    )


def test_u19_down_removes_owned_service_before_compose(monkeypatch: pytest.MonkeyPatch):
    spy = CommandSpy(inspect=_owned_container())
    monkeypatch.setattr(subprocess, "run", spy)
    assert stack.down() == 0
    methods = [(c[0], c[1] if len(c) > 1 else "") for c in spy.commands]
    assert methods[0] == ("podman", "inspect")
    assert ("podman", "rm") in methods
    rm_index = next(i for i, c in enumerate(spy.commands) if c[:3] == ["podman", "rm", "-f"])
    compose_index = next(i for i, c in enumerate(spy.commands) if c[0] == "podman-compose")
    assert rm_index < compose_index
    compose = spy.commands[compose_index]
    assert "-v" not in compose  # plain down preserves volumes


def test_u20_destroy_removes_owned_service_before_volume_teardown(monkeypatch: pytest.MonkeyPatch):
    spy = CommandSpy(inspect=_owned_container())
    monkeypatch.setattr(subprocess, "run", spy)
    assert stack.down_volumes() == 0
    compose = next(c for c in spy.commands if c[0] == "podman-compose")
    rm_index = next(i for i, c in enumerate(spy.commands) if c[:3] == ["podman", "rm", "-f"])
    assert rm_index < spy.commands.index(compose)
    assert "-v" in compose


def test_u21_absent_container_is_idempotent(monkeypatch: pytest.MonkeyPatch):
    spy = CommandSpy(inspect=_Result(1, stderr="Error: no such container"))
    monkeypatch.setattr(subprocess, "run", spy)
    assert stack.down() == 0
    assert not any(c[:3] == ["podman", "rm", "-f"] for c in spy.commands)
    assert any(c[0] == "podman-compose" for c in spy.commands)


def test_u22_foreign_container_is_never_removed(monkeypatch: pytest.MonkeyPatch):
    foreign = _Result(0, stdout=json.dumps([{"Config": {"Labels": {"other": "1"}}}]))
    spy = CommandSpy(inspect=foreign)
    monkeypatch.setattr(subprocess, "run", spy)
    with pytest.raises(stack.OrchestrationError):
        stack._cleanup_host_network_service()
    assert not any(c[:3] == ["podman", "rm", "-f"] for c in spy.commands)


def test_u23_inspect_error_and_rm_failure_abort(monkeypatch: pytest.MonkeyPatch):
    error = CommandSpy(inspect=_Result(1, stderr="cannot connect to socket"))
    monkeypatch.setattr(subprocess, "run", error)
    with pytest.raises(stack.OrchestrationError):
        stack._cleanup_host_network_service()
    failing = CommandSpy(inspect=_owned_container(), rm=_Result(1, stderr="device busy"))
    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(stack.OrchestrationError):
        stack._cleanup_host_network_service()


def test_u22_foreign_container_blocks_destroy(monkeypatch: pytest.MonkeyPatch):
    foreign = _Result(0, stdout=json.dumps([{"Config": {"Labels": {}}}]))
    spy = CommandSpy(inspect=foreign)
    monkeypatch.setattr(subprocess, "run", spy)
    with pytest.raises(stack.OrchestrationError):
        stack.down_volumes()
    # The Compose destroy must not have been reached.
    assert not any(c[0] == "podman-compose" for c in spy.commands)
