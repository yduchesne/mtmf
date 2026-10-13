"""PR 17-C development certificate helper tests.

Only the deterministic path/permission/idempotency logic is unit-tested; the
actual X.509 trust and container-UID readability are exercised by the live WSL
acceptance.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-certs.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_certs", _SCRIPT)
assert _spec is not None and _spec.loader is not None
certs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = certs
_spec.loader.exec_module(certs)


def test_cert_paths_are_deterministic(tmp_path: Path):
    paths = certs.CertPaths.resolve(tmp_path)
    assert paths.ca_key == tmp_path / "dev-ca.key"
    assert paths.ca_cert == tmp_path / "dev-ca.crt"
    assert paths.server_key == tmp_path / "server.key"
    assert paths.server_cert == tmp_path / "server.crt"


def test_default_directory_respects_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("MTMF_DEV_CA_DIR", str(tmp_path / "ca"))
    assert certs.default_directory() == tmp_path / "ca"
    monkeypatch.delenv("MTMF_DEV_CA_DIR", raising=False)
    assert certs.default_directory().name == "mtmf-dev-ca"


def test_incomplete_material_fails_closed(tmp_path: Path):
    with pytest.raises(certs.CertError):
        certs.check(tmp_path)


def test_harden_requires_leaf_key(tmp_path: Path):
    empty = certs.CertPaths.resolve(tmp_path)
    assert not empty.server_key.exists()
    with pytest.raises(certs.CertError):
        certs.harden(tmp_path)


def test_harden_fails_closed_without_podman(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = certs.CertPaths.resolve(tmp_path)
    tmp_path.mkdir(exist_ok=True)
    paths.server_key.write_bytes(b"not-a-real-key")
    monkeypatch.setattr(certs.shutil, "which", lambda _name: None)
    with pytest.raises(certs.CertError):
        certs.harden(tmp_path)


def test_generate_is_idempotent_without_rotate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(certs, "_exists", lambda paths: True)
    monkeypatch.setattr(certs, "check", lambda directory, *, hostname: None)
    monkeypatch.setattr(certs, "_make_ca", lambda paths: pytest.fail("must not recreate CA"))
    monkeypatch.setattr(
        certs, "_make_leaf", lambda paths, hostname: pytest.fail("must not recreate")
    )
    assert certs.generate(tmp_path) is False


def test_generate_rotate_replaces_material(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    made: list[str] = []
    monkeypatch.setattr(certs, "_make_ca", lambda paths: made.append("ca"))
    monkeypatch.setattr(certs, "_make_leaf", lambda paths, hostname: made.append("leaf"))
    monkeypatch.setattr(certs, "_set_permissions", lambda paths: None)
    monkeypatch.setattr(certs, "check", lambda directory, *, hostname: None)
    assert certs.generate(tmp_path, rotate=True) is True
    assert made == ["ca", "leaf"]
