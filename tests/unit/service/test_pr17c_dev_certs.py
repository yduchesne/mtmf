"""PR 17-C development certificate helper tests (AM14-AM23).

Deterministic path/permission/logic tests plus real-OpenSSL PKI-state tests.
The tests assert that partial or inconsistent material never triggers
generation and leaves existing bytes/mtimes unchanged.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-certs.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_certs", _SCRIPT)
assert _spec is not None and _spec.loader is not None
certs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = certs
_spec.loader.exec_module(certs)

_MANAGED = ("ca_key", "ca_cert", "server_key", "server_cert")


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


def _generate_valid(tmp_path: Path) -> certs.CertPaths:
    assert certs.generate(tmp_path) is True
    paths = certs.CertPaths.resolve(tmp_path)
    for name in _MANAGED:
        assert getattr(paths, name).is_file()
    return paths


def _snapshot(paths: certs.CertPaths) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for name in _MANAGED:
        path = getattr(paths, name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            snapshot[name] = None
            continue
        if not stat.S_ISREG(info.st_mode):
            snapshot[name] = ("nonregular", info.st_mode)
            continue
        snapshot[name] = (path.read_bytes(), info.st_mtime_ns, info.st_mode)
    return snapshot


def _forbid_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certs, "_make_ca", lambda paths: pytest.fail("must not generate CA"))
    monkeypatch.setattr(
        certs, "_make_leaf", lambda paths, hostname: pytest.fail("must not generate leaf")
    )


# --- AM14: empty directory generates a complete, valid set -----------------


def test_am14_empty_directory_generates_valid_material(tmp_path: Path):
    paths = _generate_valid(tmp_path)
    certs.check(tmp_path)
    assert paths.ca_key.stat().st_mode & 0o077 == 0
    assert paths.server_key.stat().st_mode & 0o077 == 0
    assert paths.ca_cert.stat().st_mode & 0o077 != 0  # public


# --- AM15: complete valid set is idempotent and unchanged ------------------


def test_am15_complete_valid_is_idempotent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = _generate_valid(tmp_path)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    assert certs.generate(tmp_path) is False
    assert _snapshot(paths) == before


# --- AM16/AM17: partial material fails closed without side effects ---------


@pytest.mark.parametrize("present", ["ca_key", "ca_cert", "server_key", "server_cert"])
@pytest.mark.parametrize("of_four", [1, 3])
def test_am16_am17_partial_material_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, present: str, of_four: int
):
    paths = certs.CertPaths.resolve(tmp_path)
    tmp_path.mkdir(exist_ok=True)
    ordered = list(_MANAGED)
    chosen = ordered[:of_four] if of_four == 3 else [present]
    if present not in chosen:
        chosen[-1] = present
    for name in chosen:
        getattr(paths, name).write_bytes(b"placeholder")
        os.chmod(getattr(paths, name), 0o600)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)
    assert _snapshot(paths) == before


# --- AM18: symlink / non-regular managed material --------------------------


def test_am18_symlink_material_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = _generate_valid(tmp_path)
    real_key = tmp_path / "server.real.key"
    real_key.write_bytes(paths.server_key.read_bytes())
    paths.server_key.unlink()
    paths.server_key.symlink_to(real_key)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)
    assert _snapshot(paths) == before


def test_am18_directory_component_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = certs.CertPaths.resolve(tmp_path)
    tmp_path.mkdir(exist_ok=True)
    paths.ca_key.mkdir()
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)


# --- AM19: complete set with invalid SAN -----------------------------------


def test_am19_wrong_san_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = _generate_valid(tmp_path)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path, hostname="other.mtmf.test")
    assert _snapshot(paths) == before


# --- AM20/AM21: mismatched key pairs ---------------------------------------


def _unrelated_key(path: Path) -> None:
    certs._run(
        [
            certs._openssl(),
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(path),
        ]
    )
    os.chmod(path, 0o600)


def test_am20_mismatched_ca_key_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = _generate_valid(tmp_path)
    replacement = tmp_path / "other-ca.key"
    _unrelated_key(replacement)
    paths.ca_key.write_bytes(replacement.read_bytes())
    os.chmod(paths.ca_key, 0o600)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)
    assert _snapshot(paths) == before


def test_am21_mismatched_leaf_key_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    paths = _generate_valid(tmp_path)
    replacement = tmp_path / "other-leaf.key"
    _unrelated_key(replacement)
    paths.server_key.write_bytes(replacement.read_bytes())
    os.chmod(paths.server_key, 0o600)
    before = _snapshot(paths)
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)
    assert _snapshot(paths) == before


def test_pairing_helper_detects_mismatch(tmp_path: Path):
    paths = _generate_valid(tmp_path)
    other = tmp_path / "other.key"
    _unrelated_key(other)
    with pytest.raises(certs.CertError):
        certs._require_key_matches_cert(paths.server_cert, other, label="server")


# --- AM22: explicit rotation -----------------------------------------------


def test_am22_explicit_rotate_replaces_and_then_idempotent(tmp_path: Path):
    paths = _generate_valid(tmp_path)
    original = paths.ca_cert.read_bytes()
    assert certs.generate(tmp_path, rotate=True) is True
    assert paths.ca_cert.read_bytes() != original
    certs.check(tmp_path)
    before = _snapshot(paths)
    assert certs.generate(tmp_path) is False
    assert _snapshot(paths) == before


# --- AM23: interrupted rotation leaves partial material --------------------


def test_am23_partial_after_interrupted_rotation_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    paths = _generate_valid(tmp_path)
    paths.server_cert.unlink()  # simulate an interrupted rotation
    _forbid_generation(monkeypatch)
    with pytest.raises(certs.CertError):
        certs.generate(tmp_path)


# --- stale serial bookkeeping ----------------------------------------------


def test_stale_serial_on_empty_directory_is_ignored(tmp_path: Path):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "dev-ca.srl").write_text("DEADBEEF", encoding="ascii")
    paths = _generate_valid(tmp_path)
    assert paths.ca_cert.is_file()
    certs.check(tmp_path)
