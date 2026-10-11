"""Pure contract tests for the G0-A mapper-attestation logic.

These tests exercise the canonical-manifest normalization, hashing, drift
diff, and fail-closed record handling without requiring a running Keycloak.
They are intentionally outside the default ``tests/unit`` gate.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "pr14-g0a-mapper-attestation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("pr14_g0a_attestation", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


att = _load_module()


def test_normalize_mappers_is_deterministic_and_excludes_instance_ids():
    mappers = [
        {
            "id": "instance-1",
            "name": "b",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": "x", "claim.value": "y"},
        },
        {
            "id": "instance-2",
            "name": "a",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"access.token.claim": "true", "included.custom.audience": "aud"},
        },
    ]
    normalized = att.normalize_mappers(mappers)
    assert [m["name"] for m in normalized] == ["a", "b"]
    assert all("id" not in m and "instance" not in json.dumps(m) for m in normalized)
    # Key order in config must not affect equality.
    assert att.normalize_mappers(list(reversed(mappers))) == normalized


def test_manifest_hash_is_stable():
    manifest = {
        "realm": "r",
        "clients": [{"clientId": "a"}, {"clientId": "b"}],
        "clientScopes": [],
    }
    assert att.manifest_hash(manifest) == att.manifest_hash(json.loads(json.dumps(manifest)))


def test_diff_manifests_detects_added_removed_and_changed():
    expected = {"a": 1, "b": {"c": [1, 2]}}
    actual = {"a": 2, "b": {"c": [1, 2, 3]}, "d": True}
    drift = att.diff_manifests(expected, actual)
    paths = {entry["path"] for entry in drift}
    assert "a" in paths
    assert "b.c" in paths
    assert "d" in paths
    assert att.diff_manifests({"x": 1}, {"x": 1}) == []


def test_check_record_fails_closed_on_missing_and_stale(tmp_path):
    missing = tmp_path / "record.json"
    assert att.check_record(str(missing), max_age_seconds=60).ok is False
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps({"hash": "h", "observed_at_epoch": 0}))
    assert att.check_record(str(stale), max_age_seconds=1).ok is False
    fresh = tmp_path / "fresh.json"
    import time

    fresh.write_text(json.dumps({"hash": "h", "observed_at_epoch": time.time()}))
    assert att.check_record(str(fresh), max_age_seconds=60).ok is True


def test_read_expected_fails_closed_on_missing_or_invalid(tmp_path):
    with pytest.raises(att.AttestationError):
        att.read_expected(str(tmp_path / "absent.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    with pytest.raises(att.AttestationError):
        att.read_expected(str(bad))


def test_committed_expected_manifest_is_secret_free():
    manifest = (
        Path(__file__).resolve().parents[2] / "dev" / "keycloak" / "expected-config-manifest.json"
    )
    if not manifest.exists():
        pytest.skip("expected manifest not present")
    text = manifest.read_text()
    assert "secret" not in text.lower()
    loaded = json.loads(text)
    assert loaded["realm"] == "mtmf-pr14-dev"
    assert any(client["clientId"] == "mtmf-evidence-user" for client in loaded["clients"])
