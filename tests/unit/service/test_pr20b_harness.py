"""Deterministic tests for the PR 20B acceptance harness components.

These load the hyphenated scripts directly and exercise only pure logic: the
deterministic fixture-id math shared with the PR 20A fixture, the control-file
fault selection, and the response-tamper helper. No Podman, PostgreSQL,
Keycloak, or network is touched.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import pr20a_reference_fixture as reference_fixture  # noqa: E402


def _load(name: str, filename: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


transitions = _load("pr20b_transitions_test", "pr20b_fixture_transitions.py")
fault_proxy = _load("pr20b_fault_proxy_test", "pr20b-fault-proxy.py")
wrapper = _load("pr20b_wrapper_test", "pr20b-reference-acceptance.py")
metadata = _load("pr20b_metadata_fixture_test", "pr20b_metadata_fixture.py")


def test_fixture_transition_ids_match_reference_fixture() -> None:
    subject = "e4519a40-9d36-42c4-af80-eee42e7221ff"
    ids = transitions._fixture_ids("dev", subject)
    tenant_id = reference_fixture.deterministic("tenant:dev")
    identity_id = reference_fixture.deterministic(f"user-identity:{subject}")
    assert ids["tenant_id"] == tenant_id
    assert ids["identity_id"] == identity_id
    assert ids["assignment_id"] == reference_fixture.reference_assignment_id(tenant_id, identity_id)
    assert transitions._role_urn(tenant_id) == reference_fixture.reference_role_urn(tenant_id)


def test_transition_requires_explicit_acceptance_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MTMF_PR20B_ACCEPTANCE_DB", raising=False)
    with pytest.raises(transitions.TransitionError):
        transitions._expected_database()
    monkeypatch.setenv("MTMF_PR20B_ACCEPTANCE_DB", "mtmf")
    assert transitions._expected_database() == "mtmf"


def test_subscription_id_is_deterministic() -> None:
    first = transitions._subscription_id("dev", "evidence-same-client")
    second = transitions._subscription_id("dev", "evidence-same-client")
    assert first == second


def test_fault_proxy_defaults_to_none_without_control_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fault_proxy, "FAULT_FILE", "")
    assert fault_proxy._current_fault() == "none"


def test_fault_proxy_reads_known_mode_and_ignores_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = tmp_path / "fault"
    monkeypatch.setattr(fault_proxy, "FAULT_FILE", str(control))
    control.write_text("http_503", encoding="utf-8")
    assert fault_proxy._current_fault() == "http_503"
    control.write_text("not-a-mode", encoding="utf-8")
    assert fault_proxy._current_fault() == "none"


def test_fault_proxy_tampers_only_the_correlation_id() -> None:
    payload = json.dumps(
        {"decisions": [{"request_id": "document-read-0", "effect": "ALLOW", "reason": "PERMITTED"}]}
    ).encode()
    tampered = json.loads(fault_proxy._tamper_request_id(payload))
    assert tampered["decisions"][0]["request_id"] == "tampered-correlation-0000"
    assert tampered["decisions"][0]["effect"] == "ALLOW"


def test_fault_proxy_tamper_preserves_malformed_payload() -> None:
    assert fault_proxy._tamper_request_id(b"{not json") == b"{not json"


def test_wrapper_batch_document_is_distinct() -> None:
    assert wrapper.PR20B_BATCH_DOCUMENT_ID not in {
        "d0c0a1e0-0001-4000-8000-000000000001",
        "d0c0a1e0-0002-4000-8000-000000000002",
    }
    assert wrapper.PR20B_LIVE_TEST.startswith("tests/e2e/")


def test_known_fault_modes_are_complete() -> None:
    expected_modes = {
        "none",
        "refuse",
        "delay",
        "http_502",
        "http_503",
        "non_json",
        "malformed_json",
        "mismatch",
    }
    assert expected_modes == set(fault_proxy._KNOWN_FAULTS)


def test_wrapper_fault_hostname_is_distinct_and_canonical() -> None:
    assert wrapper.FAULT_HOSTNAME == "mtmf-fault.mtmf.test"
    assert wrapper.FAULT_HOSTNAME != "mtmf.mtmf.test"
    assert f"https://{wrapper.FAULT_HOSTNAME}:29501" == wrapper.FAULT_BASE_URL
    assert wrapper.FAULT_PROXY_CONTAINER.startswith("mtmf-pr20a-acceptance_")


def test_wrapper_known_modes_match_proxy() -> None:
    assert set(fault_proxy._KNOWN_FAULTS) == wrapper.KNOWN_FAULT_MODES


def test_metadata_fixture_action_and_role_contract() -> None:
    tenant_id = uuid.UUID("17ab63f3-16d9-57e9-a7a1-e42b9f0c0850")
    assert metadata.METADATA_ACTION.endswith("document:read-metadata")
    assert metadata.METADATA_PERMISSION.endswith("document:read-metadata")
    assert metadata.METADATA_ACTION != reference_fixture.DOCUMENT_READ_ACTION
    payload = metadata.metadata_role_payload(tenant_id)
    assert payload["urn"] == metadata.metadata_role_urn(tenant_id)
    assert payload["urn"].endswith("reference-document-metadata-reader")
    assert len(payload["permission_sets"]) == 1
    permission_set = payload["permission_sets"][0]
    assert permission_set["effect"] == "allow"
    assert len(permission_set["permissions"]) == 1
    assert permission_set["permissions"][0]["urn"] == metadata.METADATA_PERMISSION


def test_metadata_assignments_are_distinct_per_subject() -> None:
    tenant_id = uuid.UUID("17ab63f3-16d9-57e9-a7a1-e42b9f0c0850")
    alice = metadata.metadata_assignment_id(
        tenant_id, metadata.identity_id_for_subject("subject-alice")
    )
    bob = metadata.metadata_assignment_id(
        tenant_id, metadata.identity_id_for_subject("subject-bob")
    )
    assert alice != bob


def test_fault_proxy_records_non_secret_fault_and_error_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence.jsonl"
    monkeypatch.setattr(fault_proxy, "EVIDENCE_FILE", str(evidence))
    fault_proxy._record_fault("http_503")
    fault_proxy._record_error(
        401,
        b'{"error":{"code":"UNAUTHENTICATED","message":"secret-free"}}',
        "application/json",
    )
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert any(record.get("fault") == "http_503" for record in records)
    assert any(record.get("error_code") == "UNAUTHENTICATED" for record in records)
    assert all("token" not in json.dumps(record).lower() for record in records)
