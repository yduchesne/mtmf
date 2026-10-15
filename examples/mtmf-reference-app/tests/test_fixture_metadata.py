"""PR20B metadata fixture: canonical aggregate, idempotency, and drift failure.

The fixture is acceptance-only and uses sanctioned stored functions. These
tests exercise its pure canonical payload and its reconciliation/drift behavior
with an in-memory fake provisioner; no database is touched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

import pr20a_reference_fixture
import pr20b_metadata_fixture as metadata_fixture
import pytest

TENANT_ID = UUID("17ab63f3-16d9-57e9-a7a1-e42b9f0c0850")
OTHER_TENANT_ID = UUID("27ab63f3-16d9-57e9-a7a1-e42b9f0c0851")
ALICE = "fa09fe07-90a3-43ef-b01b-7e74ca5132ee"
BOB = "bf67cb4e-c7ff-4faa-b4b6-b261241a6cf2"


class _Result:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None


class _FakeProvisioner:
    def __init__(
        self, *, existing_tenant: Any = None, aggregate_rows: list[tuple[Any, ...]] | None = None
    ) -> None:
        self.existing_tenant = existing_tenant
        self.aggregate_rows = aggregate_rows or []
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    def _scalar(self, sql: str, params: tuple[Any, ...]) -> Any:
        if "defining_tenant_id" in sql:
            return self.existing_tenant
        return None

    def _execute(self, sql: str, params: tuple[Any, ...]) -> _Result:
        self.executed.append((sql, params))
        if "LEFT JOIN" in sql:
            return _Result(self.aggregate_rows)
        return _Result([])


def _expected_rows(tenant_id: UUID) -> list[tuple[Any, ...]]:
    payload = metadata_fixture.metadata_role_payload(tenant_id)
    rows: list[tuple[Any, ...]] = []
    for permission_set in payload["permission_sets"]:
        for permission in permission_set["permissions"]:
            rows.append(
                (
                    permission_set["id"],
                    permission_set["role_urn"],
                    permission_set["effect"],
                    permission["id"],
                    permission["permission_set_id"],
                    permission["urn"],
                )
            )
    return rows


def test_canonical_payload_has_exactly_one_allow_metadata_permission() -> None:
    payload = metadata_fixture.metadata_role_payload(TENANT_ID)
    assert payload["urn"] == metadata_fixture.metadata_role_urn(TENANT_ID)
    assert payload["urn"].endswith("reference-document-metadata-reader")
    assert len(payload["permission_sets"]) == 1
    permission_set = payload["permission_sets"][0]
    assert permission_set["effect"] == "allow"
    assert len(permission_set["permissions"]) == 1
    assert permission_set["permissions"][0]["urn"] == metadata_fixture.METADATA_PERMISSION
    assert metadata_fixture.METADATA_ACTION.endswith("document:read-metadata")
    assert metadata_fixture.METADATA_PERMISSION.endswith("document:read-metadata")


def test_assignment_ids_are_distinct_and_deterministic() -> None:
    alice = metadata_fixture.metadata_assignment_id(
        TENANT_ID, metadata_fixture.identity_id_for_subject(ALICE)
    )
    bob = metadata_fixture.metadata_assignment_id(
        TENANT_ID, metadata_fixture.identity_id_for_subject(BOB)
    )
    assert alice != bob
    assert alice == metadata_fixture.metadata_assignment_id(
        TENANT_ID, metadata_fixture.identity_id_for_subject(ALICE)
    )


def test_ensure_metadata_action_calls_action_add() -> None:
    provisioner = _FakeProvisioner()
    metadata_fixture.ensure_metadata_action(provisioner)
    sql, params = provisioner.executed[0]
    assert "mtmf.action_add" in sql
    assert params == (metadata_fixture.METADATA_ACTION,)


def test_ensure_metadata_role_creates_when_absent() -> None:
    provisioner = _FakeProvisioner(existing_tenant=None)
    metadata_fixture.ensure_metadata_role(provisioner, TENANT_ID)
    assert any("mtmf.role_add" in sql for sql, _params in provisioner.executed)


def test_ensure_metadata_role_is_idempotent_when_aggregate_matches() -> None:
    provisioner = _FakeProvisioner(
        existing_tenant=TENANT_ID, aggregate_rows=_expected_rows(TENANT_ID)
    )
    metadata_fixture.ensure_metadata_role(provisioner, TENANT_ID)
    assert not any("mtmf.role_add" in sql for sql, _params in provisioner.executed)


def test_ensure_metadata_role_rejects_aggregate_drift() -> None:
    provisioner = _FakeProvisioner(existing_tenant=TENANT_ID, aggregate_rows=[])
    with pytest.raises(metadata_fixture.MetadataFixtureError):
        metadata_fixture.ensure_metadata_role(provisioner, TENANT_ID)


def test_ensure_metadata_role_rejects_foreign_definition_namespace() -> None:
    provisioner = _FakeProvisioner(existing_tenant=OTHER_TENANT_ID)
    with pytest.raises(metadata_fixture.MetadataFixtureError):
        metadata_fixture.ensure_metadata_role(provisioner, TENANT_ID)


def test_ensure_metadata_assignment_uses_deterministic_id() -> None:
    provisioner = _FakeProvisioner()
    identity_id = metadata_fixture.identity_id_for_subject(BOB)
    metadata_fixture.ensure_metadata_assignment(provisioner, TENANT_ID, identity_id)
    sql, params = provisioner.executed[0]
    assert "mtmf.identity_role_assignment_add" in sql
    assert params[0] == metadata_fixture.metadata_assignment_id(TENANT_ID, identity_id)
    assert params[1] == TENANT_ID
    assert params[2] == identity_id
    assert params[3] == metadata_fixture.metadata_role_urn(TENANT_ID)


def test_classify_subjects_uses_persisted_content_assignment(tmp_path: Path) -> None:
    alice_identity = metadata_fixture.identity_id_for_subject(ALICE)
    content_assignment = pr20a_reference_fixture.reference_assignment_id(TENANT_ID, alice_identity)

    class _ClassifyProvisioner(_FakeProvisioner):
        def _execute(self, sql: str, params: tuple[Any, ...]) -> _Result:
            self.executed.append((sql, params))
            if "identity_role_assignment WHERE id" in sql:
                return _Result([(content_assignment,)])
            return _Result([])

    provisioner = _ClassifyProvisioner()
    classes = metadata_fixture.classify_subjects(provisioner, TENANT_ID, [ALICE, BOB])
    assert classes == {"allowed": ALICE, "denied": BOB}


def test_classify_subjects_fails_closed_on_ambiguity() -> None:
    provisioner = _FakeProvisioner()
    with pytest.raises(metadata_fixture.MetadataFixtureError):
        metadata_fixture.classify_subjects(provisioner, TENANT_ID, [ALICE, BOB])
