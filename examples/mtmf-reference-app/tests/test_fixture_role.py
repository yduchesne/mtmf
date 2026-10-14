"""R01-R10: exact fixture Role aggregate reconciliation.

The canonical payload has exactly one ALLOW permission set owning exactly one
Permission. These tests prove that an existing Role is accepted only when its
persisted security-relevant aggregate matches exactly, and that every drift is
rejected without any write.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pr20a_reference_fixture as fixture
import pytest

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-4222-8222-222222222222")


class _Result:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class FakeProvisioner:
    """Record privileged calls and serve deterministic aggregate rows."""

    def __init__(
        self,
        *,
        existing_tenant: uuid.UUID | None,
        rows: list[tuple[Any, ...]] | None = None,
    ) -> None:
        self._existing_tenant = existing_tenant
        self._rows = rows or []
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.scalar_calls: list[tuple[str, tuple[Any, ...]]] = []

    def _scalar(self, sql: str, params: tuple[Any, ...]) -> Any:
        self.scalar_calls.append((sql, params))
        return self._existing_tenant

    def _execute(self, sql: str, params: tuple[Any, ...]) -> _Result:
        self.executed.append((sql, params))
        if "mtmf.role_add" in sql:
            return _Result([])
        if "FROM mtmf.permission_set" in sql:
            return _Result(self._rows)
        raise AssertionError(f"unexpected SQL: {sql}")

    @property
    def role_add_calls(self) -> list[tuple[str, tuple[Any, ...]]]:
        return [entry for entry in self.executed if "mtmf.role_add" in entry[0]]

    @property
    def aggregate_reads(self) -> list[tuple[str, tuple[Any, ...]]]:
        return [entry for entry in self.executed if "FROM mtmf.permission_set" in entry[0]]


def _expected_row(tenant: uuid.UUID = TENANT) -> tuple[Any, ...]:
    """Return the one expected row with ``uuid.UUID`` values (psycopg-style)."""
    payload = fixture.reference_role_payload(tenant)
    permission_set = payload["permission_sets"][0]
    permission = permission_set["permissions"][0]
    return (
        uuid.UUID(permission_set["id"]),
        permission_set["role_urn"],
        permission_set["effect"],
        uuid.UUID(permission["id"]),
        uuid.UUID(permission["permission_set_id"]),
        permission["urn"],
    )


def _set_id(tenant: uuid.UUID = TENANT) -> uuid.UUID:
    return fixture.deterministic(f"reference-document-permission-set:{tenant}")


def _permission_id(tenant: uuid.UUID = TENANT) -> uuid.UUID:
    return fixture.deterministic(f"reference-document-permission:{tenant}")


def _role_urn(tenant: uuid.UUID = TENANT) -> str:
    return fixture.reference_role_urn(tenant)


def test_r01_absent_role_is_created_with_canonical_payload() -> None:
    provisioner = FakeProvisioner(existing_tenant=None)
    fixture.ensure_document_role(provisioner, TENANT)
    assert len(provisioner.role_add_calls) == 1
    _sql, params = provisioner.role_add_calls[0]
    assert json.loads(params[0]) == fixture.reference_role_payload(TENANT)
    assert provisioner.aggregate_reads == []


def test_r02_exact_aggregate_is_accepted_without_mutation() -> None:
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[_expected_row()])
    fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []
    assert len(provisioner.aggregate_reads) == 1


def test_r03_extra_deny_set_is_rejected() -> None:
    extra = (
        uuid.uuid4(),
        _role_urn(),
        "deny",
        uuid.uuid4(),
        uuid.uuid4(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[_expected_row(), extra])
    with pytest.raises(fixture.ReferenceFixtureError):
        fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []


def test_r04_extra_allow_set_is_rejected() -> None:
    extra = (
        uuid.uuid4(),
        _role_urn(),
        "allow",
        uuid.uuid4(),
        uuid.uuid4(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[_expected_row(), extra])
    with pytest.raises(fixture.ReferenceFixtureError):
        fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []


def test_r05_missing_permission_is_rejected() -> None:
    row = (_set_id(), _role_urn(), "allow", None, None, None)
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[row])
    with pytest.raises(fixture.ReferenceFixtureError):
        fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []


def test_r06_wrong_set_or_permission_identifier_is_rejected() -> None:
    wrong_set = (
        uuid.uuid4(),
        _role_urn(),
        "allow",
        _permission_id(),
        _set_id(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    wrong_permission = (
        _set_id(),
        _role_urn(),
        "allow",
        uuid.uuid4(),
        _set_id(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    for rows in ([wrong_set], [wrong_permission]):
        provisioner = FakeProvisioner(existing_tenant=TENANT, rows=rows)
        with pytest.raises(fixture.ReferenceFixtureError):
            fixture.ensure_document_role(provisioner, TENANT)
        assert provisioner.role_add_calls == []


def test_r07_wrong_effect_parent_or_role_urn_is_rejected() -> None:
    wrong_effect = (
        _set_id(),
        _role_urn(),
        "deny",
        _permission_id(),
        _set_id(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    wrong_role_urn = (
        _set_id(),
        _role_urn(OTHER_TENANT),
        "allow",
        _permission_id(),
        _set_id(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    wrong_parent = (
        _set_id(),
        _role_urn(),
        "allow",
        _permission_id(),
        uuid.uuid4(),
        fixture.DOCUMENT_READ_PERMISSION,
    )
    for rows in ([wrong_effect], [wrong_role_urn], [wrong_parent]):
        provisioner = FakeProvisioner(existing_tenant=TENANT, rows=rows)
        with pytest.raises(fixture.ReferenceFixtureError):
            fixture.ensure_document_role(provisioner, TENANT)
        assert provisioner.role_add_calls == []


def test_r08_role_owned_by_another_tenant_is_rejected_before_read() -> None:
    provisioner = FakeProvisioner(existing_tenant=OTHER_TENANT, rows=[_expected_row()])
    with pytest.raises(fixture.ReferenceFixtureError):
        fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []
    assert provisioner.aggregate_reads == []


def test_r09_repeated_initialization_is_idempotent() -> None:
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[_expected_row()])
    fixture.ensure_document_role(provisioner, TENANT)
    fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []
    assert len(provisioner.aggregate_reads) == 2


def test_r10_duplicate_rows_are_rejected_without_collapsing() -> None:
    provisioner = FakeProvisioner(existing_tenant=TENANT, rows=[_expected_row(), _expected_row()])
    with pytest.raises(fixture.ReferenceFixtureError):
        fixture.ensure_document_role(provisioner, TENANT)
    assert provisioner.role_add_calls == []
