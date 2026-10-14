"""Deterministic unit tests for the PR 19A provenance contract.

These tests exercise the immutable :class:`VerifiedMutationProvenance`
contract and its fail-closed registration guard. They do **not** prove the
end-to-end trusted-application mutation path: PR 19A Phase 0 found no
category-A management mutation entry point, so the database/atomicity cases
of the PR 19A matrix are recorded as BLOCKED in
``docs/pr-artifacts/pr-19a/`` rather than simulated here.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from helpers import make_action_urn

from mtmf_core.application import mutation_provenance as module
from mtmf_core.application.mutation_provenance import (
    MutationProvenanceError,
    UnregisteredMutationError,
    VerifiedMutationProvenance,
    registered_mutations,
    require_registered_mutation,
)
from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.domain.identity import DomainId


def _valid_provenance(**overrides: object) -> VerifiedMutationProvenance:
    values: dict[str, object] = {
        "operation_id": uuid4(),
        "actor_identity_id": DomainId.generate(),
        "actor_principal_id": DomainId.generate(),
        "tenant_id": DomainId.generate(),
        "application_id": DomainId.generate(),
        "action_urn": make_action_urn(),
        "target_kind": "tenant",
        "target_id": DomainId.generate(),
        "authorized_at": datetime.now(UTC),
    }
    values.update(overrides)
    return VerifiedMutationProvenance(**values)  # type: ignore[arg-type]


# --- PA-U01: structurally valid provenance is accepted and immutable --------


def test_pa_u01_valid_provenance_is_accepted_and_immutable() -> None:
    provenance = _valid_provenance()
    assert isinstance(provenance.operation_id, UUID)
    assert provenance.target_kind == "tenant"
    assert provenance.authorized_at.tzinfo is not None

    with pytest.raises(FrozenInstanceError):
        provenance.target_kind = "identity"  # type: ignore[misc]


def test_pa_u01_equal_field_values_compare_equal() -> None:
    operation_id = uuid4()
    identity_id = DomainId.generate()
    principal_id = DomainId.generate()
    tenant_id = DomainId.generate()
    application_id = DomainId.generate()
    target_id = DomainId.generate()
    action = make_action_urn()
    instant = datetime.now(UTC)
    first = VerifiedMutationProvenance(
        operation_id,
        identity_id,
        principal_id,
        tenant_id,
        application_id,
        action,
        "tenant",
        target_id,
        instant,
    )
    second = VerifiedMutationProvenance(
        operation_id,
        identity_id,
        principal_id,
        tenant_id,
        application_id,
        action,
        "tenant",
        target_id,
        instant,
    )
    assert first == second
    assert first.authorized_at_utc == instant.astimezone(UTC)


def test_pa_u01_offset_zero_timestamp_is_normalized_to_utc() -> None:
    offset_zero = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(0)))
    provenance = _valid_provenance(authorized_at=offset_zero)
    assert provenance.authorized_at_utc.tzinfo is UTC


# --- PA-U02: missing/None actor, tenant, application or target --------------


@pytest.mark.parametrize(
    "field",
    [
        "actor_identity_id",
        "actor_principal_id",
        "tenant_id",
        "application_id",
        "target_id",
    ],
)
def test_pa_u02_none_identity_is_rejected(field: str) -> None:
    with pytest.raises(MutationProvenanceError, match="must be a DomainId"):
        _valid_provenance(**{field: None})


def test_pa_u02_missing_required_field_is_a_constructor_error() -> None:
    with pytest.raises(TypeError):
        VerifiedMutationProvenance(  # type: ignore[call-arg]
            operation_id=uuid4(),
            actor_identity_id=DomainId.generate(),
            actor_principal_id=DomainId.generate(),
            tenant_id=DomainId.generate(),
            application_id=DomainId.generate(),
            action_urn=make_action_urn(),
            target_kind="tenant",
            authorized_at=datetime.now(UTC),
        )


def test_pa_u02_empty_or_malformed_target_kind_is_rejected() -> None:
    for bad in (None, "", " tenant", "tenant ", "ten ant", "x" * 65):
        with pytest.raises(MutationProvenanceError, match="target_kind"):
            _valid_provenance(target_kind=bad)


# --- PA-U03: operation UUID and UTC instant validation ----------------------


def test_pa_u03_non_uuid_operation_id_is_rejected() -> None:
    for bad in (None, "not-a-uuid", "00000000-0000-0000-0000-000000000000"):
        with pytest.raises(MutationProvenanceError, match="operation_id"):
            _valid_provenance(operation_id=bad)


def test_pa_u03_naive_timestamp_is_rejected() -> None:
    with pytest.raises(MutationProvenanceError, match="timezone-aware UTC"):
        _valid_provenance(authorized_at=datetime(2026, 1, 1, 12, 0))


def test_pa_u03_non_utc_timestamp_is_rejected() -> None:
    non_utc = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    with pytest.raises(MutationProvenanceError, match="timezone-aware UTC"):
        _valid_provenance(authorized_at=non_utc)


def test_pa_u03_non_datetime_timestamp_is_rejected() -> None:
    with pytest.raises(MutationProvenanceError, match="must be a datetime"):
        _valid_provenance(authorized_at="2026-01-01T00:00:00Z")


def test_pa_u03_non_action_urn_is_rejected() -> None:
    for bad in (None, "urn:mtmf:iam:actions:system:tenant:get-object"):
        with pytest.raises(MutationProvenanceError, match="action_urn"):
            _valid_provenance(action_urn=bad)
    # A validated ActionUrn is accepted.
    assert _valid_provenance(action_urn=ActionUrn("urn:mtmf:iam:actions:system:tenant:get-object"))


# --- PA-U04: no caller-supplied-actor factory or trust flag -----------------


def test_pa_u04_module_exposes_no_trusted_factory_or_flag() -> None:
    # No convenience constructor that would accept a raw actor ID as proof.
    assert not hasattr(module, "from_actor_id")
    assert not hasattr(module, "for_actor")
    assert not hasattr(module, "trusted")
    # The only public callables are the read-only registry and its guard.
    assert callable(module.require_registered_mutation)
    assert callable(module.registered_mutations)
    # Construction has no boolean "trusted"/"verified" field.
    provenance = _valid_provenance()
    assert not hasattr(provenance, "trusted")
    assert not hasattr(provenance, "verified")


# --- PA-U13: closed target-kind/Action registration guard -------------------


def test_pa_u13_registry_is_empty_and_read_only_in_pr19a() -> None:
    assert dict(registered_mutations()) == {}
    with pytest.raises(TypeError):
        registered_mutations()["tenant"] = frozenset()  # type: ignore[index]


def test_pa_u13_unregistered_target_kind_fails_closed() -> None:
    provenance = _valid_provenance(target_kind="tenant")
    with pytest.raises(UnregisteredMutationError, match="not an approved mutation target"):
        require_registered_mutation(provenance)


def test_pa_u13_unapproved_action_for_registered_kind_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provenance = _valid_provenance(target_kind="tenant")
    monkeypatch.setattr(module, "_MIGRATED_MUTATIONS", {"tenant": frozenset({"urn:other"})})
    with pytest.raises(UnregisteredMutationError, match="is not approved for target kind"):
        require_registered_mutation(provenance)


def test_pa_u13_approved_pairing_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    provenance = _valid_provenance(target_kind="tenant")
    monkeypatch.setattr(
        module, "_MIGRATED_MUTATIONS", {"tenant": frozenset({provenance.action_urn.value})}
    )
    require_registered_mutation(provenance)
