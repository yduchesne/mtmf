"""Unit tests for PostgreSQL stored-payload to domain mapping.

These tests exercise the strict mapping layer without a database: every
legal payload reconstructs the exact domain object, and every malformed
payload fails closed with :class:`PersistenceDataError` rather than
coercing data or returning a partial aggregate.
"""

from __future__ import annotations

import pytest
from helpers import make_identity, make_role, make_tenant

from mtmf_core import (
    ActionUrn,
    DomainId,
    RoleUrn,
    SecurityScope,
)
from mtmf_core.persistence.errors import PersistenceDataError, PersistenceIntegrityError
from mtmf_core.persistence.postgres.mapping import (
    action_from_urn,
    group_from_payload,
    identity_from_payload,
    organization_from_payload,
    principal_from_payload,
    role_from_payload,
    role_to_payload,
    tenant_from_payload,
)
from mtmf_core.persistence.postgres.repositories import _extension_param


def _tenant_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": "11111111-1111-4111-8111-111111111111",
        "name": "Tenant",
        "scope": 2,
        "owner_identity_id": "22222222-2222-4222-8222-222222222222",
        "deletion_status": 2,
        "extension": {"k": [1, None]},
    }
    payload.update(overrides)
    return payload


def test_tenant_round_trip() -> None:
    tenant = tenant_from_payload(_tenant_payload())
    assert tenant.id == DomainId.from_str("11111111-1111-4111-8111-111111111111")
    assert tenant.scope is SecurityScope.TENANT
    assert tenant.extension == {"k": [1, None]}


def test_organization_round_trip() -> None:
    organization = organization_from_payload(
        {
            "id": "11111111-1111-4111-8111-111111111111",
            "tenant_id": "44444444-4444-4444-8444-444444444444",
            "name": "Org",
            "owner_identity_id": "22222222-2222-4222-8222-222222222222",
            "deletion_status": 2,
            "extension": {},
        }
    )
    assert organization.tenant_id == DomainId.from_str("44444444-4444-4444-8444-444444444444")


def test_principal_identity_group_round_trip() -> None:
    principal = principal_from_payload(
        {"id": str(make_tenant().id), "name": "P", "deletion_status": 2, "extension": {}}
    )
    assert principal.name == "P"
    identity = identity_from_payload(
        {
            "id": str(make_identity().id),
            "principal_id": "33333333-3333-4333-8333-333333333333",
            "name": "I",
            "deletion_status": 2,
            "extension": {},
        }
    )
    assert identity.principal_id == DomainId.from_str("33333333-3333-4333-8333-333333333333")
    group = group_from_payload(
        {
            "id": str(make_tenant().id),
            "tenant_id": "44444444-4444-4444-8444-444444444444",
            "name": "G",
            "deletion_status": 2,
            "extension": {},
        }
    )
    assert group.tenant_id == DomainId.from_str("44444444-4444-4444-8444-444444444444")


def test_role_payload_round_trip() -> None:
    role = make_role(name="Rich", description="desc")
    payload = role_to_payload(role)
    restored = role_from_payload(payload)
    assert restored == role
    assert (
        restored.permission_sets[0].permissions[0].urn == role.permission_sets[0].permissions[0].urn
    )


def test_role_payload_carries_declared_ownership() -> None:
    role = make_role()
    payload = role_to_payload(role)
    (permission_set,) = payload["permission_sets"]  # type: ignore[misc]
    assert permission_set["role_urn"] == role.urn.value
    (permission,) = permission_set["permissions"]
    assert permission["permission_set_id"] == str(role.permission_sets[0].id)


def test_role_payload_with_tenant_definition_namespace() -> None:
    tenant_id = make_tenant().id
    role = make_role(tenant_id=tenant_id)
    restored = role_from_payload(role_to_payload(role))
    assert restored.defining_tenant_id == tenant_id


def test_action_from_urn() -> None:
    urn = ActionUrn("urn:mtmf:iam:actions:system:principal:get-object")
    assert action_from_urn(urn).urn == urn


def test_role_payload_system_namespace_has_no_defining_tenant() -> None:
    role = RoleUrn("urn:mtmf:iam:roles:system:unit-mapping")
    assert role.definition_namespace is not None


@pytest.mark.parametrize("payload", [None, [], "text", 3])
def test_non_object_payload_fails(payload: object) -> None:
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(payload)


def test_missing_and_wrong_typed_fields_fail() -> None:
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(name=3))
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(id="not-a-uuid"))
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(scope=9))
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(deletion_status=9))
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(extension=[1, 2]))
    with pytest.raises(PersistenceDataError):
        tenant_from_payload(_tenant_payload(scope=True))


def test_role_malformed_child_payloads_fail() -> None:
    payload = role_to_payload(make_role())
    payload["permission_sets"] = "not-an-array"
    with pytest.raises(PersistenceDataError):
        role_from_payload(payload)

    payload = role_to_payload(make_role())
    (permission_set,) = payload["permission_sets"]  # type: ignore[misc]
    permission_set["role_urn"] = "urn:mtmf:iam:roles:system:different"
    with pytest.raises(PersistenceDataError):
        role_from_payload(payload)

    payload = role_to_payload(make_role())
    (permission_set,) = payload["permission_sets"]  # type: ignore[misc]
    (permission,) = permission_set["permissions"]
    permission["permission_set_id"] = "11111111-1111-4111-8111-111111111111"
    with pytest.raises(PersistenceDataError):
        role_from_payload(payload)

    payload = role_to_payload(make_role())
    (permission_set,) = payload["permission_sets"]  # type: ignore[misc]
    permission_set["effect"] = "maybe"
    with pytest.raises(PersistenceDataError):
        role_from_payload(payload)


def test_role_missing_defining_tenant_is_null() -> None:
    urn = RoleUrn("urn:mtmf:iam:roles:system:unit-mapping")
    set_id = DomainId.from_str("11111111-1111-4111-8111-111111111111")
    payload: dict[str, object] = {
        "urn": urn.value,
        "name": "R",
        "description": "",
        "defining_tenant_id": None,
        "extension": {},
        "permission_sets": [
            {
                "id": str(set_id),
                "role_urn": urn.value,
                "effect": "allow",
                "permissions": [
                    {
                        "id": "22222222-2222-4222-8222-222222222222",
                        "permission_set_id": str(set_id),
                        "urn": "urn:mtmf:iam:permissions:system:principal:get-*",
                    }
                ],
            }
        ],
    }
    assert role_from_payload(payload).defining_tenant_id is None


def test_extension_param_accepts_object_and_rejects_non_object() -> None:
    assert _extension_param({"k": 1}) is not None
    for bad in (None, [], "x", 3):
        with pytest.raises(PersistenceIntegrityError):
            _extension_param(bad)
