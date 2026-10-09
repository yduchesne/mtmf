"""Role aggregate integration slice (V3).

The complete ``Role -> PermissionSet -> Permission`` aggregate is written
as one statement inside the caller's UnitOfWork, preserving child
identities, ownership, effects, matchers, and positional ordering, and
never committing a partial aggregate.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.types.json import Jsonb

from mtmf_core import (
    DomainId,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Principal,
    Role,
    RoleUrn,
)
from mtmf_core.persistence.errors import DuplicatePersistenceIdentityError
from mtmf_core.persistence.postgres.mapping import role_to_payload
from mtmf_core.persistence.spi import MtmfSpi


def _rich_role(role_urn: RoleUrn) -> Role:
    allow_set_id = DomainId.generate()
    deny_set_id = DomainId.generate()
    return Role(
        role_urn,
        "Rich Role",
        "description",
        None,
        (
            PermissionSet(
                allow_set_id,
                role_urn,
                PermissionEffect.ALLOW,
                (
                    Permission(
                        DomainId.generate(),
                        allow_set_id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-*"),
                    ),
                ),
            ),
            PermissionSet(
                deny_set_id,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        DomainId.generate(),
                        deny_set_id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-object"),
                    ),
                    Permission(
                        DomainId.generate(),
                        deny_set_id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*"),
                    ),
                ),
            ),
        ),
        {"meta": {"k": 1}},
    )


def test_v3_role_aggregate_add_and_get_preserves_children(postgres_spi: MtmfSpi) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:integration-rich")
    role = _rich_role(role_urn)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_role_repository(uow).get(role_urn)
    assert stored == role
    assert [ps.effect for ps in stored.permission_sets] == [
        PermissionEffect.ALLOW,
        PermissionEffect.DENY,
    ]
    assert [str(ps.id) for ps in stored.permission_sets] == [
        str(ps.id) for ps in role.permission_sets
    ]
    assert [p.urn.value for p in stored.permission_sets[1].permissions] == [
        "urn:mtmf:iam:permissions:system:principal:set-object",
        "urn:mtmf:iam:permissions:system:principal:set-*",
    ]


def test_v3_role_save_replaces_children_atomically(postgres_spi: MtmfSpi) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:integration-save")
    role = _rich_role(role_urn)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()

    set_id = DomainId.generate()
    replacement = Role(
        role_urn,
        "Replacement",
        role.description,
        None,
        (
            PermissionSet(
                set_id,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        DomainId.generate(),
                        set_id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-object"),
                    ),
                ),
            ),
        ),
        {"new": True},
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).save(replacement)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_role_repository(uow).get(role_urn)
    assert stored == replacement


def test_v3_get_absent_role_returns_none(postgres_spi: MtmfSpi) -> None:
    with postgres_spi.create_unit_of_work() as uow:
        assert (
            postgres_spi.create_role_repository(uow).get(
                RoleUrn("urn:mtmf:iam:roles:system:absent")
            )
            is None
        )


def test_v3_tenant_role_definition_ownership_round_trips(postgres_spi: MtmfSpi) -> None:
    from provider_helpers import seed_entity_graph

    graph = seed_entity_graph(postgres_spi)
    role_urn = RoleUrn(f"urn:mtmf:iam:roles:tenant:{graph.tenant.id}:scoped")
    set_id = DomainId.generate()
    role = Role(
        role_urn,
        "Scoped",
        "",
        graph.tenant.id,
        (
            PermissionSet(
                set_id,
                role_urn,
                PermissionEffect.ALLOW,
                (
                    Permission(
                        DomainId.generate(),
                        set_id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-object"),
                    ),
                ),
            ),
        ),
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_role_repository(uow).get(role_urn)
    assert stored.defining_tenant_id == graph.tenant.id


def test_v3_crafted_child_reparenting_is_rejected_by_the_function(
    runtime_connection: psycopg.Connection,
) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:crafted")
    set_id = DomainId.generate()
    payload = {
        "urn": role_urn.value,
        "name": "Crafted",
        "description": "",
        "defining_tenant_id": None,
        "extension": {},
        "permission_sets": [
            {
                "id": str(set_id),
                "role_urn": "urn:mtmf:iam:roles:system:other",
                "effect": "allow",
                "permissions": [
                    {
                        "id": str(DomainId.generate()),
                        "permission_set_id": str(set_id),
                        "urn": "urn:mtmf:iam:permissions:system:principal:get-object",
                    }
                ],
            }
        ],
    }
    with pytest.raises(psycopg.Error) as captured:
        runtime_connection.execute("SELECT mtmf.role_add(%s)", (Jsonb(payload),))
    assert captured.value.sqlstate == "MT001"
    runtime_connection.rollback()


def test_v3_failed_aggregate_rolls_back_sibling_writes(postgres_spi: MtmfSpi) -> None:
    principal = Principal(DomainId.generate(), "Sibling")
    shared_set_id = DomainId.generate()
    first_urn = RoleUrn("urn:mtmf:iam:roles:system:first")
    second_urn = RoleUrn("urn:mtmf:iam:roles:system:second")

    def role(role_urn: RoleUrn) -> Role:
        return Role(
            role_urn,
            "Role",
            "",
            None,
            (
                PermissionSet(
                    shared_set_id,
                    role_urn,
                    PermissionEffect.ALLOW,
                    (
                        Permission(
                            DomainId.generate(),
                            shared_set_id,
                            PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-object"),
                        ),
                    ),
                ),
            ),
        )

    with (
        pytest.raises(DuplicatePersistenceIdentityError),
        postgres_spi.create_unit_of_work() as uow,
    ):
        postgres_spi.create_principal_repository(uow).add(principal)
        postgres_spi.create_role_repository(uow).add(role(first_urn))
        # The second Role reuses the same PermissionSet UUID, which the
        # aggregate writer rejects; the whole transaction must roll back.
        postgres_spi.create_role_repository(uow).add(role(second_urn))
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_repository(uow).get(principal.id) is None
        assert postgres_spi.create_role_repository(uow).get(first_urn) is None
        assert postgres_spi.create_role_repository(uow).get(second_urn) is None


def test_v3_payload_serialization_is_detached(postgres_spi: MtmfSpi) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:detached")
    role = _rich_role(role_urn)
    payload = role_to_payload(role)
    assert payload["urn"] == role_urn.value
