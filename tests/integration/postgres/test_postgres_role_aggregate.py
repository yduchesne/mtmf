"""Role aggregate integration slice (V3).

The complete ``Role -> PermissionSet -> Permission`` aggregate is written
as one statement inside the caller's UnitOfWork, preserving child
identities, ownership, effects, matchers, and positional ordering, and
never committing a partial aggregate.

The ``b1_`` cases (PR 7B-1 amendment) additionally prove that a save can
never reparent a currently persisted child UUID: an existing
``PermissionSet.id`` must still belong to the saved ``Role.urn``, and an
existing ``Permission.id`` must still belong to its enclosing
``PermissionSet.id``. The persisted-parent checks run before any
destructive write.
"""

from __future__ import annotations

import threading

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
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceIntegrityError,
    PersistenceTransactionError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi
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


# --- PR 7B-1: persisted child-ownership immutability -------------------------


def _single_set_role(
    role_urn: RoleUrn,
    *,
    name: str = "Role",
    set_id: DomainId,
    permission_id: DomainId,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    permission_urn: str = "urn:mtmf:iam:permissions:system:principal:get-object",
    defining_tenant_id: DomainId | None = None,
) -> Role:
    """A one-set Role whose child UUIDs are supplied explicitly."""
    return Role(
        role_urn,
        name,
        "",
        defining_tenant_id,
        (
            PermissionSet(
                set_id,
                role_urn,
                effect,
                (Permission(permission_id, set_id, PermissionUrn(permission_urn)),),
            ),
        ),
    )


def _two_roles(postgres_spi: MtmfSpi) -> tuple[Role, Role]:
    """Commit two independent Roles, each owning one set and one permission."""
    role_a = _single_set_role(
        RoleUrn("urn:mtmf:iam:roles:system:ownership-a"),
        name="A",
        set_id=DomainId.generate(),
        permission_id=DomainId.generate(),
    )
    role_b = _single_set_role(
        RoleUrn("urn:mtmf:iam:roles:system:ownership-b"),
        name="B",
        set_id=DomainId.generate(),
        permission_id=DomainId.generate(),
        effect=PermissionEffect.DENY,
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role_a)
        postgres_spi.create_role_repository(uow).add(role_b)
        uow.commit()
    return role_a, role_b


def _stored_role(postgres_spi: MtmfSpi, urn: RoleUrn) -> Role | None:
    with postgres_spi.create_unit_of_work() as uow:
        return postgres_spi.create_role_repository(uow).get(urn)


def test_b1_c01_retained_child_uuids_survive_mutable_changes(postgres_spi: MtmfSpi) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:retain")
    role = _rich_role(role_urn)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()

    first_set = role.permission_sets[0]
    retained = Role(
        role_urn,
        "Renamed",
        "changed description",
        None,
        (
            PermissionSet(
                first_set.id,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        first_set.permissions[0].id,
                        first_set.id,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*"),
                    ),
                ),
            ),
        ),
        {"changed": True},
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).save(retained)
        uow.commit()
    stored = _stored_role(postgres_spi, role_urn)
    assert stored == retained
    assert stored.permission_sets[0].id == first_set.id
    assert stored.permission_sets[0].permissions[0].id == first_set.permissions[0].id


def test_b1_c02_removed_children_disappear_and_new_children_are_added(
    postgres_spi: MtmfSpi,
) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:replace")
    role = _rich_role(role_urn)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()
    old_set_id = role.permission_sets[0].id
    new_set_id = DomainId.generate()
    replacement = _single_set_role(
        role_urn, name="Replacement", set_id=new_set_id, permission_id=DomainId.generate()
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).save(replacement)
        uow.commit()
    stored = _stored_role(postgres_spi, role_urn)
    assert stored == replacement
    assert stored.permission_sets[0].id == new_set_id
    assert all(permission_set.id != old_set_id for permission_set in stored.permission_sets)


def test_b1_c03_same_role_cross_set_permission_move_is_rejected(
    postgres_spi: MtmfSpi,
) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:cross-set")
    set_one = DomainId.generate()
    set_two = DomainId.generate()
    permission_id = DomainId.generate()
    role = Role(
        role_urn,
        "A",
        "",
        None,
        (
            PermissionSet(
                set_one,
                role_urn,
                PermissionEffect.ALLOW,
                (
                    Permission(
                        permission_id,
                        set_one,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-object"),
                    ),
                ),
            ),
            PermissionSet(
                set_two,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        DomainId.generate(),
                        set_two,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-object"),
                    ),
                ),
            ),
        ),
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()
    baseline = _stored_role(postgres_spi, role_urn)

    # Internally consistent (permission_set_id == enclosing set), but the
    # Permission UUID currently belongs to set_one and is moved to set_two.
    forged = _single_set_role(
        role_urn,
        name="A",
        set_id=set_two,
        permission_id=permission_id,
        effect=PermissionEffect.DENY,
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(PersistenceIntegrityError):
            postgres_spi.create_role_repository(uow).save(forged)
        with pytest.raises(PersistenceTransactionError):
            uow.commit()
        uow.rollback()
    assert _stored_role(postgres_spi, role_urn) == baseline


def test_b1_c04_cross_role_permission_reparenting_is_rejected(
    postgres_spi: MtmfSpi,
) -> None:
    role_a, role_b = _two_roles(postgres_spi)
    permission_a = role_a.permission_sets[0].permissions[0].id
    set_b = role_b.permission_sets[0].id
    baseline_a = _stored_role(postgres_spi, role_a.urn)
    baseline_b = _stored_role(postgres_spi, role_b.urn)

    forged = _single_set_role(
        role_b.urn,
        name="B",
        set_id=set_b,
        permission_id=permission_a,
        effect=PermissionEffect.DENY,
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(PersistenceIntegrityError):
            postgres_spi.create_role_repository(uow).save(forged)
        uow.rollback()
    assert _stored_role(postgres_spi, role_a.urn) == baseline_a
    assert _stored_role(postgres_spi, role_b.urn) == baseline_b


def test_b1_c05_cross_role_set_reuse_is_rejected(postgres_spi: MtmfSpi) -> None:
    role_a, role_b = _two_roles(postgres_spi)
    set_a = role_a.permission_sets[0].id
    baseline_a = _stored_role(postgres_spi, role_a.urn)
    baseline_b = _stored_role(postgres_spi, role_b.urn)

    # Internally consistent: the payload declares set_a under role B, but
    # set_a is currently persisted under role A.
    forged = _single_set_role(
        role_b.urn,
        name="B",
        set_id=set_a,
        permission_id=DomainId.generate(),
        effect=PermissionEffect.DENY,
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(PersistenceIntegrityError):
            postgres_spi.create_role_repository(uow).save(forged)
        uow.rollback()
    assert _stored_role(postgres_spi, role_a.urn) == baseline_a
    assert _stored_role(postgres_spi, role_b.urn) == baseline_b


def test_b1_c10_reused_set_and_permission_uuids_are_rejected(postgres_spi: MtmfSpi) -> None:
    role_a, role_b = _two_roles(postgres_spi)
    set_b = role_b.permission_sets[0].id
    permission_b = role_b.permission_sets[0].permissions[0].id
    baseline_a = _stored_role(postgres_spi, role_a.urn)

    # Reuse role B's persisted set under role A.
    forged_set = _single_set_role(
        role_a.urn, name="A", set_id=set_b, permission_id=DomainId.generate()
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(PersistenceIntegrityError):
            postgres_spi.create_role_repository(uow).save(forged_set)
        uow.rollback()

    # Reuse role B's persisted permission under a genuinely new set.
    forged_permission = _single_set_role(
        role_a.urn, name="A", set_id=DomainId.generate(), permission_id=permission_b
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(PersistenceIntegrityError):
            postgres_spi.create_role_repository(uow).save(forged_permission)
        uow.rollback()
    assert _stored_role(postgres_spi, role_a.urn) == baseline_a


def test_b1_c11_reordering_retained_children_is_allowed(postgres_spi: MtmfSpi) -> None:
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:reorder")
    set_one = DomainId.generate()
    set_two = DomainId.generate()
    permission_one = DomainId.generate()
    permission_two = DomainId.generate()
    role = Role(
        role_urn,
        "Ordered",
        "",
        None,
        (
            PermissionSet(
                set_one,
                role_urn,
                PermissionEffect.ALLOW,
                (
                    Permission(
                        permission_one,
                        set_one,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-a"),
                    ),
                ),
            ),
            PermissionSet(
                set_two,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        permission_two,
                        set_two,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-b"),
                    ),
                ),
            ),
        ),
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).add(role)
        uow.commit()
    reordered = Role(
        role_urn,
        "Ordered",
        "",
        None,
        (
            PermissionSet(
                set_two,
                role_urn,
                PermissionEffect.DENY,
                (
                    Permission(
                        permission_two,
                        set_two,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-b"),
                    ),
                ),
            ),
            PermissionSet(
                set_one,
                role_urn,
                PermissionEffect.ALLOW,
                (
                    Permission(
                        permission_one,
                        set_one,
                        PermissionUrn("urn:mtmf:iam:permissions:system:principal:get-a"),
                    ),
                ),
            ),
        ),
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_role_repository(uow).save(reordered)
        uow.commit()
    stored = _stored_role(postgres_spi, role_urn)
    assert [permission_set.id for permission_set in stored.permission_sets] == [set_two, set_one]


def test_b1_c09_save_unknown_role_is_a_contract_result(postgres_spi: MtmfSpi) -> None:
    unknown = _single_set_role(
        RoleUrn("urn:mtmf:iam:roles:system:unknown-save"),
        set_id=DomainId.generate(),
        permission_id=DomainId.generate(),
    )
    with postgres_spi.create_unit_of_work() as uow:
        with pytest.raises(UnknownPersistenceIdentityError):
            postgres_spi.create_role_repository(uow).save(unknown)
        # A contract result is not an aborted statement; the UoW still commits.
        uow.commit()


def test_b1_c12_rejected_save_rolls_back_sibling_write(postgres_spi: MtmfSpi) -> None:
    role_a, role_b = _two_roles(postgres_spi)
    set_a = role_a.permission_sets[0].id
    principal = Principal(DomainId.generate(), "Sibling")
    forged = _single_set_role(role_b.urn, name="B", set_id=set_a, permission_id=DomainId.generate())
    with (
        pytest.raises(PersistenceIntegrityError),
        postgres_spi.create_unit_of_work() as uow,
    ):
        postgres_spi.create_principal_repository(uow).add(principal)
        postgres_spi.create_role_repository(uow).save(forged)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        assert postgres_spi.create_principal_repository(uow).get(principal.id) is None
    assert _stored_role(postgres_spi, role_a.urn) == role_a


def test_b1_c06_forged_payload_role_urn_is_rejected(
    runtime_connection: psycopg.Connection,
) -> None:
    set_id = DomainId.generate()
    payload = {
        "urn": "urn:mtmf:iam:roles:system:forged-c06",
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


def test_b1_c07_forged_payload_permission_owner_is_rejected(
    runtime_connection: psycopg.Connection,
) -> None:
    set_id = DomainId.generate()
    payload = {
        "urn": "urn:mtmf:iam:roles:system:forged-c07",
        "name": "Crafted",
        "description": "",
        "defining_tenant_id": None,
        "extension": {},
        "permission_sets": [
            {
                "id": str(set_id),
                "role_urn": "urn:mtmf:iam:roles:system:forged-c07",
                "effect": "allow",
                "permissions": [
                    {
                        "id": str(DomainId.generate()),
                        "permission_set_id": str(DomainId.generate()),
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


def test_b1_persisted_reparenting_via_direct_runtime_call_is_rejected(
    postgres_spi: MtmfSpi, runtime_connection: psycopg.Connection
) -> None:
    role_a, role_b = _two_roles(postgres_spi)
    set_a = role_a.permission_sets[0].id
    forged = _single_set_role(role_b.urn, name="B", set_id=set_a, permission_id=DomainId.generate())
    payload = role_to_payload(forged)
    with pytest.raises(psycopg.Error) as captured:
        runtime_connection.execute("SELECT mtmf.role_save(%s)", (Jsonb(payload),))
    assert captured.value.sqlstate == "MT001"
    runtime_connection.rollback()
    # The rejected save mutated nothing.
    assert _stored_role(postgres_spi, role_a.urn) == role_a


def test_b1_concurrent_cross_role_reuse_never_reassigns_persisted_child(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    setup_provider = PostgresMtmfSpi(runtime_config)
    role_a, role_b = _two_roles(setup_provider)
    retained_set = role_a.permission_sets[0].id

    first_provider = PostgresMtmfSpi(runtime_config)
    second_provider = PostgresMtmfSpi(runtime_config)
    outcomes: dict[str, str] = {}
    started = threading.Barrier(2)

    def worker(name: str, provider: PostgresMtmfSpi, role: Role) -> None:
        try:
            with provider.create_unit_of_work() as uow:
                started.wait(timeout=10)
                provider.create_role_repository(uow).save(role)
                uow.commit()
            outcomes[name] = "committed"
        except PersistenceIntegrityError:
            outcomes[name] = "integrity"
        except DuplicatePersistenceIdentityError:
            outcomes[name] = "duplicate"
        except Exception as exc:
            outcomes[name] = f"error:{type(exc).__name__}"

    # Role A retains its set; Role B tries to reuse the same persisted UUID.
    forged_b = _single_set_role(
        role_b.urn,
        name="B",
        set_id=retained_set,
        permission_id=DomainId.generate(),
        effect=PermissionEffect.DENY,
    )
    threads = [
        threading.Thread(target=worker, args=("a", first_provider, role_a)),
        threading.Thread(target=worker, args=("b", second_provider, forged_b)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads), "concurrent saves must not hang"

    assert outcomes["a"] == "committed"
    assert outcomes["b"] in ("integrity", "duplicate")
    owner = db.execute(
        "SELECT role_urn FROM mtmf.permission_set WHERE id = %s", (retained_set.value,)
    ).fetchone()[0]
    assert owner == role_a.urn.value
