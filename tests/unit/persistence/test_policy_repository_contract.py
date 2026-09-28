"""Policy repository contract tests (plan Policy matrix).

Role is persisted as one ``Role -> PermissionSet -> Permission``
aggregate owned by its canonical Role URN: PermissionSet effects and
Permission matcher URNs (including complete-qualifier wildcards) round
trip, extensions are preserved, and changes participate in
commit/rollback. PermissionSets and Permissions are not independently
assignable aggregates, and no RoleAssignment model exists.

Action is a shared exact definition identified by its immutable Action
URN; wildcard Action URNs remain impossible.
"""

from __future__ import annotations

import pytest
from helpers import (
    make_id,
    make_permission_set,
    make_permission_urn,
    make_role,
    make_role_urn,
)

from mtmf_core import (
    BASELINE_ACTIONS,
    Action,
    ActionUrn,
    DomainInvariantError,
    Permission,
    PermissionEffect,
    PermissionSet,
    Role,
    RoleUrn,
)
from mtmf_core.persistence import (
    DuplicatePersistenceIdentityError,
    MtmfSpi,
)


def _rich_role() -> object:
    """A SYSTEM Role with ALLOW and DENY sets, exact and wildcard matchers."""
    role_urn = make_role_urn(role_name="rich-role")
    allow_set_id = make_id()
    deny_set_id = make_id()
    allow_set = PermissionSet(
        allow_set_id,
        role_urn,
        PermissionEffect.ALLOW,
        (
            Permission(
                make_id(),
                allow_set_id,
                make_permission_urn(verb="set", qualifier="*"),
            ),
        ),
    )
    deny_set = PermissionSet(
        deny_set_id,
        role_urn,
        PermissionEffect.DENY,
        (
            Permission(
                make_id(),
                deny_set_id,
                make_permission_urn(verb="set", qualifier="alias"),
            ),
        ),
    )
    return Role(
        role_urn, "Rich Role", "A rich role", None, (allow_set, deny_set), {"meta": {"k": 1}}
    )


def test_role_aggregate_round_trip(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert stored == role
        assert stored is not role
        assert stored.permission_sets is not role.permission_sets
        assert stored.permission_sets[0] is not role.permission_sets[0]
        assert stored.permission_sets[0].permissions is not role.permission_sets[0].permissions


def test_role_permission_set_effects_and_matcher_urns_preserved(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert [permission_set.effect for permission_set in stored.permission_sets] == [
            PermissionEffect.ALLOW,
            PermissionEffect.DENY,
        ]
        assert stored.permission_sets[0].permissions[0].urn.value.endswith(":set-*")
        assert stored.permission_sets[1].permissions[0].urn.value.endswith(":set-alias")
        assert stored.permission_sets[0].permissions[0].urn.is_wildcard


def test_role_definition_ownership_preserved(spi: MtmfSpi) -> None:
    tenant_id = make_id()
    role = make_role(tenant_id=tenant_id)
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert stored.urn == role.urn
        assert stored.urn.encoded_tenant_id == tenant_id
        assert stored.defining_tenant_id == tenant_id


def test_role_extension_preserved(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert stored.extension == role.extension
        assert stored.extension is not role.extension


def test_role_mutation_without_save_is_not_durable(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = spi.create_role_repository(uow).get(role.urn)
        loaded.name = "mutated"
        loaded.extension["meta"] = "mutated"
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert stored.name == "Rich Role"
        assert stored.extension["meta"] == {"k": 1}


def test_role_save_commit_updates(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    replacement = Role(
        role.urn,
        "Replacement",
        role.description,
        role.defining_tenant_id,
        (make_permission_set(role_urn=role.urn, effect=PermissionEffect.DENY),),
        {"new": True},
    )
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).save(replacement)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_role_repository(uow).get(role.urn)
        assert stored.name == "Replacement"
        assert len(stored.permission_sets) == 1
        assert stored.permission_sets[0].effect is PermissionEffect.DENY
        assert stored.extension == {"new": True}


def test_role_save_rollback_reverts(spi: MtmfSpi) -> None:
    role = _rich_role()
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = spi.create_role_repository(uow).get(role.urn)
        loaded.name = "would-be"
        spi.create_role_repository(uow).save(loaded)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert spi.create_role_repository(uow).get(role.urn).name == "Rich Role"


def test_role_duplicate_urn_fails(spi: MtmfSpi) -> None:
    role = _rich_role()
    duplicate = _rich_role()
    with spi.create_unit_of_work() as uow:
        repo = spi.create_role_repository(uow)
        repo.add(role)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(duplicate)
        uow.commit()
    with spi.create_unit_of_work() as uow, pytest.raises(DuplicatePersistenceIdentityError):
        spi.create_role_repository(uow).add(duplicate)


def test_role_urn_is_the_persistence_identity_not_the_name(spi: MtmfSpi) -> None:
    urn = make_role_urn(role_name="canonical")
    renamed = Role(urn, "display-name", "", None, (make_permission_set(role_urn=urn),))
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(renamed)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_role_repository(uow).get(RoleUrn(urn.value)) == renamed


def test_no_role_assignment_persistence_surface() -> None:
    import mtmf_core.persistence as persistence

    assert not hasattr(persistence, "RoleAssignment")
    assert not hasattr(persistence, "RoleAssignmentRepository")


def test_permission_set_and_permission_are_not_independently_assignable(spi: MtmfSpi) -> None:
    import mtmf_core.persistence as persistence

    for factory_name in (
        "create_permission_set_repository",
        "create_permission_repository",
        "create_policy_repository",
    ):
        assert not hasattr(spi, factory_name)
        assert not hasattr(persistence, factory_name.replace("create_", "").title())


def test_action_add_get_round_trip(spi: MtmfSpi) -> None:
    for urn in BASELINE_ACTIONS:
        action = Action(urn)
        with spi.create_unit_of_work() as uow:
            spi.create_action_repository(uow).add(action)
            uow.commit()
        with spi.create_unit_of_work() as uow:
            stored = spi.create_action_repository(uow).get(urn)
            assert stored == action
            assert stored.urn.value == urn.value


def test_action_read_your_writes_within_one_transaction(spi: MtmfSpi) -> None:
    urn = BASELINE_ACTIONS[0]
    with spi.create_unit_of_work() as uow:
        repo = spi.create_action_repository(uow)
        repo.add(Action(urn))
        # A staged Action is visible to the same transaction before commit.
        assert repo.get(urn) == Action(urn)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        assert spi.create_action_repository(uow).get(urn) is None


def test_action_duplicate_urn_fails(spi: MtmfSpi) -> None:
    urn = BASELINE_ACTIONS[0]
    first = Action(urn)
    with spi.create_unit_of_work() as uow:
        repo = spi.create_action_repository(uow)
        repo.add(first)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repo.add(Action(urn))
        uow.commit()
    with spi.create_unit_of_work() as uow, pytest.raises(DuplicatePersistenceIdentityError):
        spi.create_action_repository(uow).add(Action(urn))


def test_action_exact_urn_is_the_canonical_identity(spi: MtmfSpi) -> None:
    urn = ActionUrn("urn:mtmf:iam:actions:system:tenant:set-active")
    with spi.create_unit_of_work() as uow:
        spi.create_action_repository(uow).add(Action(urn))
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_action_repository(uow).get(urn)
        assert stored is not None
        assert stored.urn.verb == "set"
        assert stored.urn.qualifier == "active"


def test_wildcard_action_remains_impossible(spi: MtmfSpi) -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-*")
    with pytest.raises(DomainInvariantError):
        Action(ActionUrn("urn:mtmf:iam:actions:system:principal:set-*"))
    with spi.create_unit_of_work() as uow:
        assert (
            spi.create_action_repository(uow).get(
                ActionUrn("urn:mtmf:iam:actions:system:principal:set-object")
            )
            is None
        )
