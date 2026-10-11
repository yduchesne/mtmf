"""Unit tests for PostgreSQL repositories using a scripted UnitOfWork.

The scripted UnitOfWork records the exact reviewed function call and
returns deterministic rows, so repository control flow (duplicate
detection, unknown-identity detection, payload mapping, and find
directions) is exercised without a database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from helpers import make_identity, make_organization, make_principal, make_role, make_tenant

from mtmf_core import (
    Action,
    ActionUrn,
    Application,
    ApplicationTenantRegistration,
    DomainId,
    Group,
    GroupOrgMembership,
    GroupTenantMembership,
    Identity,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    Organization,
    Principal,
    PrincipalTenantMembership,
    RegistrationLifecycle,
    RoleUrn,
    SubscriptionLifecycle,
    Tenant,
    TenantApplicationSubscription,
)
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.postgres import repositories as repo_module
from mtmf_core.persistence.postgres.mapping import role_to_payload


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _ScriptedUnitOfWork:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self._rows_for: list[tuple[str, list[tuple[Any, ...]]]] = []

    def set(self, substring: str, rows: list[tuple[Any, ...]]) -> _ScriptedUnitOfWork:
        self._rows_for.append((substring, rows))
        return self

    def _execute(self, query: str, params: tuple[object, ...]) -> _FakeCursor:
        self.calls.append((query, params))
        for substring, rows in self._rows_for:
            if substring in query:
                return _FakeCursor(rows)
        return _FakeCursor([(True,)])


def _uow() -> Any:
    return _ScriptedUnitOfWork()


def _tenant_payload(tenant: Tenant) -> dict[str, object]:
    return {
        "id": str(tenant.id),
        "name": tenant.name,
        "scope": int(tenant.scope),
        "owner_identity_id": str(tenant.owner_identity_id),
        "lifecycle": int(tenant.lifecycle),
        "deletion_status": int(tenant.deletion_status),
        "extension": tenant.extension,
    }


def _organization_payload(organization: Organization) -> dict[str, object]:
    return {
        "id": str(organization.id),
        "tenant_id": str(organization.tenant_id),
        "name": organization.name,
        "owner_identity_id": str(organization.owner_identity_id),
        "deletion_status": int(organization.deletion_status),
        "extension": organization.extension,
    }


def _principal_payload(principal: Principal) -> dict[str, object]:
    return {
        "id": str(principal.id),
        "name": principal.name,
        "deletion_status": int(principal.deletion_status),
        "extension": principal.extension,
    }


def _identity_payload(identity: Identity) -> dict[str, object]:
    return {
        "id": str(identity.id),
        "principal_id": str(identity.principal_id),
        "name": identity.name,
        "origin": int(identity.origin),
        "deletion_status": int(identity.deletion_status),
        "extension": identity.extension,
    }


def _group_payload(group: Group) -> dict[str, object]:
    return {
        "id": str(group.id),
        "tenant_id": str(group.tenant_id),
        "name": group.name,
        "deletion_status": int(group.deletion_status),
        "extension": group.extension,
    }


def test_tenant_repository_lifecycle() -> None:
    uow = _uow()
    repository = repo_module.PostgresTenantRepository(uow)
    tenant = make_tenant()
    repository.add(tenant)
    assert "mtmf.tenant_add" in uow.calls[0][0]

    duplicate = _ScriptedUnitOfWork().set("tenant_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresTenantRepository(duplicate).add(tenant)

    uow = _ScriptedUnitOfWork().set("tenant_get", [(_tenant_payload(tenant),)])
    assert repo_module.PostgresTenantRepository(uow).get(tenant.id) == tenant

    uow = _ScriptedUnitOfWork().set("tenant_get", [])
    assert repo_module.PostgresTenantRepository(uow).get(tenant.id) is None

    uow = _uow()
    repo_module.PostgresTenantRepository(uow).save(tenant)
    assert "mtmf.tenant_save" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("tenant_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresTenantRepository(uow).save(tenant)


def test_organization_repository_lifecycle() -> None:
    organization = make_organization()
    uow = _uow()
    repo_module.PostgresOrganizationRepository(uow).add(organization)
    assert "mtmf.organization_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("organization_get", [(_organization_payload(organization),)])
    assert repo_module.PostgresOrganizationRepository(uow).get(organization.id) == organization

    uow = _ScriptedUnitOfWork().set("organization_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresOrganizationRepository(uow).add(organization)

    uow = _ScriptedUnitOfWork().set("organization_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresOrganizationRepository(uow).save(organization)


def test_principal_repository_lifecycle() -> None:
    principal = make_principal()
    uow = _uow()
    repo_module.PostgresPrincipalRepository(uow).add(principal)
    assert "mtmf.principal_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("principal_get", [(_principal_payload(principal),)])
    assert repo_module.PostgresPrincipalRepository(uow).get(principal.id) == principal

    uow = _ScriptedUnitOfWork().set("principal_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresPrincipalRepository(uow).add(principal)

    uow = _ScriptedUnitOfWork().set("principal_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresPrincipalRepository(uow).save(principal)


def test_identity_repository_lifecycle() -> None:
    identity = make_identity()
    uow = _uow()
    repo_module.PostgresIdentityRepository(uow).add(identity)
    assert "mtmf.identity_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("identity_get", [(_identity_payload(identity),)])
    assert repo_module.PostgresIdentityRepository(uow).get(identity.id) == identity

    uow = _ScriptedUnitOfWork().set("identity_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresIdentityRepository(uow).add(identity)

    uow = _ScriptedUnitOfWork().set("identity_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresIdentityRepository(uow).save(identity)


def test_group_repository_lifecycle() -> None:
    group = Group(DomainId.generate(), DomainId.generate(), "G")
    uow = _uow()
    repo_module.PostgresGroupRepository(uow).add(group)
    assert "mtmf.group_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("group_get", [(_group_payload(group),)])
    assert repo_module.PostgresGroupRepository(uow).get(group.id) == group

    uow = _ScriptedUnitOfWork().set("group_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresGroupRepository(uow).add(group)

    uow = _ScriptedUnitOfWork().set("group_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresGroupRepository(uow).save(group)


def test_group_repository_empty_get() -> None:
    uow = _ScriptedUnitOfWork().set("group_get", [])
    assert repo_module.PostgresGroupRepository(uow).get(DomainId.generate()) is None


def test_organization_and_identity_and_principal_empty_get() -> None:
    for name, repository_type in (
        ("organization_get", repo_module.PostgresOrganizationRepository),
        ("identity_get", repo_module.PostgresIdentityRepository),
        ("principal_get", repo_module.PostgresPrincipalRepository),
    ):
        uow = _ScriptedUnitOfWork().set(name, [])
        assert repository_type(uow).get(DomainId.generate()) is None


def test_role_repository_lifecycle() -> None:
    role = make_role()
    payload = role_to_payload(role)
    uow = _uow()
    repo_module.PostgresRoleRepository(uow).add(role)
    assert "mtmf.role_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("role_get", [(payload,)])
    assert repo_module.PostgresRoleRepository(uow).get(role.urn) == role

    uow = _ScriptedUnitOfWork().set("role_get", [])
    assert repo_module.PostgresRoleRepository(uow).get(role.urn) is None

    uow = _uow()
    repo_module.PostgresRoleRepository(uow).save(role)
    assert "mtmf.role_save" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("role_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresRoleRepository(uow).add(role)

    uow = _ScriptedUnitOfWork().set("role_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresRoleRepository(uow).save(role)


def test_action_repository_lifecycle() -> None:
    urn = ActionUrn("urn:mtmf:iam:actions:system:principal:get-object")
    uow = _ScriptedUnitOfWork().set("action_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresActionRepository(uow).add(Action(urn))

    uow = _ScriptedUnitOfWork().set("action_get", [(True,)])
    assert repo_module.PostgresActionRepository(uow).get(urn) == Action(urn)

    uow = _ScriptedUnitOfWork().set("action_get", [(False,)])
    assert repo_module.PostgresActionRepository(uow).get(urn) is None


def test_membership_repositories_add_get_and_find() -> None:
    first = DomainId.generate()
    second = DomainId.generate()
    other = DomainId.generate()

    cases = (
        (
            repo_module.PostgresPrincipalTenantMembershipRepository,
            PrincipalTenantMembership(first, second),
            "principal_tenant_membership",
            "find_by_principal",
            "find_by_tenant",
        ),
        (
            repo_module.PostgresIdentityTenantMembershipRepository,
            IdentityTenantMembership(first, second),
            "identity_tenant_membership",
            "find_by_identity",
            "find_by_tenant",
        ),
        (
            repo_module.PostgresGroupTenantMembershipRepository,
            GroupTenantMembership(first, second),
            "group_tenant_membership",
            "find_by_group",
            "find_by_tenant",
        ),
        (
            repo_module.PostgresIdentityGroupMembershipRepository,
            IdentityGroupMembership(first, second),
            "identity_group_membership",
            "find_by_identity",
            "find_by_group",
        ),
        (
            repo_module.PostgresIdentityOrgMembershipRepository,
            IdentityOrgMembership(first, second),
            "identity_org_membership",
            "find_by_identity",
            "find_by_organization",
        ),
        (
            repo_module.PostgresGroupOrgMembershipRepository,
            GroupOrgMembership(first, second),
            "group_org_membership",
            "find_by_group",
            "find_by_organization",
        ),
    )
    for repository_type, membership, prefix, first_find, second_find in cases:
        uow = _uow()
        repository_type(uow).add(membership)
        assert f"mtmf.{prefix}_add" in uow.calls[0][0]

        uow = _ScriptedUnitOfWork().set(f"{prefix}_get", [(False,)])
        assert repository_type(uow).get(first, second) is None

        uow = _ScriptedUnitOfWork().set(f"{prefix}_get", [(True,)])
        assert repository_type(uow).get(first, second) == membership

        uow = _ScriptedUnitOfWork().set(f"{prefix}_add", [(False,)])
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository_type(uow).add(membership)

        uow = _ScriptedUnitOfWork().set(first_find, [(second.value,), (other.value,)])
        first_expected = (type(membership)(first, second), type(membership)(first, other))
        assert getattr(repository_type(uow), first_find)(first) == first_expected

        uow = _ScriptedUnitOfWork().set(second_find, [(first.value,)])
        assert getattr(repository_type(uow), second_find)(second) == (membership,)


def test_role_repository_uses_the_canonical_role_urn() -> None:
    role = make_role(urn=RoleUrn("urn:mtmf:iam:roles:system:canonical"))
    uow = _uow()
    repo_module.PostgresRoleRepository(uow).add(role)
    query, params = uow.calls[0]
    assert query == "SELECT mtmf.role_add(%s)"
    assert len(params) == 1


_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _application_payload(application: Application) -> dict[str, object]:
    return {
        "id": str(application.id),
        "application_key": application.application_key,
        "name": application.name,
        "owner_identity_id": str(application.owner_identity_id),
        "lifecycle": int(application.lifecycle),
        "extension": application.extension,
    }


def _registration_payload(registration: ApplicationTenantRegistration) -> dict[str, object]:
    return {
        "id": str(registration.id),
        "application_id": str(registration.application_id),
        "tenant_id": str(registration.tenant_id),
        "created_by_identity_id": str(registration.created_by_identity_id),
        "lifecycle": int(registration.lifecycle),
        "created_at": registration.created_at.isoformat(),
    }


def _subscription_payload(subscription: TenantApplicationSubscription) -> dict[str, object]:
    return {
        "id": str(subscription.id),
        "application_id": str(subscription.application_id),
        "tenant_id": str(subscription.tenant_id),
        "created_by_identity_id": str(subscription.created_by_identity_id),
        "lifecycle": int(subscription.lifecycle),
        "starts_at": subscription.starts_at.isoformat(),
        "ends_at": None if subscription.ends_at is None else subscription.ends_at.isoformat(),
        "created_at": subscription.created_at.isoformat(),
    }


def test_application_repository_lifecycle() -> None:
    application = Application(DomainId.generate(), "ati-client", "ATI Client", DomainId.generate())
    uow = _uow()
    repo_module.PostgresApplicationRepository(uow).add(application)
    assert "mtmf.application_add" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("application_get", [(_application_payload(application),)])
    assert repo_module.PostgresApplicationRepository(uow).get(application.id) == application

    uow = _ScriptedUnitOfWork().set(
        "application_get_by_key", [(_application_payload(application),)]
    )
    assert repo_module.PostgresApplicationRepository(uow).get_by_key("ATI-Client") == application

    uow = _ScriptedUnitOfWork()
    repo_module.PostgresApplicationRepository(uow).save(application)
    assert "mtmf.application_save" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("application_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresApplicationRepository(uow).add(application)

    uow = _ScriptedUnitOfWork().set("application_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresApplicationRepository(uow).save(application)


def test_application_registration_repository_lifecycle() -> None:
    registration = ApplicationTenantRegistration(
        DomainId.generate(),
        DomainId.generate(),
        DomainId.generate(),
        DomainId.generate(),
        _NOW,
        RegistrationLifecycle.ACTIVE,
    )
    uow = _uow()
    repo_module.PostgresApplicationTenantRegistrationRepository(uow).add(registration)
    assert "mtmf.application_tenant_registration_add" in uow.calls[0][0]

    payload = (_registration_payload(registration),)
    uow = _ScriptedUnitOfWork().set("application_tenant_registration_get", [payload])
    assert (
        repo_module.PostgresApplicationTenantRegistrationRepository(uow).get(registration.id)
        == registration
    )

    uow = _ScriptedUnitOfWork().set(
        "application_tenant_registration_find_by_application_and_tenant", [payload]
    )
    assert repo_module.PostgresApplicationTenantRegistrationRepository(
        uow
    ).find_by_application_and_tenant(registration.application_id, registration.tenant_id) == (
        registration,
    )

    uow = _ScriptedUnitOfWork().set("application_tenant_registration_find_by_tenant", [payload])
    assert repo_module.PostgresApplicationTenantRegistrationRepository(uow).find_by_tenant(
        registration.tenant_id
    ) == (registration,)

    uow = _uow()
    repo_module.PostgresApplicationTenantRegistrationRepository(uow).save(registration)
    assert "mtmf.application_tenant_registration_save" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("application_tenant_registration_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresApplicationTenantRegistrationRepository(uow).add(registration)

    uow = _ScriptedUnitOfWork().set("application_tenant_registration_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresApplicationTenantRegistrationRepository(uow).save(registration)


def test_tenant_application_subscription_repository_lifecycle() -> None:
    subscription = TenantApplicationSubscription(
        DomainId.generate(),
        DomainId.generate(),
        DomainId.generate(),
        DomainId.generate(),
        _NOW,
        _NOW,
        None,
        SubscriptionLifecycle.ACTIVE,
    )
    uow = _uow()
    repo_module.PostgresTenantApplicationSubscriptionRepository(uow).add(subscription)
    assert "mtmf.tenant_application_subscription_add" in uow.calls[0][0]

    payload = (_subscription_payload(subscription),)
    uow = _ScriptedUnitOfWork().set("tenant_application_subscription_get", [payload])
    assert (
        repo_module.PostgresTenantApplicationSubscriptionRepository(uow).get(subscription.id)
        == subscription
    )

    uow = _ScriptedUnitOfWork().set(
        "tenant_application_subscription_find_by_application_and_tenant", [payload]
    )
    assert repo_module.PostgresTenantApplicationSubscriptionRepository(
        uow
    ).find_by_application_and_tenant(subscription.application_id, subscription.tenant_id) == (
        subscription,
    )

    uow = _ScriptedUnitOfWork().set("tenant_application_subscription_find_by_tenant", [payload])
    assert repo_module.PostgresTenantApplicationSubscriptionRepository(uow).find_by_tenant(
        subscription.tenant_id
    ) == (subscription,)

    uow = _uow()
    repo_module.PostgresTenantApplicationSubscriptionRepository(uow).save(subscription)
    assert "mtmf.tenant_application_subscription_save" in uow.calls[0][0]

    uow = _ScriptedUnitOfWork().set("tenant_application_subscription_add", [(False,)])
    with pytest.raises(DuplicatePersistenceIdentityError):
        repo_module.PostgresTenantApplicationSubscriptionRepository(uow).add(subscription)

    uow = _ScriptedUnitOfWork().set("tenant_application_subscription_save", [(False,)])
    with pytest.raises(UnknownPersistenceIdentityError):
        repo_module.PostgresTenantApplicationSubscriptionRepository(uow).save(subscription)
