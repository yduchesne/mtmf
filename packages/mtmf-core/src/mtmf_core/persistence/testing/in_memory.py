"""Deterministic in-memory persistence provider for contract validation.

``InMemoryMtmfSpi`` is a test/internal provider, NOT a production
provider. It implements the :class:`~mtmf_core.persistence.spi.MtmfSpi`
contract with provider-owned committed state and UnitOfWork-local
transactional staging so that the PR 5 persistence contracts can be
proven deterministically before PostgreSQL mechanics are introduced.

Semantics:

- one provider instance owns one committed state; every UnitOfWork from
  the instance shares it;
- each UnitOfWork stages its writes locally: another active UnitOfWork
  never sees uncommitted state;
- commit merges the staged writes into committed state; rollback and
  uncommitted context exit discard them;
- entities are stored and returned as detached copies: no mutable
  reference is ever shared between the provider and a caller.
- immutable typed memberships are keyed by their relationship fact and
  returned as frozen value objects;
- duplicate immutable identities fail deterministically and mutable
  names are never identity.

No locks, MVCC, isolation levels, deadlocks, or serialization failures
are simulated. No PostgreSQL/SQL/driver/migration machinery is involved.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from enum import Enum
from types import TracebackType
from typing import ClassVar, Self, cast

from mtmf_core.domain.action import Action
from mtmf_core.domain.group import Group
from mtmf_core.domain.iam_urn import ActionUrn, RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.json_types import JsonObject, JsonValue
from mtmf_core.domain.memberships import (
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    PrincipalTenantMembership,
)
from mtmf_core.domain.organization import Organization
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    ForeignUnitOfWorkError,
    UnitOfWorkStateError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.repositories import (
    ActionRepository,
    GroupOrgMembershipRepository,
    GroupRepository,
    GroupTenantMembershipRepository,
    IdentityGroupMembershipRepository,
    IdentityOrgMembershipRepository,
    IdentityRepository,
    IdentityTenantMembershipRepository,
    OrganizationRepository,
    PrincipalRepository,
    PrincipalTenantMembershipRepository,
    RoleRepository,
    TenantRepository,
)
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = ["InMemoryMtmfSpi"]


class _UnitOfWorkState(Enum):
    """Internal lifecycle state of an in-memory UnitOfWork."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"


class _CommittedState:
    """Provider-owned durable state shared by all UnitOfWorks of one SPI."""

    def __init__(self) -> None:
        self._collections: dict[str, dict[object, object]] = {}

    def has(self, collection: str, key: object) -> bool:
        """Whether ``key`` is durable in ``collection``."""
        stored = self._collections.get(collection)
        return stored is not None and key in stored

    def get(self, collection: str, key: object) -> object | None:
        """Return the durable value for ``key``, or ``None``."""
        stored = self._collections.get(collection)
        if stored is None:
            return None
        return stored.get(key)

    def items(self, collection: str) -> tuple[tuple[object, object], ...]:
        """Return the durable key/value items of ``collection`` as a snapshot tuple."""
        stored = self._collections.get(collection)
        if stored is None:
            return ()
        return tuple(stored.items())

    def merge(self, collection: str, writes: dict[object, object]) -> None:
        """Merge one UnitOfWork's staged writes into this committed state."""
        target = self._collections.setdefault(collection, {})
        target.update(writes)


class _InMemoryUnitOfWork:
    """Concrete in-memory UnitOfWork implementing the contract."""

    def __init__(self, committed_state: _CommittedState) -> None:
        self._committed_state = committed_state
        self._staged: dict[str, dict[object, object]] = {}
        self._state: _UnitOfWorkState = _UnitOfWorkState.PENDING

    def _require_active(self, operation: str) -> None:
        """Fail unless this UnitOfWork currently hosts a transaction."""
        if self._state is not _UnitOfWorkState.ACTIVE:
            raise UnitOfWorkStateError(
                f"{operation} requires an active UnitOfWork; "
                f"current UnitOfWork state is {self._state.value}"
            )

    def _staged_for(self, collection: str) -> dict[object, object]:
        """The transaction-local write set for one collection (created on demand)."""
        staged = self._staged.get(collection)
        if staged is None:
            staged = {}
            self._staged[collection] = staged
        return staged

    def _discard(self) -> None:
        """Discard staged writes and complete the UnitOfWork."""
        self._staged.clear()
        self._state = _UnitOfWorkState.COMPLETED

    def __enter__(self) -> Self:
        """Establish the logical transaction; the UnitOfWork becomes active."""
        if self._state is not _UnitOfWorkState.PENDING:
            raise UnitOfWorkStateError(
                "UnitOfWork cannot be entered: it is not in its initial state "
                f"(current state is {self._state.value})"
            )
        self._state = _UnitOfWorkState.ACTIVE
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back any active transaction and never suppress an exception.

        A normal exit without an explicit commit rolls back (the
        lifecycle contract); an exceptional exit rolls back too. The
        original exception always propagates.
        """
        if self._state is _UnitOfWorkState.ACTIVE:
            self._discard()

    def commit(self) -> None:
        """Make every staged write durable and complete this UnitOfWork."""
        self._require_active("commit")
        for collection, staged in self._staged.items():
            self._committed_state.merge(collection, staged)
        self._discard()

    def rollback(self) -> None:
        """Discard every staged write and complete this UnitOfWork."""
        self._require_active("rollback")
        self._discard()


def _clone_json_value(value: JsonValue) -> JsonValue:
    """Return a structurally detached copy of one JSON value."""
    if isinstance(value, dict):
        return {key: _clone_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone_json_value(item) for item in value]
    return value


def _clone_extension(extension: JsonObject) -> JsonObject:
    """Return a structurally detached copy of an application extension object."""
    return {key: _clone_json_value(value) for key, value in extension.items()}


class _InMemoryEntityRepository[EntityT]:
    """Shared add/get/save mechanics for mutable aggregate roots.

    Staged writes are cloned on write and loaded values are cloned on
    read so that provider state never shares a mutable reference with a
    caller.

    ``add`` fails on an identity that already exists (committed or
    staged); ``save`` fails on an unknown identity; mutable names are
    never part of the identity key.
    """

    _collection: ClassVar[str]

    def __init__(self, uow: _InMemoryUnitOfWork) -> None:
        self._uow = uow

    def _require_active(self) -> None:
        self._uow._require_active(f"{type(self).__name__} operation")

    def _key(self, entity: EntityT) -> object:
        """Return the immutable persistence identity key of ``entity``."""
        raise NotImplementedError

    def _clone(self, entity: EntityT) -> EntityT:
        """Return a detached copy of ``entity``."""
        raise NotImplementedError

    def add(self, entity: EntityT) -> None:
        """Stage a new entity, rejecting an already-existing identity."""
        self._require_active()
        key = self._key(entity)
        staged = self._uow._staged_for(self._collection)
        if key in staged or self._uow._committed_state.has(self._collection, key):
            raise DuplicatePersistenceIdentityError(
                f"{self._collection}: identity {key!r} already exists"
            )
        staged[key] = self._clone(entity)

    def _get(self, key: object) -> EntityT | None:
        """Load the entity with ``key`` from the transactional view, if any."""
        self._require_active()
        staged = self._uow._staged_for(self._collection)
        if key in staged:
            return self._clone(cast(EntityT, staged[key]))
        committed = self._uow._committed_state.get(self._collection, key)
        if committed is not None:
            return self._clone(cast(EntityT, committed))
        return None

    def save(self, entity: EntityT) -> None:
        """Stage an update to an existing entity identity."""
        self._require_active()
        key = self._key(entity)
        staged = self._uow._staged_for(self._collection)
        if key not in staged and not self._uow._committed_state.has(self._collection, key):
            raise UnknownPersistenceIdentityError(
                f"{self._collection}: cannot save unknown identity {key!r}; "
                "introduce new identities with add"
            )
        staged[key] = self._clone(entity)


class _InMemoryTenantRepository(_InMemoryEntityRepository[Tenant]):
    """In-memory :class:`~mtmf_core.persistence.repositories.TenantRepository`."""

    _collection: ClassVar[str] = "Tenant"

    def get(self, id: DomainId) -> Tenant | None:
        """Return the Tenant with ``id`` from the transactional view, if any."""
        return self._get(id)

    def _key(self, entity: Tenant) -> object:
        return entity.id

    def _clone(self, entity: Tenant) -> Tenant:
        return replace(entity, extension=_clone_extension(entity.extension))


class _InMemoryOrganizationRepository(_InMemoryEntityRepository[Organization]):
    """In-memory :class:`~mtmf_core.persistence.repositories.OrganizationRepository`."""

    _collection: ClassVar[str] = "Organization"

    def get(self, id: DomainId) -> Organization | None:
        """Return the Organization with ``id`` from the transactional view, if any."""
        return self._get(id)

    def _key(self, entity: Organization) -> object:
        return entity.id

    def _clone(self, entity: Organization) -> Organization:
        return replace(entity, extension=_clone_extension(entity.extension))


class _InMemoryPrincipalRepository(_InMemoryEntityRepository[Principal]):
    """In-memory :class:`~mtmf_core.persistence.repositories.PrincipalRepository`."""

    _collection: ClassVar[str] = "Principal"

    def get(self, id: DomainId) -> Principal | None:
        """Return the Principal with ``id`` from the transactional view, if any."""
        return self._get(id)

    def _key(self, entity: Principal) -> object:
        return entity.id

    def _clone(self, entity: Principal) -> Principal:
        return replace(entity, extension=_clone_extension(entity.extension))


class _InMemoryIdentityRepository(_InMemoryEntityRepository[Identity]):
    """In-memory :class:`~mtmf_core.persistence.repositories.IdentityRepository`."""

    _collection: ClassVar[str] = "Identity"

    def get(self, id: DomainId) -> Identity | None:
        """Return the Identity with ``id`` from the transactional view, if any."""
        return self._get(id)

    def _key(self, entity: Identity) -> object:
        return entity.id

    def _clone(self, entity: Identity) -> Identity:
        return replace(entity, extension=_clone_extension(entity.extension))


class _InMemoryGroupRepository(_InMemoryEntityRepository[Group]):
    """In-memory :class:`~mtmf_core.persistence.repositories.GroupRepository`."""

    _collection: ClassVar[str] = "Group"

    def get(self, id: DomainId) -> Group | None:
        """Return the Group with ``id`` from the transactional view, if any."""
        return self._get(id)

    def _key(self, entity: Group) -> object:
        return entity.id

    def _clone(self, entity: Group) -> Group:
        return replace(entity, extension=_clone_extension(entity.extension))


class _InMemoryRoleRepository(_InMemoryEntityRepository[Role]):
    """In-memory :class:`~mtmf_core.persistence.repositories.RoleRepository`.

    The whole ``Role -> PermissionSet -> Permission`` aggregate is
    cloned and stored atomically under the Role's immutable URN.
    """

    _collection: ClassVar[str] = "Role"

    def get(self, urn: RoleUrn) -> Role | None:
        """Return the Role aggregate with canonical ``urn``, if any."""
        return self._get(urn)

    def _key(self, entity: Role) -> object:
        return entity.urn

    def _clone(self, entity: Role) -> Role:
        permission_sets = tuple(
            replace(
                permission_set,
                permissions=tuple(replace(permission) for permission in permission_set.permissions),
            )
            for permission_set in entity.permission_sets
        )
        return replace(
            entity,
            permission_sets=permission_sets,
            extension=_clone_extension(entity.extension),
        )


class _InMemoryActionRepository:
    """In-memory :class:`~mtmf_core.persistence.repositories.ActionRepository`.

    An Action is immutable and exclusively identified by its exact
    Action URN, so only ``add`` and ``get`` exist.
    """

    _collection: ClassVar[str] = "Action"

    def __init__(self, uow: _InMemoryUnitOfWork) -> None:
        self._uow = uow

    def add(self, action: Action) -> None:
        """Stage a new Action, rejecting one whose exact URN already exists."""
        self._uow._require_active("ActionRepository.add")
        staged = self._uow._staged_for(self._collection)
        if action.urn in staged or self._uow._committed_state.has(self._collection, action.urn):
            raise DuplicatePersistenceIdentityError(f"Action: URN {action.urn!r} already exists")
        staged[action.urn] = replace(action)

    def get(self, urn: ActionUrn) -> Action | None:
        """Return the Action with exact ``urn`` from the transactional view, if any."""
        self._uow._require_active("ActionRepository.get")
        staged = self._uow._staged_for(self._collection)
        if urn in staged:
            return cast(Action, staged[urn])
        committed = self._uow._committed_state.get(self._collection, urn)
        return cast(Action, committed) if committed is not None else None


class _InMemoryMembershipRepository[MembershipT]:
    """Shared add/get/find mechanics for immutable typed memberships.

    The membership fact itself is the persistence identity key: there is
    no surrogate ID and no polymorphic ``member_type``/``member_id``.
    Facts are frozen value objects, so they are stored and returned
    without duplication.
    """

    _collection: ClassVar[str]

    def __init__(self, uow: _InMemoryUnitOfWork) -> None:
        self._uow = uow

    def add(self, membership: MembershipT) -> None:
        """Stage a new membership fact, rejecting a duplicate relationship."""
        self._uow._require_active(f"{type(self).__name__}.add")
        staged = self._uow._staged_for(self._collection)
        if membership in staged or self._uow._committed_state.has(self._collection, membership):
            raise DuplicatePersistenceIdentityError(
                f"{self._collection}: membership {membership!r} already exists"
            )
        staged[membership] = membership

    def _get(self, key: MembershipT) -> MembershipT | None:
        """Return the exact membership fact from the transactional view, if any."""
        self._uow._require_active(f"{type(self).__name__}.get")
        staged = self._uow._staged_for(self._collection)
        if key in staged:
            return cast(MembershipT, staged[key])
        committed = self._uow._committed_state.get(self._collection, key)
        return cast(MembershipT, committed) if committed is not None else None

    def _find(self, predicate: Callable[[MembershipT], bool]) -> tuple[MembershipT, ...]:
        """Return every membership fact matching ``predicate``.

        The transactional view combines durable facts with facts staged
        by the current UnitOfWork, so callers read their own staged
        writes without an intervening commit.
        """
        self._uow._require_active(f"{type(self).__name__} query")
        committed = self._uow._committed_state.items(self._collection)
        matches = [
            cast(MembershipT, value)
            for value, _ in committed
            if predicate(cast(MembershipT, value))
        ]
        for value in self._uow._staged_for(self._collection).values():
            item = cast(MembershipT, value)
            if predicate(item):
                matches.append(item)
        return tuple(matches)


class _InMemoryPrincipalTenantMembershipRepository(
    _InMemoryMembershipRepository[PrincipalTenantMembership]
):
    """In-memory Principal-Tenant membership repository."""

    _collection: ClassVar[str] = "PrincipalTenantMembership"

    def get(self, principal_id: DomainId, tenant_id: DomainId) -> PrincipalTenantMembership | None:
        """Return the exact Principal-Tenant membership fact, if any."""
        return self._get(PrincipalTenantMembership(principal_id, tenant_id))

    def find_by_principal(self, principal_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every membership fact of one Principal."""
        return self._find(lambda membership: membership.principal_id == principal_id)

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every Principal membership fact in one Tenant."""
        return self._find(lambda membership: membership.tenant_id == tenant_id)


class _InMemoryIdentityTenantMembershipRepository(
    _InMemoryMembershipRepository[IdentityTenantMembership]
):
    """In-memory Identity-Tenant membership repository."""

    _collection: ClassVar[str] = "IdentityTenantMembership"

    def get(self, identity_id: DomainId, tenant_id: DomainId) -> IdentityTenantMembership | None:
        """Return the exact Identity-Tenant membership fact, if any."""
        return self._get(IdentityTenantMembership(identity_id, tenant_id))

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every membership fact of one Identity."""
        return self._find(lambda membership: membership.identity_id == identity_id)

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every Identity membership fact in one Tenant."""
        return self._find(lambda membership: membership.tenant_id == tenant_id)


class _InMemoryGroupTenantMembershipRepository(
    _InMemoryMembershipRepository[GroupTenantMembership]
):
    """In-memory Group-Tenant membership repository."""

    _collection: ClassVar[str] = "GroupTenantMembership"

    def get(self, group_id: DomainId, tenant_id: DomainId) -> GroupTenantMembership | None:
        """Return the exact Group-Tenant membership fact, if any."""
        return self._get(GroupTenantMembership(group_id, tenant_id))

    def find_by_group(self, group_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every membership fact of one Group."""
        return self._find(lambda membership: membership.group_id == group_id)

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every Group membership fact in one Tenant."""
        return self._find(lambda membership: membership.tenant_id == tenant_id)


class _InMemoryIdentityGroupMembershipRepository(
    _InMemoryMembershipRepository[IdentityGroupMembership]
):
    """In-memory Identity-Group membership repository."""

    _collection: ClassVar[str] = "IdentityGroupMembership"

    def get(self, identity_id: DomainId, group_id: DomainId) -> IdentityGroupMembership | None:
        """Return the exact Identity-Group membership fact, if any."""
        return self._get(IdentityGroupMembership(identity_id, group_id))

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every membership fact of one Identity."""
        return self._find(lambda membership: membership.identity_id == identity_id)

    def find_by_group(self, group_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every Identity membership fact of one Group."""
        return self._find(lambda membership: membership.group_id == group_id)


class _InMemoryIdentityOrgMembershipRepository(
    _InMemoryMembershipRepository[IdentityOrgMembership]
):
    """In-memory Identity-Organization membership repository."""

    _collection: ClassVar[str] = "IdentityOrgMembership"

    def get(self, identity_id: DomainId, organization_id: DomainId) -> IdentityOrgMembership | None:
        """Return the exact Identity-Organization membership fact, if any."""
        return self._get(IdentityOrgMembership(identity_id, organization_id))

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every membership fact of one Identity."""
        return self._find(lambda membership: membership.identity_id == identity_id)

    def find_by_organization(self, organization_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every Identity membership fact of one Organization."""
        return self._find(lambda membership: membership.organization_id == organization_id)


class _InMemoryGroupOrgMembershipRepository(_InMemoryMembershipRepository[GroupOrgMembership]):
    """In-memory Group-Organization membership repository."""

    _collection: ClassVar[str] = "GroupOrgMembership"

    def get(self, group_id: DomainId, organization_id: DomainId) -> GroupOrgMembership | None:
        """Return the exact Group-Organization membership fact, if any."""
        return self._get(GroupOrgMembership(group_id, organization_id))

    def find_by_group(self, group_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every membership fact of one Group."""
        return self._find(lambda membership: membership.group_id == group_id)

    def find_by_organization(self, organization_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every Group membership fact of one Organization."""
        return self._find(lambda membership: membership.organization_id == organization_id)


class InMemoryMtmfSpi:
    """Deterministic in-memory :class:`~mtmf_core.persistence.spi.MtmfSpi`.

    This provider exists to validate the persistence contracts and to
    serve deterministic unit tests. It is clearly test/internal state
    and must not be used as a production persistence provider.

    Repository factories accept only UnitOfWork objects created by this
    provider instance; any foreign UnitOfWork is rejected determinically
    with :class:`~mtmf_core.persistence.errors.ForeignUnitOfWorkError`.
    """

    def __init__(self) -> None:
        self._committed_state = _CommittedState()

    def create_unit_of_work(self) -> UnitOfWork:
        """Create an independent UnitOfWork sharing this provider's committed state."""
        return _InMemoryUnitOfWork(self._committed_state)

    def _require_own_uow(self, uow: UnitOfWork) -> _InMemoryUnitOfWork:
        """Return ``uow`` after rejecting UnitOfWorks from another provider."""
        if (
            not isinstance(uow, _InMemoryUnitOfWork)
            or uow._committed_state is not self._committed_state
        ):
            raise ForeignUnitOfWorkError(
                "repository factories accept only UnitOfWork objects created by this "
                "persistence provider instance"
            )
        return uow

    def create_tenant_repository(self, uow: UnitOfWork) -> TenantRepository:
        """Create a Tenant repository bound to ``uow``."""
        return _InMemoryTenantRepository(self._require_own_uow(uow))

    def create_organization_repository(self, uow: UnitOfWork) -> OrganizationRepository:
        """Create an Organization repository bound to ``uow``."""
        return _InMemoryOrganizationRepository(self._require_own_uow(uow))

    def create_principal_repository(self, uow: UnitOfWork) -> PrincipalRepository:
        """Create a Principal repository bound to ``uow``."""
        return _InMemoryPrincipalRepository(self._require_own_uow(uow))

    def create_identity_repository(self, uow: UnitOfWork) -> IdentityRepository:
        """Create an Identity repository bound to ``uow``."""
        return _InMemoryIdentityRepository(self._require_own_uow(uow))

    def create_group_repository(self, uow: UnitOfWork) -> GroupRepository:
        """Create a Group repository bound to ``uow``."""
        return _InMemoryGroupRepository(self._require_own_uow(uow))

    def create_role_repository(self, uow: UnitOfWork) -> RoleRepository:
        """Create a Role aggregate repository bound to ``uow``."""
        return _InMemoryRoleRepository(self._require_own_uow(uow))

    def create_action_repository(self, uow: UnitOfWork) -> ActionRepository:
        """Create an Action repository bound to ``uow``."""
        return _InMemoryActionRepository(self._require_own_uow(uow))

    def create_principal_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> PrincipalTenantMembershipRepository:
        """Create a Principal-Tenant membership repository bound to ``uow``."""
        return _InMemoryPrincipalTenantMembershipRepository(self._require_own_uow(uow))

    def create_identity_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityTenantMembershipRepository:
        """Create an Identity-Tenant membership repository bound to ``uow``."""
        return _InMemoryIdentityTenantMembershipRepository(self._require_own_uow(uow))

    def create_group_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupTenantMembershipRepository:
        """Create a Group-Tenant membership repository bound to ``uow``."""
        return _InMemoryGroupTenantMembershipRepository(self._require_own_uow(uow))

    def create_identity_group_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityGroupMembershipRepository:
        """Create an Identity-Group membership repository bound to ``uow``."""
        return _InMemoryIdentityGroupMembershipRepository(self._require_own_uow(uow))

    def create_identity_org_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityOrgMembershipRepository:
        """Create an Identity-Organization membership repository bound to ``uow``."""
        return _InMemoryIdentityOrgMembershipRepository(self._require_own_uow(uow))

    def create_group_org_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupOrgMembershipRepository:
        """Create a Group-Organization membership repository bound to ``uow``."""
        return _InMemoryGroupOrgMembershipRepository(self._require_own_uow(uow))
