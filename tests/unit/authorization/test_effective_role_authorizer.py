"""End-to-end effective-Role -> Authorizer tests (plan matrix R14-R18, R20).

These tests wire the application-layer :class:`EffectiveRoleResolver` to
the existing authoritative :class:`Authorizer` through the trusted
:func:`build_authorization_context` factory. They prove that persisted
assignment state produces the documented default-deny, specificity, and
equal-specificity DENY behavior and that infrastructure/integrity
failures fail closed without becoming a policy decision.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from authz_helpers import make_action, make_permission_set_with_rules, make_role_from_sets
from helpers import make_id, make_identity, make_principal, make_role_urn, make_tenant

from mtmf_core import (
    AuthorizationRequest,
    Authorizer,
    DenyReason,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    InMemoryMtmfSpi,
    PermissionEffect,
    PrincipalTenantMembership,
    SessionContext,
    UnsupportedConstraint,
)
from mtmf_core.application import (
    EffectiveRoleIntegrityError,
    EffectiveRoleResolver,
    build_authorization_context,
)
from mtmf_core.persistence.errors import PersistenceConnectionError


def _role_with_rule(*, effect: PermissionEffect, verb: str, qualifier: str, name: str):
    """Build a single-rule Role whose owned PermissionSet matches its URN."""
    role_urn = make_role_urn(role_name=name.lower().replace(" ", "-"))
    permission_set = make_permission_set_with_rules(
        role_urn=role_urn, effect=effect, rules=((verb, qualifier),)
    )
    return make_role_from_sets(role_urn=role_urn, permission_sets=(permission_set,), role_name=name)


@dataclass
class _AuthGraph:
    spi: InMemoryMtmfSpi
    tenant_id: object
    principal_id: object
    identity_id: object


def _seed() -> _AuthGraph:
    spi = InMemoryMtmfSpi()
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(principal.id, tenant.id)
        )
        spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(identity.id, tenant.id)
        )
        uow.commit()
    return _AuthGraph(spi, tenant.id, principal.id, identity.id)


def _store_role(graph: _AuthGraph, role) -> None:
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_role_repository(uow).add(role)
        uow.commit()


def _assign(graph: _AuthGraph, role_urn) -> None:
    assignment = IdentityRoleAssignment(
        make_id(),
        graph.tenant_id,
        graph.identity_id,
        role_urn,  # type: ignore[arg-type]
    )
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_identity_role_assignment_repository(uow).add(assignment)
        uow.commit()


def _authorize(
    graph: _AuthGraph,
    action,
    *,
    unsupported_constraints=(),
    resolver: EffectiveRoleResolver | None = None,
) -> object:
    resolver = resolver if resolver is not None else EffectiveRoleResolver(graph.spi)
    session = SessionContext(graph.tenant_id, graph.principal_id, graph.identity_id)  # type: ignore[arg-type]
    with graph.spi.create_unit_of_work() as uow:
        state = resolver.resolve(uow, session=session, target_tenant_id=graph.tenant_id)  # type: ignore[arg-type]
    context = build_authorization_context(state)
    request = AuthorizationRequest(
        context,
        action,
        graph.tenant_id,  # type: ignore[arg-type]
        unsupported_constraints=unsupported_constraints,
    )
    return Authorizer().authorize(request)


def test_r14_exact_deny_beats_wildcard_allow_through_persisted_roles() -> None:
    graph = _seed()
    allow_role = _role_with_rule(
        effect=PermissionEffect.ALLOW, verb="get", qualifier="*", name="Wildcard Allow"
    )
    deny_role = _role_with_rule(
        effect=PermissionEffect.DENY, verb="get", qualifier="object", name="Exact Deny"
    )
    _store_role(graph, allow_role)
    _store_role(graph, deny_role)
    _assign(graph, allow_role.urn)
    _assign(graph, deny_role.urn)
    decision = _authorize(graph, make_action())
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_r15_equal_specificity_allow_and_deny_is_deny() -> None:
    graph = _seed()
    allow_role = _role_with_rule(
        effect=PermissionEffect.ALLOW, verb="get", qualifier="object", name="Exact Allow"
    )
    deny_role = _role_with_rule(
        effect=PermissionEffect.DENY, verb="get", qualifier="object", name="Exact Deny"
    )
    _store_role(graph, allow_role)
    _store_role(graph, deny_role)
    _assign(graph, allow_role.urn)
    _assign(graph, deny_role.urn)
    decision = _authorize(graph, make_action())
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_r16_no_applicable_role_is_deny() -> None:
    graph = _seed()
    decision = _authorize(graph, make_action())
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_r16b_effective_allow_role_is_allow() -> None:
    graph = _seed()
    allow_role = _role_with_rule(
        effect=PermissionEffect.ALLOW, verb="get", qualifier="object", name="Exact Allow"
    )
    _store_role(graph, allow_role)
    _assign(graph, allow_role.urn)
    decision = _authorize(graph, make_action())
    assert decision.allowed


class _ExplodingSpi:
    """A provider whose very first read fails as an infrastructure error."""

    def create_unit_of_work(self) -> object:
        return object()

    def create_tenant_repository(self, uow: object) -> object:
        raise PersistenceConnectionError("simulated database outage")


def test_r17_database_outage_during_resolution_fails_closed_as_an_error() -> None:
    resolver = EffectiveRoleResolver(_ExplodingSpi())  # type: ignore[arg-type]
    session = SessionContext(make_id(), make_id(), make_id())
    with pytest.raises(PersistenceConnectionError):
        resolver.resolve(object(), session=session, target_tenant_id=session.tenant_id)  # type: ignore[arg-type]


def test_r18_unknown_role_in_assignment_is_an_integrity_error() -> None:
    graph = _seed()
    _assign(graph, make_role_urn(role_name="never-stored"))
    resolver = EffectiveRoleResolver(graph.spi)
    session = SessionContext(graph.tenant_id, graph.principal_id, graph.identity_id)  # type: ignore[arg-type]
    with (
        graph.spi.create_unit_of_work() as uow,
        pytest.raises(EffectiveRoleIntegrityError),
    ):
        resolver.resolve(uow, session=session, target_tenant_id=graph.tenant_id)  # type: ignore[arg-type]


def test_r20_unsupported_constraint_remains_fail_closed() -> None:
    graph = _seed()
    allow_role = _role_with_rule(
        effect=PermissionEffect.ALLOW, verb="get", qualifier="object", name="Exact Allow"
    )
    _store_role(graph, allow_role)
    _assign(graph, allow_role.urn)
    decision = _authorize(
        graph,
        make_action(),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.UNSUPPORTED_CONSTRAINT
