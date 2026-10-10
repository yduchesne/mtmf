"""Narrow core-domain invariant error hierarchy.

These errors represent deterministic violations of documented domain
invariants. They are deliberately a small internal hierarchy: the future
public ``mtmf-api`` error contract, transport encoding, and HTTP mapping
are separate concerns owned by later PRs.
"""

from __future__ import annotations


class DomainInvariantError(ValueError):
    """Base class for deterministic core-domain invariant violations."""


class TenantBoundaryError(DomainInvariantError):
    """A relationship would cross or misplace a Tenant boundary."""


class MembershipPrerequisiteError(DomainInvariantError):
    """A membership lacks a required explicit prerequisite relationship.

    Prerequisites are never inferred and never auto-created: a missing
    prerequisite is rejected.
    """


class SessionContextError(DomainInvariantError):
    """A session context is structurally inconsistent."""


class ImmutabilityError(DomainInvariantError):
    """An attempt to replace an immutable identity/provenance field."""


class RootInvariantError(DomainInvariantError):
    """A root bootstrap/continuity invariant is violated.

    Raised only by the structural root-bootstrap validators. It does not
    represent authentication, authorization, or a privileged decision.
    """


class StewardshipInvariantError(DomainInvariantError):
    """A structural Tenant-stewardship designation invariant is violated.

    Raised only by the structural stewardship validators. Possessing or
    passing such a designation confers no Role, Permission, or authority.
    """


class TenantLifecycleError(DomainInvariantError):
    """An ordinary-Tenant lifecycle state or transition is invalid (PR 10).

    Raised by the pure lifecycle validators. This is structural validation
    only; it does not authenticate an operator or authorize an activation.
    """


class ManagementGroupInvariantError(DomainInvariantError):
    """A structural TenantManagementGroup invariant is violated (PR 11).

    Raised only by the pure structural TenantManagementGroup validators.
    Possessing or passing a management group confers no Role, Permission,
    scope elevation, or authority; delegated manager-side actor eligibility
    remains unresolved until the PR 11 decision gate is approved.
    """
