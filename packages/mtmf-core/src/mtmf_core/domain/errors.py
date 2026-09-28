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
