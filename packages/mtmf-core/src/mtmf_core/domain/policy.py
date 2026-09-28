"""Policy-definition value types shared by the policy domain.

:class:`PermissionEffect` carries exactly the ALLOW/DENY semantics of
the security model. :class:`DefinitionNamespace` describes Role
definition ownership and is deliberately distinct from the separate
:class:`~mtmf_core.domain.scope.SecurityScope` concept: a Role never
carries a security Scope.
"""

from __future__ import annotations

from enum import Enum


class PermissionEffect(Enum):
    """The effect carried by one PermissionSet.

    Exactly :attr:`ALLOW` and :attr:`DENY` exist. There is no
    ABSTAIN/UNKNOWN state. The values are strings rather than integers
    so that no authorization precedence can be derived from a numeric
    encoding; ordering and conflict resolution are explicit evaluation
    rules owned by later PRs.
    """

    ALLOW = "allow"
    DENY = "deny"


class DefinitionNamespace(Enum):
    """Whether a Role is defined by MTMF globally or by one Tenant.

    This is a Role-definition ownership concept. It must never be
    confused with :class:`~mtmf_core.domain.scope.SecurityScope`: Roles
    have no security Scope, and definition ownership is not a privilege
    hierarchy.
    """

    SYSTEM = "system"
    TENANT = "tenant"
