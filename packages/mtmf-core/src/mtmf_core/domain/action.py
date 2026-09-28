"""Action: the shared exact operation definition.

An Action is the exact operation requested against a resource. It is
not a Permission: callers request Actions, while owned Permissions are
matcher rules used to decide whether an Action is authorized.

The canonical identity of an Action is its immutable, exact Action URN.
A wildcard can never appear in an Action URN.

``BASELINE_ACTIONS`` lists the documented baseline example Actions as a
foundation for tests and consumers. It is explicitly NOT an exhaustive
Action catalog: the complete catalog remains unresolved by the security
model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.domain.mixins import ImmutableFieldGuard


@dataclass(slots=True)
class Action(ImmutableFieldGuard):
    """A shared exact operation definition.

    The immutable :attr:`urn` is the sole state: an Action carries no
    effect, no Role/PermissionSet ownership, no assignment context, no
    resource-instance target, no security scope, and no decision state.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"urn"})

    urn: ActionUrn


# Baseline example Actions from SECURITY_MODEL.md section 15.2. These
# are shared exact SYSTEM-namespace Actions used as a foundation; the
# complete Action catalog is explicitly unresolved and not claimed here.
BASELINE_ACTIONS: tuple[ActionUrn, ...] = (
    ActionUrn("urn:mtmf:iam:actions:system:principal:create-object"),
    ActionUrn("urn:mtmf:iam:actions:system:principal:get-object"),
    ActionUrn("urn:mtmf:iam:actions:system:principal:update-object"),
    ActionUrn("urn:mtmf:iam:actions:system:principal:delete-object"),
    ActionUrn("urn:mtmf:iam:actions:system:principal:set-active"),
    ActionUrn("urn:mtmf:iam:actions:system:principal:set-inactive"),
    ActionUrn("urn:mtmf:iam:actions:system:role:create-object"),
    ActionUrn("urn:mtmf:iam:actions:system:role:get-object"),
    ActionUrn("urn:mtmf:iam:actions:system:role:update-object"),
    ActionUrn("urn:mtmf:iam:actions:system:role:delete-object"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:create-object"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:get-object"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:update-object"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:delete-object"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:set-active"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:set-inactive"),
    ActionUrn("urn:mtmf:iam:actions:system:tenant:transfer-stewardship"),
)
