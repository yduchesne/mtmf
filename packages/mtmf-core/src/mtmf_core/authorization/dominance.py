"""Security-scope dominance primitives.

The security model settles exactly one dominance rule at the PR 4
boundary: strict scope dominance ``subject.scope < target.scope``.
No other authorization rule may be derived from the numeric enum
ordering. Alternate dominance (Tenant Stewardship, TenantManagementGroup
delegation) is explicitly not implemented here and must fail closed
until settled.
"""

from __future__ import annotations

from mtmf_core.domain.scope import SecurityScope


def strictly_dominates(subject: SecurityScope, target: SecurityScope) -> bool:
    """True when ``subject`` strictly dominates ``target``.

    Implements the documented strict-dominance rule:

    - ROOT dominates SYSTEM, TENANT, and ORGANIZATION;
    - SYSTEM dominates TENANT and ORGANIZATION;
    - TENANT dominates ORGANIZATION;
    - the same scope never dominates (strict less-than);
    - ORGANIZATION dominates nothing.

    The helper implements exactly this one rule and nothing else; it
    never consults authorization state and is side-effect-free.
    """
    return subject < target
