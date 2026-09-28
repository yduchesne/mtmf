"""Foundational URN value type.

Later PRs own the concrete Role/Action/Permission URN namespaces and the
Permission-URN wildcard grammar. This type provides the generic
immutable URN shell that every later MTMF URN reuses, with only
empty/obviously-malformed values rejected here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Urn:
    """An immutable URN value preserving its original canonical string.

    :param value: canonical URN text such as ``urn:mtmf:role:system.admin``.
    :raises ValueError: if ``value`` is empty or obviously malformed.
    """

    value: str

    def __post_init__(self) -> None:
        validate_urn(self.value)

    def __str__(self) -> str:
        return self.value


def validate_urn(value: str) -> None:
    """Raise :class:`ValueError` for empty or obviously malformed URNs.

    The check is deliberately generic: only structural flaws are
    rejected so that PR 3 can define MTMF-specific namespace and wildcard
    rules on top of this foundation.
    """
    if not value:
        raise ValueError("URN must not be empty")
    if not value.startswith("urn:"):
        raise ValueError("URN must start with the 'urn:' scheme prefix")
    remainder = value[4:]
    if ":" not in remainder:
        raise ValueError("URN must contain a namespace-specific string")
    namespace, _, specific = remainder.partition(":")
    if not namespace:
        raise ValueError("URN namespace identifier must not be empty")
    if not specific:
        raise ValueError("URN namespace-specific string must not be empty")
    if value != value.strip():
        raise ValueError("URN must not contain leading or trailing whitespace")
