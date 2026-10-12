"""Server-side Action sensitivity classification for snapshot TTLs.

PR 12 decision T3 fixes the snapshot lifetimes: 60 seconds default, 300
seconds absolute maximum, 15 seconds maximum for a security-sensitive
Action. The classification must come from authoritative server-side
metadata or an explicit reviewed allowlist, never from a caller flag. If
any Action in a batch is sensitive, the whole response is bounded by the
sensitive TTL because the v1 response carries one ``expires_at``.

No authoritative Action sensitivity catalog exists yet, so the default
classifier is the conservative one: it treats every Action as sensitive
and therefore bounds every response to 15 seconds. A future approved
allowlist may be injected explicitly.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = [
    "AllowlistSensitiveActionClassifier",
    "ConservativeSensitiveActionClassifier",
    "SensitiveActionClassifier",
]


@runtime_checkable
class SensitiveActionClassifier(Protocol):
    """Authoritative, server-side sensitivity decision for an Action URN."""

    def is_sensitive(self, action_urn: str) -> bool:
        """Return whether ``action_urn`` is security-sensitive."""
        ...


class ConservativeSensitiveActionClassifier:
    """Fail-safe classifier that bounds every response to the sensitive TTL.

    Used until an authoritative sensitivity classification is reviewed and
    approved; it never guesses that an unclassified Action is
    non-sensitive.
    """

    __slots__ = ()

    def is_sensitive(self, action_urn: str) -> bool:
        """Return ``True`` for every Action."""
        return True


class AllowlistSensitiveActionClassifier:
    """Reviewed-allowlist classifier over exact canonical Action URNs."""

    __slots__ = ("_sensitive",)

    def __init__(self, sensitive_action_urns: frozenset[str]) -> None:
        for urn in sensitive_action_urns:
            if not isinstance(urn, str) or not urn:
                raise ValueError("sensitive Action URNs must be non-empty strings")
        self._sensitive = frozenset(sensitive_action_urns)

    def is_sensitive(self, action_urn: str) -> bool:
        """Return whether ``action_urn`` is in the reviewed allowlist."""
        return action_urn in self._sensitive
