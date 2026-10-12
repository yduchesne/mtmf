"""Distinct liveness/readiness semantics for the PR 17 HTTP PDP.

Liveness answers only "is the process alive"; it must never pretend that
authentication dependencies are healthy. Readiness answers "are the
verified database/runtime privileges, issuer configuration, and (in the
development profile) completed initialization present". Readiness does
**not** replace the mandatory per-request PR 14 issuer attestation.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, runtime_checkable

__all__ = ["ReadinessProbe", "ReadinessState", "StaticReadiness"]


@runtime_checkable
class ReadinessState(Protocol):
    """A readiness decision that exposes no internal detail."""

    def is_ready(self) -> bool:
        """Return whether the service is ready to serve authorization."""
        ...


class StaticReadiness:
    """A fixed readiness state (used by deterministic composition/tests)."""

    __slots__ = ("_ready",)

    def __init__(self, ready: bool) -> None:
        self._ready = ready

    def is_ready(self) -> bool:
        """Return the fixed readiness."""
        return self._ready


class ReadinessProbe:
    """Readiness derived from a sequence of fail-closed dependency checks.

    Each check raises (or returns ``False``) when its dependency is not
    healthy; any failure makes the whole probe unready. Checks must be
    bounded and must not expose secrets or a public authorization oracle.
    """

    __slots__ = ("_checks",)

    def __init__(self, checks: Sequence[Callable[[], None]]) -> None:
        self._checks = tuple(checks)

    def is_ready(self) -> bool:
        """Return ``True`` only when every dependency check succeeds."""
        for check in self._checks:
            try:
                check()
            except Exception:
                # Readiness is fail-closed and detail-free.
                return False
        return True
