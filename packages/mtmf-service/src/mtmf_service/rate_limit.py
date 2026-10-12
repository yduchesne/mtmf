"""Bounded, in-process request rate limiting for the PR 17 HTTP PDP.

The limiter is deliberately local to one process. It is a resource
protection control, **not** a cluster-global quota: a multi-worker or
multi-replica deployment must not present it as a distributed limit.
Keys are derived from the transport peer address (never a spoofable
forwarded header). Saturation returns a PR 15 ``RATE_LIMITED`` envelope
and never a grant.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

__all__ = ["MonotonicClock", "RateLimiter", "TokenBucketRateLimiter"]


@runtime_checkable
class RateLimiter(Protocol):
    """A keyed admission-control decision."""

    def acquire(self, key: str) -> bool:
        """Return ``True`` when a request for ``key`` is admitted."""
        ...


@runtime_checkable
class MonotonicClock(Protocol):
    """A monotonic-seconds source (injectable for determinism)."""

    def monotonic(self) -> float:
        """Return monotonically non-decreasing seconds."""
        ...


class _SystemMonotonicClock:
    """Default monotonic clock backed by :func:`time.monotonic`."""

    __slots__ = ()

    def monotonic(self) -> float:
        """Return ``time.monotonic()``."""
        return time.monotonic()


class TokenBucketRateLimiter:
    """Thread-safe, per-key token bucket with a bounded number of keys.

    :param per_minute: sustained refill rate in requests per minute.
    :param burst: maximum bucket capacity (instantaneous burst).
    :param max_keys: hard cap on tracked keys; beyond it the
        least-recently-used bucket is evicted, so an attacker cannot grow
        memory without bound.
    :param clock: monotonic time source; injectable for tests.
    """

    __slots__ = (
        "_burst",
        "_clock",
        "_lock",
        "_max_keys",
        "_refill_per_second",
        "_tokens",
    )

    def __init__(
        self,
        *,
        per_minute: int,
        burst: int,
        max_keys: int = 100_000,
        clock: MonotonicClock | None = None,
    ) -> None:
        if per_minute < 1 or burst < 1 or max_keys < 1:
            raise ValueError("rate limiter parameters must be positive")
        self._refill_per_second = per_minute / 60.0
        self._burst = float(burst)
        self._max_keys = max_keys
        self._clock: MonotonicClock = clock or _SystemMonotonicClock()
        self._lock = threading.Lock()
        self._tokens: dict[str, tuple[float, float]] = {}

    def acquire(self, key: str) -> bool:
        """Consume one token for ``key`` if available."""
        with self._lock:
            now = self._clock.monotonic()
            tokens, updated = self._tokens.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + (now - updated) * self._refill_per_second)
            if tokens < 1.0:
                self._tokens[key] = (tokens, now)
                return False
            self._tokens[key] = (tokens - 1.0, now)
            if len(self._tokens) > self._max_keys:
                self._evict_oldest()
            return True

    def _evict_oldest(self) -> None:
        """Drop the least-recently-updated bucket to bound memory."""
        oldest_key = min(self._tokens, key=lambda existing: self._tokens[existing][1])
        del self._tokens[oldest_key]
