"""Bounded synchronous-evaluation admission for the PR 17 HTTP PDP.

The evaluation path runs synchronous, potentially blocking work (DB, issuer
and policy calls) in a worker thread. ``asyncio.wait_for`` around
``run_in_threadpool`` enforces a *response* deadline but does **not**
terminate a running worker: Starlette abandons the thread on cancellation
and it keeps running (see the amendment timeout evidence). A response
deadline alone therefore neither bounds resource use nor proves that no
work continues after the client gave up.

This module adds an explicit, configurable admission counter around
evaluation. A permit is acquired before dispatch and released **only when
the underlying worker actually completes** (or, if the worker never began
because it was cancelled while queued, when the transport observes that it
never started). Saturation is a deterministic, fail-closed rejection rather
than unbounded queueing.

The admission counter is process-local, like the rate limiter: it bounds
work per worker process, not cluster-wide.
"""

from __future__ import annotations

import threading

__all__ = ["EvaluationAdmission", "EvaluationPermit"]


class EvaluationPermit:
    """One admission permit with idempotent, state-guarded release.

    States: ``HELD`` (acquired, worker not yet entered) -> ``RUNNING``
    (worker entered) -> ``RELEASED``; or ``HELD`` -> ``RELEASED`` when the
    worker never began. A release after ``RELEASED`` is a no-op, so the
    worker's ``finally`` and the transport's not-started fallback cannot
    double-count.
    """

    __slots__ = ("_admission", "_lock", "_state")

    def __init__(self, admission: EvaluationAdmission) -> None:
        self._admission = admission
        self._lock = threading.Lock()
        self._state = "HELD"

    def mark_started(self) -> bool:
        """Record that the worker entered; ``False`` if already released."""
        with self._lock:
            if self._state == "HELD":
                self._state = "RUNNING"
                return True
            return False

    def release(self) -> None:
        """Release the permit exactly once, when the worker completes."""
        with self._lock:
            if self._state == "RELEASED":
                return
            self._state = "RELEASED"
        self._admission._release()

    def release_if_not_started(self) -> None:
        """Release only if the worker never entered (cancelled while queued)."""
        with self._lock:
            if self._state != "HELD":
                return
            self._state = "RELEASED"
        self._admission._release()


class EvaluationAdmission:
    """A bounded, in-process counter of in-flight evaluations."""

    __slots__ = ("_lock", "_max", "_peak", "_running")

    def __init__(self, max_in_flight: int) -> None:
        if max_in_flight < 1:
            raise ValueError("max_in_flight must be positive")
        self._max = max_in_flight
        self._running = 0
        self._peak = 0
        self._lock = threading.Lock()

    @property
    def max_in_flight(self) -> int:
        """The configured admission cap."""
        return self._max

    @property
    def in_flight(self) -> int:
        """The number of permits currently held."""
        with self._lock:
            return self._running

    @property
    def peak_in_flight(self) -> int:
        """The observed peak number of concurrently held permits."""
        with self._lock:
            return self._peak

    def try_acquire(self) -> EvaluationPermit | None:
        """Return a permit, or ``None`` when the cap is already reached."""
        with self._lock:
            if self._running >= self._max:
                return None
            self._running += 1
            if self._running > self._peak:
                self._peak = self._running
        return EvaluationPermit(self)

    def _release(self) -> None:
        with self._lock:
            if self._running > 0:
                self._running -= 1
