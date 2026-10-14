"""W01-W08: bounded-worker lifetime and capacity correctness.

These tests exercise the fixup defect directly: a worker slot must remain
occupied until the submitted synchronous operation actually terminates, even
after the awaiting caller times out or is cancelled.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

import pytest
from mtmf_reference_app.app import BoundedWorker

_THREAD_WAIT_SECONDS = 10.0


class BlockingCall:
    """A synchronous call that blocks until released, recording lifecycle."""

    def __init__(self, result: Any = "done") -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.entered = 0
        self._result = result

    def __call__(self) -> Any:
        self.entered += 1
        self.started.set()
        self.release.wait(_THREAD_WAIT_SECONDS)
        self.finished.set()
        return self._result


class LateFailure:
    """A blocking call that raises only after it is released."""

    def __init__(self, message: str = "late-boom") -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self._message = message

    def __call__(self) -> Any:
        self.started.set()
        self.release.wait(_THREAD_WAIT_SECONDS)
        self.finished.set()
        raise ValueError(self._message)


class Recorder:
    """A non-blocking call that records how many times it was entered."""

    def __init__(self, result: Any = "done") -> None:
        self.entered = 0
        self._result = result

    def __call__(self) -> Any:
        self.entered += 1
        return self._result


class ConcurrencyProbe:
    """Track the maximum number of simultaneously entered blocking calls."""

    def __init__(self, target: int) -> None:
        self._target = target
        self.entered_target = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.current = 0
        self.maximum = 0
        self.entered = 0

    def __call__(self, index: int) -> int:
        with self._lock:
            self.current += 1
            self.entered += 1
            self.maximum = max(self.maximum, self.current)
            if self.entered >= self._target:
                self.entered_target.set()
        self.release.wait(_THREAD_WAIT_SECONDS)
        with self._lock:
            self.current -= 1
        return index


async def _wait_thread_event(event: threading.Event, timeout: float = 2.0) -> bool:
    """Wait for a thread-side event without blocking the event loop."""
    loop = asyncio.get_running_loop()
    return bool(await loop.run_in_executor(None, event.wait, timeout))


async def _completes_within(task: asyncio.Future[Any], timeout: float = 0.1) -> bool:
    done, _ = await asyncio.wait({task}, timeout=timeout)
    return task in done


def test_w01_normal_return_and_slot_reuse() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=1.0)
        assert await worker.run(lambda: 41 + 1) == 42
        assert await worker.run(lambda: "second") == "second"

    asyncio.run(scenario())


def test_w02_blocking_exception_propagates_and_slot_reusable() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=1.0)

        def boom() -> None:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            await worker.run(boom)
        assert await worker.run(lambda: "ok") == "ok"

    asyncio.run(scenario())


def test_w03_timeout_keeps_slot_until_thread_finishes() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=0.05)
        first = BlockingCall("first")
        second = Recorder("second")
        with pytest.raises(TimeoutError):
            await worker.run(first)
        assert await _wait_thread_event(first.started)
        assert not first.finished.is_set()  # caller finished, thread did not
        second_task = asyncio.ensure_future(worker.run(second))
        assert not await _completes_within(second_task)
        assert second.entered == 0
        first.release.set()
        assert await _wait_thread_event(first.finished)
        assert await asyncio.wait_for(second_task, timeout=2.0) == "second"
        assert second.entered == 1

    asyncio.run(scenario())


def test_w04_release_after_timeout_allows_reuse() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=0.05)
        first = BlockingCall("first")
        with pytest.raises(TimeoutError):
            await worker.run(first)
        assert await _wait_thread_event(first.started)
        first.release.set()
        assert await _wait_thread_event(first.finished)
        assert await worker.run(lambda: "reused") == "reused"

    asyncio.run(scenario())


def test_w05_cancel_caller_keeps_slot_until_thread_finishes() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=5.0)
        first = BlockingCall("first")
        second = Recorder("second")
        first_task = asyncio.ensure_future(worker.run(first))
        assert await _wait_thread_event(first.started)
        first_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_task
        assert not first.finished.is_set()
        second_task = asyncio.ensure_future(worker.run(second))
        assert not await _completes_within(second_task)
        assert second.entered == 0
        first.release.set()
        assert await _wait_thread_event(first.finished)
        assert await asyncio.wait_for(second_task, timeout=2.0) == "second"

    asyncio.run(scenario())


def test_w06_cancel_while_waiting_to_acquire_no_spurious_release() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=5.0)
        first = BlockingCall("first")
        first_task = asyncio.ensure_future(worker.run(first))
        assert await _wait_thread_event(first.started)
        second = BlockingCall("second")
        second_task = asyncio.ensure_future(worker.run(second))
        assert not await _completes_within(second_task)
        assert second.entered == 0
        second_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second_task
        assert second.entered == 0
        assert not first.finished.is_set()
        first.release.set()
        assert await _wait_thread_event(first.finished)
        assert await asyncio.wait_for(first_task, timeout=2.0) == "first"
        # Exactly one permit remains: two concurrent probes must never overlap.
        probe = ConcurrencyProbe(target=1)
        first_probe = asyncio.ensure_future(worker.run(probe, 1))
        second_probe = asyncio.ensure_future(worker.run(probe, 2))
        assert await _wait_thread_event(probe.entered_target)
        await asyncio.wait({first_probe, second_probe}, timeout=0.1)
        assert probe.maximum == 1
        probe.release.set()
        await asyncio.wait_for(asyncio.gather(first_probe, second_probe), timeout=2.0)
        assert probe.maximum == 1

    asyncio.run(scenario())


def test_w07_late_exception_is_retrieved_and_slot_reused() -> None:
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    async def scenario() -> None:
        worker = BoundedWorker(limit=1, timeout=0.05)
        late = LateFailure("late-boom")
        with pytest.raises(TimeoutError):
            await worker.run(late)
        assert await _wait_thread_event(late.started)
        late.release.set()
        assert await _wait_thread_event(late.finished)
        assert await worker.run(lambda: "reused") == "reused"

    asyncio_logger = logging.getLogger("asyncio")
    handler = _Capture()
    asyncio_logger.addHandler(handler)
    previous_level = asyncio_logger.level
    asyncio_logger.setLevel(logging.WARNING)
    try:
        asyncio.run(scenario())
    finally:
        asyncio_logger.removeHandler(handler)
        asyncio_logger.setLevel(previous_level)
    joined = " | ".join(record.getMessage() for record in records)
    assert "late-boom" not in joined
    assert "never retrieved" not in joined.lower()


def test_w08_limit_two_holds_capacity_across_timeouts() -> None:
    async def scenario() -> None:
        worker = BoundedWorker(limit=2, timeout=0.05)
        probe = ConcurrencyProbe(target=2)
        tasks = [asyncio.ensure_future(worker.run(probe, index)) for index in (1, 2)]
        assert await _wait_thread_event(probe.entered_target)
        done, _ = await asyncio.wait(tasks, timeout=2.0)
        assert len(done) == 2
        for task in tasks:
            with pytest.raises(TimeoutError):
                task.result()
        assert probe.maximum == 2
        third = asyncio.ensure_future(worker.run(probe, 3))
        assert not await _completes_within(third, timeout=0.2)
        assert probe.entered == 2
        assert probe.maximum == 2
        probe.release.set()
        assert await asyncio.wait_for(third, timeout=2.0) == 3
        assert probe.maximum == 2

    asyncio.run(scenario())
