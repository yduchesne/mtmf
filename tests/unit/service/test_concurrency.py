"""Bounded evaluation admission and synchronous worker lifetime (G4 / A1-16, A1-17).

The deterministic harness uses a blocking synchronous evaluator driven by
threading events (never sleeps as the sole synchronization), an explicit
admission counter, and concurrent ASGI requests. It proves that:

- capacity saturation is a deterministic 503 (no unbounded queueing);
- a permit is retained until the *worker* completes, not merely until the
  HTTP deadline;
- a timed-out request never yields a late ALLOW or partial body;
- permits are released exactly once and in-flight returns to zero.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import ALLOW_ACTION, action_body, auth_headers, seeded_harness

from mtmf_api.authorization import (
    ActionDecision,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
)
from mtmf_service.app import create_app
from mtmf_service.concurrency import (
    EvaluationAdmission,
    EvaluationNotAdmittedError,
    run_admitted,
)
from mtmf_service.rate_limit import TokenBucketRateLimiter
from mtmf_service.readiness import StaticReadiness
from mtmf_service.settings import ServiceSettings

_NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)


class BlockingEvaluationService:
    """A synchronous evaluator that blocks until explicitly released."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self._condition = threading.Condition()
        self.active = 0
        self.peak = 0
        self.entered = 0
        self.completed = 0

    def evaluate(self, *, service_token, user_token, request):  # type: ignore[no-untyped-def]
        with self._condition:
            self.active += 1
            self.entered += 1
            self.peak = max(self.peak, self.active)
            self._condition.notify_all()
        self.release.wait(timeout=10)
        with self._condition:
            self.active -= 1
            self.completed += 1
            self._condition.notify_all()
        return AuthorizationBatchResponse(
            tenant_id=request.tenant_id,
            organization_id=request.organization_id,
            issued_at=_NOW,
            expires_at=_NOW + timedelta(seconds=15),
            decisions=tuple(
                ActionDecision(
                    request_id=item.request_id,
                    effect=AuthorizationEffect.DENY,
                    reason=DecisionReason.NO_PERMISSION,
                )
                for item in request.actions
            ),
        )


class _UnusedManagementMembershipService:
    """Stub dependency for the PR 17 admission suite (management route unused)."""

    def add_identity_to_group(self, *, service_token, user_token, request):  # type: ignore[no-untyped-def]
        raise AssertionError("the management route is not exercised by this suite")


def _app(harness, blocking, admission, settings):  # type: ignore[no-untyped-def]
    return create_app(
        settings=settings,
        authorization_service=blocking,  # type: ignore[arg-type]
        management_membership_service=_UnusedManagementMembershipService(),  # type: ignore[arg-type]
        readiness=StaticReadiness(True),
        rate_limiter=TokenBucketRateLimiter(per_minute=100000, burst=100000),
        admission=admission,
    )


def _post(client: httpx.AsyncClient, harness, *, request_id: str):  # type: ignore[no-untyped-def]
    body = action_body((request_id, ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    return client.post("/v1/authorization/evaluate", json=body, headers=auth_headers())


async def _wait_until(predicate, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met before deadline")


def test_a1_16_saturation_is_deterministic_503():
    settings = ServiceSettings(max_in_flight_evaluations=1)
    harness = seeded_harness(settings=settings)
    blocking = BlockingEvaluationService()
    admission = EvaluationAdmission(1)

    async def scenario() -> None:
        app = _app(harness, blocking, admission, settings)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = asyncio.ensure_future(_post(client, harness, request_id="r1"))
            await _wait_until(lambda: blocking.entered >= 1 and blocking.active >= 1)
            assert admission.in_flight == 1
            second = await _post(client, harness, request_id="r2")
            assert second.status_code == 503
            assert second.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
            blocking.release.set()
            first_response = await first
            assert first_response.status_code == 200
            assert "ALLOW" not in first_response.text
        await _wait_until(lambda: admission.in_flight == 0)
        assert blocking.peak == 1

    asyncio.run(scenario())


def test_a1_17_timeout_retains_permit_until_worker_completes():
    settings = ServiceSettings(max_in_flight_evaluations=1, evaluation_timeout_seconds=0.1)
    harness = seeded_harness(settings=settings)
    blocking = BlockingEvaluationService()
    admission = EvaluationAdmission(1)

    async def scenario() -> None:
        app = _app(harness, blocking, admission, settings)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            timed_out = await _post(client, harness, request_id="r1")
            assert timed_out.status_code == 503
            assert timed_out.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
            assert "ALLOW" not in timed_out.text
            # The abandoned worker is still blocked, so the permit is held.
            await _wait_until(lambda: blocking.entered >= 1)
            assert admission.in_flight == 1
            saturated = await _post(client, harness, request_id="r2")
            assert saturated.status_code == 503
            blocking.release.set()
            await _wait_until(lambda: admission.in_flight == 0)
            assert blocking.completed >= 1
            recovered = await _post(client, harness, request_id="r3")
            assert recovered.status_code == 200
        assert "ALLOW" not in recovered.text

    asyncio.run(scenario())


def test_a1_17_no_worker_runs_without_a_permit():
    settings = ServiceSettings(max_in_flight_evaluations=2)
    harness = seeded_harness(settings=settings)
    blocking = BlockingEvaluationService()
    admission = EvaluationAdmission(2)

    async def scenario() -> None:
        app = _app(harness, blocking, admission, settings)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            tasks = [
                asyncio.ensure_future(_post(client, harness, request_id=f"r{i}")) for i in range(4)
            ]
            await _wait_until(lambda: blocking.active >= 2 or all(t.done() for t in tasks))
            # At most the configured capacity of workers ever run at once.
            assert blocking.entered <= 2
            blocking.release.set()
            responses = [await task for task in tasks]
            statuses = sorted(response.status_code for response in responses)
            assert statuses == [200, 200, 503, 503]
        await _wait_until(lambda: admission.in_flight == 0)
        assert blocking.peak <= 2

    asyncio.run(scenario())


def test_admission_unit_semantics():
    admission = EvaluationAdmission(2)
    first = admission.try_acquire()
    second = admission.try_acquire()
    assert first is not None and second is not None
    assert admission.try_acquire() is None
    assert admission.in_flight == 2
    assert admission.peak_in_flight == 2
    first.release()
    first.release()
    assert admission.in_flight == 1
    second.mark_started()
    second.release_if_not_started()  # no-op: the worker already started
    assert admission.in_flight == 1
    second.release()
    assert admission.in_flight == 0
    assert admission.peak_in_flight == 2
    assert admission.try_acquire() is not None


def test_permit_release_if_not_started_releases_once():
    admission = EvaluationAdmission(1)
    permit = admission.try_acquire()
    assert permit is not None
    assert permit.mark_started() is True
    permit.release_if_not_started()  # no-op
    assert admission.in_flight == 1
    permit.release()
    assert admission.in_flight == 0
    never_started = admission.try_acquire()
    assert never_started is not None
    never_started.release_if_not_started()
    assert admission.in_flight == 0
    never_started.release()  # idempotent
    assert admission.in_flight == 0


def test_admission_rejects_bad_capacity():
    with pytest.raises(ValueError):
        EvaluationAdmission(0)


def test_a2_15_premature_release_prevents_worker_execution():
    """Cancellation proven to precede execution must prevent any work."""
    admission = EvaluationAdmission(1)
    permit = admission.try_acquire()
    assert permit is not None
    # The transport wins the race and releases before the worker begins.
    permit.release_if_not_started()
    assert admission.in_flight == 0
    executed: list[str] = []
    with pytest.raises(EvaluationNotAdmittedError):
        run_admitted(permit, lambda: executed.append("ran"))
    assert executed == []
    # The permit was released exactly once and cannot double-release.
    permit.release()
    assert admission.in_flight == 0


def test_a2_15_worker_start_blocks_transport_release():
    """If the worker begins first, the transport cannot release its permit."""
    admission = EvaluationAdmission(1)
    permit = admission.try_acquire()
    assert permit is not None
    assert permit.mark_started() is True
    # The transport observes RUNNING and must not release.
    permit.release_if_not_started()
    assert admission.in_flight == 1
    permit.release()
    assert admission.in_flight == 0


def test_a2_15_run_admitted_releases_exactly_once():
    admission = EvaluationAdmission(1)
    permit = admission.try_acquire()
    assert permit is not None
    assert run_admitted(permit, lambda: 42) == 42
    assert admission.in_flight == 0
    permit.release()
    assert admission.in_flight == 0
    with pytest.raises(EvaluationNotAdmittedError):
        run_admitted(permit, lambda: "never")
    assert admission.in_flight == 0
