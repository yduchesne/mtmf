"""Settings, clock and rate-limiter seams (PR 17 hardening)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mtmf_service.clock import FrozenClock, SystemClock
from mtmf_service.rate_limit import MonotonicClock, TokenBucketRateLimiter
from mtmf_service.settings import (
    DEFAULT_MAX_REQUEST_BYTES,
    DeploymentMode,
    ServiceConfigurationError,
    ServiceSettings,
)


def test_default_settings_are_valid_and_development():
    settings = ServiceSettings()
    settings.validate_startup()
    assert settings.deployment_mode is DeploymentMode.DEVELOPMENT
    assert settings.max_request_bytes == DEFAULT_MAX_REQUEST_BYTES


def test_production_profile_is_disabled():
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(deployment_mode=DeploymentMode.PRODUCTION).validate_startup()


def test_non_loopback_binding_is_rejected():
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(host="192.0.2.10").validate_startup()


def test_container_bind_requires_explicit_opt_in():
    ServiceSettings(host="192.0.2.10", allow_container_bind=True).validate_startup()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_request_bytes": 0},
        {"sensitive_ttl_seconds": 0},
        {"sensitive_ttl_seconds": 90, "default_ttl_seconds": 60},
        {"max_ttl_seconds": 301},
        {"rate_limit_per_minute": 0},
        {"rate_limit_burst": 0},
        {"authentication_timeout_seconds": 0},
        {"evaluation_timeout_seconds": -1},
        {"max_in_flight_evaluations": 0},
        {"user_authorization_header": ""},
    ],
)
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(**kwargs)


def test_from_env(monkeypatch):
    monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "development")
    monkeypatch.setenv("MTMF_SERVICE_MAX_REQUEST_BYTES", "1024")
    monkeypatch.setenv("MTMF_SERVICE_PORT", "28999")
    settings = ServiceSettings.from_env()
    assert settings.max_request_bytes == 1024
    assert settings.port == 28999
    with pytest.raises(ServiceConfigurationError):
        monkeypatch.setenv("MTMF_SERVICE_DEPLOYMENT_MODE", "nonsense")
        ServiceSettings.from_env()


def test_frozen_clock_advances_and_rejects_naive():
    with pytest.raises(ValueError):
        FrozenClock(datetime(2026, 1, 1))
    clock = FrozenClock(datetime(2026, 1, 1, tzinfo=UTC))
    assert clock.now() == datetime(2026, 1, 1, tzinfo=UTC)
    assert clock.advance(seconds=5).now() == datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
    assert SystemClock().now().tzinfo is UTC


class _StepClock:
    """Deterministic monotonic clock returning a fixed value."""

    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def monotonic(self) -> float:
        return self.value


def test_token_bucket_exhausts_and_refills():
    clock = _StepClock(0.0)
    limiter = TokenBucketRateLimiter(per_minute=60, burst=2, clock=clock)
    assert limiter.acquire("peer") is True
    assert limiter.acquire("peer") is True
    assert limiter.acquire("peer") is False
    clock.value = 1.0  # one second elapsed refills one token
    assert limiter.acquire("peer") is True
    assert limiter.acquire("peer") is False


def test_token_bucket_bounds_memory_by_evicting_lru():
    clock = _StepClock(0.0)
    limiter = TokenBucketRateLimiter(per_minute=60, burst=1, max_keys=2, clock=clock)
    assert limiter.acquire("a")
    assert limiter.acquire("b")
    assert limiter.acquire("c")
    assert len(limiter._tokens) <= 3  # type: ignore[attr-defined]


def test_token_bucket_rejects_bad_parameters():
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(per_minute=0, burst=1)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(per_minute=1, burst=0)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(per_minute=1, burst=1, max_keys=0)


def test_monotonic_clock_protocol_is_runtime_checkable():
    assert isinstance(TokenBucketRateLimiter(per_minute=1, burst=1)._clock, MonotonicClock)  # type: ignore[attr-defined]
