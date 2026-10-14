#!/usr/bin/env python3
"""PR 19 acceptance benchmark: PR 19 instrumentation vs. the pre-PR-19 baseline.

Runs a fixed, realistic authenticated batch-authorization workload through the
real HTTP PDP (real Keycloak-issued tokens, real PostgreSQL runtime role,
real Uvicorn ASGI app) and reports throughput and latency percentiles.

Modes:

- ``baseline``   the pre-PR-19 revision (no instrumentation support at all);
- ``disabled``   PR 19 code with OTel disabled (default);
- ``healthy``    PR 19 code with OTel enabled and a healthy Collector;
- ``unavailable`` PR 19 code with OTel enabled and the Collector stopped.

The harness is revision-agnostic: it detects whether the PR 19 observability
package is importable and adapts the composition calls accordingly, so the
same file can be copied into the pre-PR-19 worktree.

This script is intentionally *not* a unit/integration test and is never run by
``./build.sh``. It requires the explicit live environment (``MTMF_*`` runtime
configuration, ``MTMF_PR14_KC_*`` issuer credentials) and the MTMF-owned
PostgreSQL/Collector.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import psycopg

REPO_ROOT = Path(__file__).resolve().parent.parent
HERE = REPO_ROOT / "tests" / "integration" / "postgres"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

ALLOW_ACTION = "urn:mtmf:iam:actions:system:principal:get-object"
DENY_ACTION = "urn:mtmf:iam:actions:system:principal:update-object"
PORT = int(os.environ.get("MTMF_PR19_BENCH_PORT", "28015"))
BASE_URL = f"http://127.0.0.1:{PORT}"

try:
    from mtmf_service.observability.runtime import build_telemetry

    _HAS_OBSERVABILITY = True
except Exception:  # pragma: no cover - baseline revision path
    build_telemetry = None  # type: ignore[assignment]
    _HAS_OBSERVABILITY = False


@dataclass
class RunResult:
    """One measured workload run."""

    batch_size: int
    decision_mix: str
    requests: int
    duration_s: float
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        return self.requests / self.duration_s if self.duration_s > 0 else 0.0

    def percentile(self, value: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(len(ordered) - 1, round((value / 100.0) * (len(ordered) - 1)))
        return ordered[index]


def _reset_and_seed() -> tuple[str, dict[str, str]]:
    """Reset the MTMF schema and seed one deterministic tenant graph."""
    import helpers
    import test_pr17_live_http as pr17

    from mtmf_core.persistence.postgres import PostgresConfig, PostgresRole

    admin = psycopg.connect(PostgresConfig.from_env().psycopg_dsn, autocommit=True)
    helpers.reset_and_migrate(admin, PostgresConfig.from_env(PostgresRole.MIGRATOR))
    subject = pr17.ev.decode_unverified(pr17._user_token())[1]["sub"]
    ids = pr17._seed(admin, subject)
    return subject, ids


def _build_batch(tenant_id: str, batch_size: int) -> tuple[dict[str, Any], str]:
    """Build a fixed batch request and its decision-mix label."""
    if batch_size == 1:
        actions = [("r0", ALLOW_ACTION)]
        mix = "ALLOW"
    else:
        half = batch_size // 2
        actions = [(f"a{i}", ALLOW_ACTION) for i in range(half)] + [
            (f"d{i}", DENY_ACTION) for i in range(batch_size - half)
        ]
        mix = "MIXED"
    return (
        {
            "tenant_id": tenant_id,
            "organization_id": None,
            "actions": [
                {
                    "request_id": request_id,
                    "action": action,
                    "resource": {"kind": "capability"},
                }
                for request_id, action in actions
            ],
        },
        mix,
    )


def _build_app(mode: str) -> tuple[Any, Any]:
    """Compose a real ASGI app for ``mode``. Returns ``(app, telemetry)``."""
    import test_pr17_live_http as pr17

    from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi, PostgresRole
    from mtmf_service.app import create_app
    from mtmf_service.composition import build_authorization_service
    from mtmf_service.rate_limit import TokenBucketRateLimiter
    from mtmf_service.readiness import StaticReadiness
    from mtmf_service.settings import ServiceSettings

    settings_kwargs: dict[str, Any] = {"evaluation_timeout_seconds": 30.0}
    telemetry = None
    if mode != "baseline":
        settings_kwargs.update(
            {
                "otel_enabled": mode in ("healthy", "unavailable"),
                "otel_exporter_otlp_endpoint": os.environ.get("MTMF_PR19_COLLECTOR_ENDPOINT"),
                "otel_service_name": "mtmf-service",
                "otel_environment": "benchmark",
                "otel_schedule_delay_ms": 1000,
                "otel_metric_export_interval_ms": 2000,
            }
        )
        if mode == "disabled":
            settings_kwargs["otel_exporter_otlp_endpoint"] = None
    settings = ServiceSettings(**settings_kwargs)

    if mode != "baseline":
        telemetry = build_telemetry(settings)

    spi_config = PostgresConfig.from_env(PostgresRole.RUNTIME)
    if mode != "baseline":
        from mtmf_service.observability.persistence import MetricsPersistenceTelemetry

        spi = PostgresMtmfSpi(spi_config, telemetry=MetricsPersistenceTelemetry(telemetry))
    else:
        spi = PostgresMtmfSpi(spi_config)

    build_kwargs: dict[str, Any] = {}
    create_kwargs: dict[str, Any] = {}
    if mode != "baseline":
        build_kwargs["telemetry"] = telemetry
        create_kwargs["telemetry"] = telemetry
        create_kwargs["on_shutdown"] = telemetry.shutdown
    authorization_service = build_authorization_service(
        spi=spi,
        issuer_config=pr17._issuer_config(),
        settings=settings,
        **build_kwargs,
    )
    app = create_app(
        settings=settings,
        authorization_service=authorization_service,
        readiness=StaticReadiness(True),
        rate_limiter=TokenBucketRateLimiter(per_minute=10_000_000, burst=10_000_000),
        **create_kwargs,
    )
    return app, telemetry


def _measure(
    mode: str,
    *,
    warmup_s: float,
    duration_s: float,
    concurrency: int,
    runs: int,
    workloads: list[int],
    output: Path,
) -> dict[str, Any]:
    import test_pr17_live_http as pr17

    _subject, ids = _reset_and_seed()
    tenant_id = ids["tenant_id"]

    if mode == "healthy":
        subprocess.run(["podman", "start", "mtmf_collector_1"], capture_output=True)
        time.sleep(5)
    elif mode == "unavailable":
        subprocess.run(["podman", "stop", "mtmf_collector_1"], capture_output=True)
        time.sleep(2)

    app, telemetry = _build_app(mode)
    results: list[RunResult] = []
    with pr17._LiveServer(app, port=PORT):
        for batch_size in workloads:
            batch, mix = _build_batch(tenant_id, batch_size)
            for run_index in range(runs):
                # Fresh credentials per run: the development access-token
                # lifetime is short and a long campaign must not fail closed
                # on an expired service token.
                headers = pr17._headers(pr17._service_token(), pr17._user_token())
                _drive(batch, headers, seconds=warmup_s, concurrency=concurrency, record=None)
                result = _drive(
                    batch,
                    headers,
                    seconds=duration_s,
                    concurrency=concurrency,
                    record=RunResult(
                        batch_size=batch_size, decision_mix=mix, requests=0, duration_s=0.0
                    ),
                )
                result.duration_s = duration_s
                results.append(result)
                print(
                    f"[{mode}] batch={batch_size} run={run_index + 1}/{runs} "
                    f"requests={result.requests} rps={result.throughput:.1f} "
                    f"p50={result.percentile(50):.2f} p99={result.percentile(99):.2f}",
                    flush=True,
                )
    rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if telemetry is not None:
        telemetry.shutdown()
    summary = _summarize(mode, results, rss_kb)
    output.write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def _drive(
    batch: dict[str, Any],
    headers: dict[str, str],
    *,
    seconds: float,
    concurrency: int,
    record: RunResult | None,
) -> RunResult:
    """Drive one fixed workload for ``seconds`` at ``concurrency``."""
    result = record or RunResult(batch_size=0, decision_mix="", requests=0, duration_s=0.0)
    deadline = time.perf_counter() + seconds
    lock = threading.Lock()
    stop = threading.Event()

    def _worker() -> None:
        with httpx.Client(base_url=BASE_URL, timeout=30) as client:
            while not stop.is_set() and time.perf_counter() < deadline:
                start = time.perf_counter()
                response = client.post("/v1/authorization/evaluate", json=batch, headers=headers)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                if response.status_code != 200:
                    stop.set()
                    raise RuntimeError(
                        f"unexpected status {response.status_code}: {response.text[:200]}"
                    )
                with lock:
                    result.requests += 1
                    result.latencies_ms.append(elapsed_ms)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_worker) for _ in range(concurrency)]
        for future in futures:
            future.result()
    return result


def _summarize(mode: str, results: list[RunResult], rss_kb: int) -> dict[str, Any]:
    by_workload: dict[str, dict[str, Any]] = {}
    for result in results:
        key = f"size{result.batch_size}_{result.decision_mix}"
        by_workload.setdefault(key, {"runs": []})
        by_workload[key]["runs"].append(
            {
                "requests": result.requests,
                "throughput": result.throughput,
                "p50": result.percentile(50),
                "p95": result.percentile(95),
                "p99": result.percentile(99),
            }
        )
    for value in by_workload.values():
        rows = value["runs"]
        value["median_throughput"] = statistics.median(r["throughput"] for r in rows)
        value["median_p50"] = statistics.median(r["p50"] for r in rows)
        value["median_p95"] = statistics.median(r["p95"] for r in rows)
        value["median_p99"] = statistics.median(r["p99"] for r in rows)
    return {
        "mode": mode,
        "has_observability": _HAS_OBSERVABILITY,
        "max_rss_kb": rss_kb,
        "workloads": by_workload,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 19 acceptance benchmark")
    parser.add_argument(
        "--mode", choices=("baseline", "disabled", "healthy", "unavailable"), required=True
    )
    parser.add_argument("--warmup", type=float, default=10.0)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--runs", type=int, default=5)
    # Serial by default: the pre-existing (PR-14) actor/JWKS verifier is not
    # thread-safe under concurrent in-process calls (an intermittent
    # invalid_token that is identical in the baseline and PR 19 and unrelated
    # to instrumentation). Serial requests keep the comparison deterministic.
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--sizes", type=str, default="1,10,100")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode != "baseline" and not _HAS_OBSERVABILITY:
        parser.error("non-baseline mode requires the PR 19 observability package")
    if args.mode == "baseline" and _HAS_OBSERVABILITY:
        parser.error("baseline mode must run against the pre-PR-19 revision")
    workloads = [int(value) for value in args.sizes.split(",")]
    summary = _measure(
        args.mode,
        warmup_s=args.warmup,
        duration_s=args.duration,
        concurrency=args.concurrency,
        runs=args.runs,
        workloads=workloads,
        output=args.output,
    )
    print(json.dumps(summary, indent=2))
    if args.mode == "unavailable":
        subprocess.run(["podman", "start", "mtmf_collector_1"], capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
