#!/usr/bin/env python3
"""Batch-authorization lifecycle benchmark (PR 16).

Characterizes three authorization paths over the SAME deterministic
shared-context batches, reusing the PR 8E/8G policy fixtures (no second
engine):

    PI  Python individual: N full ``Authorizer().authorize(request)``
        calls (per-request session/target validation and per-request
        policy compile/resolve);
    PB  Python batch: one ``BatchAuthorizer().authorize(batch)`` (one
        shared session check, one policy compile/resolve over the whole
        ordered batch);
    RB  Rust batch: one ``RustBatchAuthorizer().authorize(batch)`` (one
        Role->primitive conversion + native indexed compile + one PyO3
        batch crossing + result mapping).

The matrix crosses batch sizes 1/10/25/100 with policy sizes
25/200/1000/5000 Permissions. Each batch cycles a deterministic mixed
Action workload (exact hit, wildcard hit, wildcard DENY, no-match) so
every outcome class is represented.

Correctness is checked BEFORE timing: for every scenario the single
Authorizer, the Python batch, and the Rust batch must be fully equal
(effect, reason, matched specificity, matched allow/deny), and the
benchmark aborts on any parity failure or unavailable native module.
Timing is informational only: no speed threshold exists, Rust slower is
acceptable, and no generalization beyond this machine is claimed.

CLI:

    uv run --no-sync python benchmarks/batch_authorization_benchmark.py
    uv run --no-sync python benchmarks/batch_authorization_benchmark.py \\
        --warmup 20 --samples 15 --json /tmp/batch-bench.json
    uv run --no-sync python benchmarks/batch_authorization_benchmark.py --smoke

``--smoke`` verifies native availability, fixture construction,
parity-before-timing, the timing loop, and human/JSON serialization with
tiny counts; it asserts no timing threshold.

Full-decision parity is checked against the existing PR 8G/8H Python
oracle and the new batch paths; the policy engine itself is not
reimplemented here.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field

from compiled_policy_benchmark import (
    _MULTI_ACTION_WORKLOAD,
    _build_scale_roles,
    _full_decision_equality,
    _policy_counts,
)
from mtmf_core import (
    AuthorizationBatch,
    AuthorizationContext,
    AuthorizationRequest,
    Authorizer,
    BatchAuthorizer,
    DomainId,
    Identity,
    IdentityOrigin,
    IdentityTenantMembership,
    Principal,
    PrincipalTenantMembership,
    Role,
    RustBatchAuthorizer,
    SecurityScope,
    SessionContext,
    Tenant,
    TenantLifecycle,
)
from mtmf_core.authorization.rust_engine import RustEngineUnavailableError, engine_version

_POLICY_SIZES = (25, 200, 1000, 5000)
_BATCH_SIZES = (1, 10, 25, 100)
_SEED = 0x50523136  # fixed PR 16 seed; scenario generation is deterministic anyway


@dataclass(frozen=True)
class BatchScenario:
    """A pre-built shared-context batch over a fixed policy."""

    name: str
    description: str
    batch_size: int
    permission_count: int
    requests: tuple[AuthorizationRequest, ...]
    batch: AuthorizationBatch


def _context(roles: tuple[Role, ...]) -> AuthorizationContext:
    """Build a structurally valid shared authorization context."""
    tenant = Tenant(
        DomainId.generate(),
        "bench-tenant",
        SecurityScope.TENANT,
        DomainId.generate(),
        lifecycle=TenantLifecycle.ACTIVE,
    )
    principal = Principal(DomainId.generate(), "bench-principal")
    identity = Identity(DomainId.generate(), principal.id, "bench-identity", IdentityOrigin.LOCAL)
    return AuthorizationContext(
        SessionContext(tenant.id, principal.id, identity.id),
        tenant,
        principal,
        identity,
        (PrincipalTenantMembership(principal.id, tenant.id),),
        (IdentityTenantMembership(identity.id, tenant.id),),
        roles,
    )


def _build_scenarios() -> list[BatchScenario]:
    """Build every deterministic batch scenario once (outside timing)."""
    scenarios: list[BatchScenario] = []
    for permission_count in _POLICY_SIZES:
        roles = _build_scale_roles(permission_count)
        _, perms_count = _policy_counts(roles)
        context = _context(roles)
        for batch_size in _BATCH_SIZES:
            actions = tuple(
                _MULTI_ACTION_WORKLOAD[index % len(_MULTI_ACTION_WORKLOAD)]
                for index in range(batch_size)
            )
            requests = tuple(
                AuthorizationRequest(context, action, context.tenant.id) for action in actions
            )
            scenarios.append(
                BatchScenario(
                    name=f"batch{batch_size}_policy{permission_count}",
                    description=(
                        f"{batch_size}-Action ordered batch over {perms_count} Permissions "
                        "(exact hit, wildcard hit, wildcard DENY, no-match)"
                    ),
                    batch_size=batch_size,
                    permission_count=perms_count,
                    requests=requests,
                    batch=AuthorizationBatch(requests),
                )
            )
    return scenarios


def _check_parity(scenario: BatchScenario) -> None:
    """Require PI == PB == RB complete-decision equality before timing."""
    authorizer = Authorizer()
    try:
        expected = tuple(authorizer.authorize(request) for request in scenario.requests)
        python_batch = BatchAuthorizer().authorize(scenario.batch).decisions
        rust_batch = RustBatchAuthorizer().authorize(scenario.batch).decisions
    except RustEngineUnavailableError as exc:
        raise SystemExit(
            f"private native module is unavailable for scenario {scenario.name!r}; "
            "run `./build.sh --rust` first"
        ) from exc
    for index, (single, python_decision, rust_decision) in enumerate(
        zip(expected, python_batch, rust_batch, strict=True)
    ):
        action = scenario.requests[index].action
        if not _full_decision_equality(single, python_decision):
            raise SystemExit(
                f"single/Python-batch parity failure in {scenario.name!r} index {index} "
                f"for {action.urn.value!r}: single={single!r} batch={python_decision!r}; "
                "timing is aborted"
            )
        if not _full_decision_equality(single, rust_decision):
            raise SystemExit(
                f"single/Rust-batch parity failure in {scenario.name!r} index {index} "
                f"for {action.urn.value!r}: single={single!r} rust={rust_decision!r}; "
                "timing is aborted"
            )


def _measure_python_individual(authorizer: Authorizer, scenario: BatchScenario) -> float:
    """N full Authorizer calls in nanoseconds."""
    start = time.perf_counter_ns()
    for request in scenario.requests:
        authorizer.authorize(request)
    return time.perf_counter_ns() - start


def _measure_python_batch(authorizer: BatchAuthorizer, scenario: BatchScenario) -> float:
    """One Python batch call in nanoseconds."""
    start = time.perf_counter_ns()
    authorizer.authorize(scenario.batch)
    return time.perf_counter_ns() - start


def _measure_rust_batch(authorizer: RustBatchAuthorizer, scenario: BatchScenario) -> float:
    """One Rust batch crossing in nanoseconds."""
    start = time.perf_counter_ns()
    authorizer.authorize(scenario.batch)
    return time.perf_counter_ns() - start


def _iqr(samples: list[float]) -> tuple[float, float, float]:
    """Return ``(q1, median, q3)`` using the inclusive median-of-halves rule."""
    ordered = sorted(samples)
    size = len(ordered)

    def median(values: list[float]) -> float:
        return statistics.median(values)

    if size < 4:
        q1 = ordered[0]
        q3 = ordered[-1]
    else:
        midpoint = size // 2
        lower = ordered[:midpoint]
        upper = ordered[midpoint:] if size % 2 == 0 else ordered[midpoint + 1 :]
        q1 = median(lower)
        q3 = median(upper)
    return q1, median(ordered), q3


@dataclass
class BatchScenarioResult:
    """Per-scenario timing outcome (informational; never a correctness gate)."""

    scenario: BatchScenario
    python_individual_samples: list[float] = field(default_factory=list)
    python_batch_samples: list[float] = field(default_factory=list)
    rust_batch_samples: list[float] = field(default_factory=list)

    def _stats(self, name: str) -> tuple[float, float, float, float]:
        samples = getattr(self, name)
        q1, median, q3 = _iqr(samples)
        return q1, median, q3, q3 - q1

    def median(self, name: str) -> float:
        return statistics.median(getattr(self, name))

    def ratio(self, candidate: str, baseline: str) -> float:
        """``baseline / candidate``; ``>1.0`` means the candidate is faster."""
        candidate_median = self.median(candidate)
        if candidate_median == 0:
            return float("inf")
        return self.median(baseline) / candidate_median


def _run_scenario(scenario: BatchScenario, *, warmup: int, samples: int) -> BatchScenarioResult:
    _check_parity(scenario)
    authorizer = Authorizer()
    batch_authorizer = BatchAuthorizer()
    rust_batch_authorizer = RustBatchAuthorizer()

    def timed(path: str) -> float:
        if path == "python_individual":
            return _measure_python_individual(authorizer, scenario)
        if path == "python_batch":
            return _measure_python_batch(batch_authorizer, scenario)
        return _measure_rust_batch(rust_batch_authorizer, scenario)

    paths = ("python_individual", "python_batch", "rust_batch")
    for _ in range(warmup):
        for path in paths:
            timed(path)

    result = BatchScenarioResult(scenario)
    for sample_index in range(samples):
        # Rotate the measured order so no path is systematically favored
        # by measurement order.
        rotation = sample_index % len(paths)
        ordered_paths = paths[rotation:] + paths[:rotation]
        elapsed = {path: timed(path) for path in ordered_paths}
        result.python_individual_samples.append(elapsed["python_individual"])
        result.python_batch_samples.append(elapsed["python_batch"])
        result.rust_batch_samples.append(elapsed["rust_batch"])
    return result


def _environment() -> dict[str, object]:
    try:
        version = engine_version()
    except RustEngineUnavailableError:
        version = "<unavailable>"
    return {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "rust_engine_version": version,
        "seed": hex(_SEED),
    }


def _render_human(
    results: list[BatchScenarioResult],
    environment: dict[str, object],
    *,
    warmup: int,
    samples: int,
) -> None:
    print("MTMF batch-authorization benchmark (PI / PB / RB; PR 16)")
    print("Environment:")
    for key, value in environment.items():
        print(f"  {key}: {value}")
    print(
        f"  config: warmup={warmup} samples={samples} median primary; "
        "near-1000ns units; characterization only"
    )
    print(
        "  paths: PI = N full Authorizer calls; PB = one Python batch (one policy compile); "
        "RB = one Rust batch crossing (conversion + compile + PyO3 + mapping)"
    )
    print(
        "  ratio direction (baseline/candidate): pb/pi = PI/PB; rb/pb = PB/RB; "
        "rb/pi = PI/RB; >1.0 means the candidate on the right is faster"
    )
    header = (
        "scenario | batch | perms | PI median | PB median | RB median | "
        "PI IQR | PB IQR | RB IQR | pb/pi | rb/pb | rb/pi"
    )
    print(header)
    print("-" * len(header))
    for result in results:
        scenario = result.scenario
        _, pi_med, _, pi_iqr = result._stats("python_individual_samples")
        _, pb_med, _, pb_iqr = result._stats("python_batch_samples")
        _, rb_med, _, rb_iqr = result._stats("rust_batch_samples")
        print(
            f"{scenario.name:<22} "
            f"{scenario.batch_size:>5} "
            f"{scenario.permission_count:>5} "
            f"{pi_med:>9.0f} "
            f"{pb_med:>9.0f} "
            f"{rb_med:>9.0f} "
            f"{pi_iqr:>7.0f} "
            f"{pb_iqr:>6.0f} "
            f"{rb_iqr:>6.0f} "
            f"{result.ratio('python_batch_samples', 'python_individual_samples'):>6.2f}x "
            f"{result.ratio('rust_batch_samples', 'python_batch_samples'):>6.2f}x "
            f"{result.ratio('rust_batch_samples', 'python_individual_samples'):>6.2f}x"
        )
    print(
        "Timing is characterization only; no speed gate exists, Rust slower is acceptable, "
        "and results are machine-specific."
    )


def _write_json(
    results: list[BatchScenarioResult],
    environment: dict[str, object],
    path: str,
    *,
    warmup: int,
    samples: int,
) -> None:
    payload = {
        "environment": environment,
        "config": {"warmup": warmup, "samples": samples},
        "paths": {
            "python_individual": "N full Authorizer.authorize calls (per-request policy compile)",
            "python_batch": "one BatchAuthorizer.authorize (one shared session/policy resolution)",
            "rust_batch": (
                "one RustBatchAuthorizer.authorize (conversion + native compile + one PyO3 "
                "batch crossing + result mapping)"
            ),
        },
        "scenarios": [
            {
                "scenario": result.scenario.name,
                "description": result.scenario.description,
                "batch_size": result.scenario.batch_size,
                "permission_count": result.scenario.permission_count,
                "python_individual_median_ns": result.median("python_individual_samples"),
                "python_batch_median_ns": result.median("python_batch_samples"),
                "rust_batch_median_ns": result.median("rust_batch_samples"),
                "python_individual_iqr_ns": result._stats("python_individual_samples")[3],
                "python_batch_iqr_ns": result._stats("python_batch_samples")[3],
                "rust_batch_iqr_ns": result._stats("rust_batch_samples")[3],
                "python_individual_min_ns": min(result.python_individual_samples),
                "python_batch_min_ns": min(result.python_batch_samples),
                "rust_batch_min_ns": min(result.rust_batch_samples),
                "python_individual_max_ns": max(result.python_individual_samples),
                "python_batch_max_ns": max(result.python_batch_samples),
                "rust_batch_max_ns": max(result.rust_batch_samples),
                "python_batch_over_python_individual_ratio": result.ratio(
                    "python_batch_samples", "python_individual_samples"
                ),
                "rust_batch_over_python_batch_ratio": result.ratio(
                    "rust_batch_samples", "python_batch_samples"
                ),
                "rust_batch_over_python_individual_ratio": result.ratio(
                    "rust_batch_samples", "python_individual_samples"
                ),
                "python_individual_samples_ns": result.python_individual_samples,
                "python_batch_samples_ns": result.python_batch_samples,
                "rust_batch_samples_ns": result.rust_batch_samples,
            }
            for result in results
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"JSON results written to {path}")


_REQUIRED_JSON_FIELDS = {
    "scenario",
    "batch_size",
    "permission_count",
    "python_individual_median_ns",
    "python_batch_median_ns",
    "rust_batch_median_ns",
    "python_individual_iqr_ns",
    "python_batch_iqr_ns",
    "rust_batch_iqr_ns",
    "python_batch_over_python_individual_ratio",
    "rust_batch_over_python_batch_ratio",
    "rust_batch_over_python_individual_ratio",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--warmup", type=int, default=20, help="warmup passes per path per scenario"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=15,
        help="timed samples per path per scenario (>=7 for the release campaign)",
    )
    parser.add_argument(
        "--json", metavar="PATH", help="also write machine-readable results to PATH"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="tiny-count verification: native availability, construction, parity, timing loop, "
        "and human/JSON output; no timing assertion",
    )
    args = parser.parse_args(argv)

    if args.smoke:
        args.warmup = 1
        args.samples = 2
    if args.warmup < 0 or args.samples < 1:
        parser.error("--warmup must be >= 0 and --samples must be >= 1")

    import tempfile

    json_path = args.json
    if args.smoke and json_path is None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="mtmf-batch-bench-smoke-"
        ) as handle:
            json_path = handle.name

    environment = _environment()
    scenarios = _build_scenarios()
    if not scenarios:
        raise SystemExit("no benchmark scenarios were constructed")

    results = [
        _run_scenario(scenario, warmup=args.warmup, samples=args.samples) for scenario in scenarios
    ]
    _render_human(results, environment, warmup=args.warmup, samples=args.samples)
    if json_path:
        _write_json(results, environment, json_path, warmup=args.warmup, samples=args.samples)
        if args.smoke:
            with open(json_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            assert set(payload) == {"environment", "config", "paths", "scenarios"}, sorted(payload)
            assert len(payload["scenarios"]) == len(scenarios), len(payload["scenarios"])
            for scenario in payload["scenarios"]:
                assert set(scenario) >= _REQUIRED_JSON_FIELDS, sorted(
                    _REQUIRED_JSON_FIELDS - set(scenario)
                )
            print("smoke mode: JSON output validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
