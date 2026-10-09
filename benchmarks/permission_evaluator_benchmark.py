#!/usr/bin/env python3
"""Reproducible Python-vs-Rust permission-evaluator benchmark.

The primary comparison is the retained linear evaluator seam (since
PR 8H the production :class:`~mtmf_core.authorization.authorizer.Authorizer`
path is the pure-Python indexed ``CompiledPolicy`` through
``DefaultAuthorizationPolicyResolver``, not this seam):

    PermissionEvaluator.evaluate(action, roles)          # Python semantic reference
    RustPermissionEvaluator.evaluate(action, roles)      # experimental, non-default

with identical pre-built domain inputs. That intentionally measures the
whole meaningful path: Role/PermissionSet traversal, domain-to-primitive
conversion, PyO3 overhead, Rust parse/match/evaluation, and mapping back
to :class:`AuthorizationDecision`.

Correctness is checked before timing: for EVERY scenario the Python and
Rust decisions must be fully equal (effect, allowed, reason, matched
specificity, matched allow/deny) and the benchmark aborts on any parity
failure or unavailable native module. Timing is informational only: no
speed threshold exists, a scenario where Rust is slower is a valid
result (PyO3/conversion overhead can dominate tiny policy), and no
generalization beyond this machine is claimed.

CLI:

    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \\
        --warmup 100 --samples 20 --iterations 1000
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --json /tmp/bench.json
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --smoke

``--smoke`` verifies native availability, fixture construction,
parity-before-timing, timing-loop execution, and human/JSON output
serialization with tiny counts. It asserts no timing threshold.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field

from mtmf_core import (
    Action,
    ActionUrn,
    AuthorizationDecision,
    DomainId,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Role,
    RoleUrn,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator
from mtmf_core.authorization.rust_engine import (
    RustEngineUnavailableError,
)
from mtmf_core.authorization.rust_engine import (
    engine_version as native_engine_version,
)
from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator


@dataclass(frozen=True)
class Scenario:
    """A deterministic pre-built policy scenario with a fixed evaluation.

    The Action/Roles/PermissionSets/Permissions are constructed once,
    outside any timed region, and never mutated.
    """

    name: str
    description: str
    action: Action
    roles: tuple[Role, ...]
    sets_count: int
    permissions_count: int


def _permission_text(verb: str, qualifier: str) -> str:
    return f"urn:mtmf:iam:permissions:system:principal:{verb}-{qualifier}"


def _role(name_suffix: str, sets: tuple[PermissionSet, ...]) -> Role:
    urn = RoleUrn(f"urn:mtmf:iam:roles:system:bench-{name_suffix}")
    return Role(urn, f"benchmark-{name_suffix}", "", None, sets)


def _permission_set(
    role_urn: RoleUrn, effect: PermissionEffect, rules: tuple[tuple[str, str], ...]
) -> PermissionSet:
    set_id = DomainId.generate()
    permissions = tuple(
        Permission(DomainId.generate(), set_id, PermissionUrn(_permission_text(verb, qualifier)))
        for verb, qualifier in rules
    )
    return PermissionSet(set_id, role_urn, effect, permissions)


def _role_with_sets(
    role_index: int,
    *,
    sets_per_role: int,
    perms_per_set: int,
    matching: bool,
    late_match: bool = False,
) -> Role:
    """Build one deterministic Role of ``sets_per_role`` PermissionSets.

    Each Permission cycles through exact-match, wildcard-match, and
    non-match patterns (deterministic from ``role_index``). ``matching``
    controls whether the family targets the benchmark Action
    ``set-active``; ``late_match`` moves the only match to the very last
    Permission so the whole policy is scanned before a decision.
    """
    role_urn = RoleUrn(f"urn:mtmf:iam:roles:system:bench-r{role_index}")
    sets = []
    for set_index in range(sets_per_role):
        rules: list[tuple[str, str]] = []
        for perm_index in range(perms_per_set):
            if late_match:
                rules.append(("get", "object"))
            else:
                choice = (role_index * 13 + set_index * 7 + perm_index) % 3
                if choice == 0:
                    rules.append(("set", "active") if matching else ("get", "object"))
                elif choice == 1:
                    rules.append(("set", "*") if matching else ("set", "alias"))
                else:
                    rules.append(("get", "object") if matching else ("delete", "object"))
        sets.append(_permission_set(role_urn, PermissionEffect.ALLOW, tuple(rules)))
    if late_match:
        last_set = sets[-1]
        set_id = last_set.id
        permissions = list(last_set.permissions)
        permissions[-1] = Permission(
            DomainId.generate(), set_id, PermissionUrn(_permission_text("set", "active"))
        )
        sets[-1] = PermissionSet(set_id, role_urn, last_set.effect, tuple(permissions))
    return Role(role_urn, f"bench-r{role_index}", "", None, tuple(sets))


def _build_scenarios() -> list[Scenario]:
    """Build every deterministic scenario once (never inside timed regions)."""
    action = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:set-active"))
    scenarios: list[Scenario] = []

    scenarios.append(
        Scenario(
            name="no_roles",
            description="fixed call overhead / default deny",
            action=action,
            roles=(),
            sets_count=0,
            permissions_count=0,
        )
    )
    # tiny: 1 Role, 1-2 sets, 1 Permission.
    scenarios.append(
        Scenario(
            name="tiny_exact",
            description="minimal successful exact match",
            action=action,
            roles=(_role_with_sets(0, sets_per_role=1, perms_per_set=1, matching=True),),
            sets_count=1,
            permissions_count=1,
        )
    )
    scenarios.append(
        Scenario(
            name="tiny_wildcard",
            description="single wildcard match path",
            action=action,
            roles=(_role_with_sets(1, sets_per_role=1, perms_per_set=1, matching=True),),
            sets_count=1,
            permissions_count=1,
        )
    )
    wildcard_role = _role(
        "tiny-conflict",
        (
            _permission_set(
                RoleUrn("urn:mtmf:iam:roles:system:bench-tiny-conflict"),
                PermissionEffect.ALLOW,
                (("set", "active"),),
            ),
            _permission_set(
                RoleUrn("urn:mtmf:iam:roles:system:bench-tiny-conflict"),
                PermissionEffect.DENY,
                (("set", "active"),),
            ),
        ),
    )
    scenarios.append(
        Scenario(
            name="tiny_equal_conflict",
            description="equal-specificity DENY precedence",
            action=action,
            roles=(wildcard_role,),
            sets_count=2,
            permissions_count=2,
        )
    )
    # small: 2 Roles, 5 sets total, 25 Permissions.
    scenarios.append(
        Scenario(
            name="small",
            description="modest realistic policy",
            action=action,
            roles=(
                _role_with_sets(0, sets_per_role=3, perms_per_set=5, matching=True),
                _role_with_sets(1, sets_per_role=2, perms_per_set=5, matching=True),
            ),
            sets_count=5,
            permissions_count=25,
        )
    )
    # medium: 5 Roles, 20 sets total, 200 Permissions.
    scenarios.append(
        Scenario(
            name="medium",
            description="amortizes FFI overhead",
            action=action,
            roles=tuple(
                _role_with_sets(index, sets_per_role=4, perms_per_set=10, matching=True)
                for index in range(5)
            ),
            sets_count=20,
            permissions_count=200,
        )
    )
    # large: 10 Roles, 100 sets total, 1000 Permissions.
    scenarios.append(
        Scenario(
            name="large",
            description="scaling characterization",
            action=action,
            roles=tuple(
                _role_with_sets(index, sets_per_role=10, perms_per_set=10, matching=True)
                for index in range(10)
            ),
            sets_count=100,
            permissions_count=1000,
        )
    )
    # large full scan: 1000 non-matching Permissions.
    scenarios.append(
        Scenario(
            name="large_no_match",
            description="full scan ending in NO_MATCH",
            action=action,
            roles=tuple(
                _role_with_sets(index, sets_per_role=10, perms_per_set=10, matching=False)
                for index in range(10)
            ),
            sets_count=100,
            permissions_count=1000,
        )
    )
    # late match: only the 1000th Permission matches (full traversal).
    scenarios.append(
        Scenario(
            name="late_match",
            description="full-policy scan with a late exact match",
            action=action,
            roles=(
                _role_with_sets(
                    0, sets_per_role=10, perms_per_set=100, matching=True, late_match=True
                ),
            ),
            sets_count=10,
            permissions_count=1000,
        )
    )
    return scenarios


def _full_decision_equality(
    python_decision: AuthorizationDecision, rust_decision: AuthorizationDecision
) -> bool:
    """Complete policy-evidence equality (never only ``allowed``)."""
    return (
        python_decision == rust_decision
        and python_decision.allowed == rust_decision.allowed
        and python_decision.effect == rust_decision.effect
        and python_decision.reason == rust_decision.reason
        and python_decision.matched_specificity == rust_decision.matched_specificity
        and python_decision.matched_allow == rust_decision.matched_allow
        and python_decision.matched_deny == rust_decision.matched_deny
    )


def _check_parity(
    evaluator_python: PermissionEvaluator,
    evaluator_rust: RustPermissionEvaluator,
    scenario: Scenario,
) -> None:
    """Evaluate once per implementation and require exact decision equality."""
    try:
        python_decision = evaluator_python.evaluate(scenario.action, scenario.roles)
        rust_decision = evaluator_rust.evaluate(scenario.action, scenario.roles)
    except RustEngineUnavailableError as exc:
        raise SystemExit(
            f"private native module is unavailable for scenario {scenario.name!r}; "
            "run `./build.sh --rust` first"
        ) from exc
    if not _full_decision_equality(python_decision, rust_decision):
        raise SystemExit(
            f"Python/Rust parity failure in scenario {scenario.name!r}: "
            f"python={python_decision!r} rust={rust_decision!r}; timing is aborted"
        )


def _measure(
    evaluator: PermissionEvaluator | RustPermissionEvaluator,
    scenario: Scenario,
    iterations: int,
) -> float:
    """One timed sample: mean nanoseconds per evaluation call."""
    start = time.perf_counter_ns()
    for _ in range(iterations):
        evaluator.evaluate(scenario.action, scenario.roles)
    elapsed = time.perf_counter_ns() - start
    return elapsed / iterations


def _dispersion(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))
    return {
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
        "stdev_ns": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
        "p95_ns": ordered[p95_index],
    }


@dataclass
class ScenarioResult:
    """Per-scenario timing outcome (informational; never a correctness gate)."""

    scenario: Scenario
    python_samples: list[float] = field(default_factory=list)
    rust_samples: list[float] = field(default_factory=list)

    @property
    def python_median_ns(self) -> float:
        return statistics.median(self.python_samples)

    @property
    def rust_median_ns(self) -> float:
        return statistics.median(self.rust_samples)

    @property
    def ratio_python_over_rust(self) -> float:
        """>1.0 means Rust is faster in this environment for this scenario."""
        if self.rust_median_ns == 0:
            return float("inf")
        return self.python_median_ns / self.rust_median_ns


def _run_scenario(
    evaluator_python: PermissionEvaluator,
    evaluator_rust: RustPermissionEvaluator,
    scenario: Scenario,
    *,
    warmup: int,
    samples: int,
    iterations: int,
) -> ScenarioResult:
    _check_parity(evaluator_python, evaluator_rust, scenario)
    _measure(evaluator_python, scenario, warmup)
    _measure(evaluator_rust, scenario, warmup)
    result = ScenarioResult(scenario)
    for sample_index in range(samples):
        # Alternate the measured implementation first so one side is not
        # systematically favored by order effects.
        if sample_index % 2 == 0:
            result.python_samples.append(_measure(evaluator_python, scenario, iterations))
            result.rust_samples.append(_measure(evaluator_rust, scenario, iterations))
        else:
            result.rust_samples.append(_measure(evaluator_rust, scenario, iterations))
            result.python_samples.append(_measure(evaluator_python, scenario, iterations))
    return result


def _environment() -> dict[str, str]:
    try:
        engine_version = native_engine_version()
    except RustEngineUnavailableError:
        engine_version = "<unavailable>"
    return {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "rust_engine_version": engine_version,
        "python_evaluator": PermissionEvaluator.__module__,
        "rust_evaluator": RustPermissionEvaluator.__module__,
    }


def _render_human(
    results: list[ScenarioResult],
    environment: dict[str, str],
    *,
    warmup: int,
    samples: int,
    iterations: int,
) -> None:
    print("MTMF permission-evaluator benchmark (Python vs Rust)")
    print("Environment:")
    for key, value in environment.items():
        print(f"  {key}: {value}")
    print(
        f"  config: warmup={warmup} samples={samples} iterations={iterations} "
        "(median primary; characterization only)"
    )
    header = (
        "scenario | policy size | python median | rust median | "
        "ratio (py/rust) | dispersion (py stdev/max, rust stdev/max)"
    )
    print(header)
    print("-" * len(header))
    for result in results:
        scenario = result.scenario
        py_disp = _dispersion(result.python_samples)
        rust_disp = _dispersion(result.rust_samples)
        ratio = result.ratio_python_over_rust
        ratio_text = f"{ratio:.2f}x" if result.rust_median_ns > 0 else "inf"
        print(
            f"{scenario.name:<16} "
            f"{scenario.sets_count:>4} sets/{scenario.permissions_count:>5} perms "
            f"{result.python_median_ns:>12.0f} ns "
            f"{result.rust_median_ns:>12.0f} ns "
            f"{ratio_text:>13} "
            f"{py_disp['stdev_ns']:>10.0f}/{py_disp['max_ns']:>10.0f} "
            f"{rust_disp['stdev_ns']:>10.0f}/{rust_disp['max_ns']:>10.0f}"
        )
    print("Timing is characterization only; no speed gate exists. Results are machine-specific.")


def _write_json(results: list[ScenarioResult], environment: dict[str, str], path: str) -> None:
    payload = {
        "environment": environment,
        "scenarios": [
            {
                "name": result.scenario.name,
                "description": result.scenario.description,
                "sets_count": result.scenario.sets_count,
                "permissions_count": result.scenario.permissions_count,
                "python_median_ns": result.python_median_ns,
                "rust_median_ns": result.rust_median_ns,
                "ratio_python_over_rust": result.ratio_python_over_rust,
                "python_samples": result.python_samples,
                "rust_samples": result.rust_samples,
                "python_dispersion": _dispersion(result.python_samples),
                "rust_dispersion": _dispersion(result.rust_samples),
            }
            for result in results
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"JSON results written to {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--warmup", type=int, default=20, help="warmup evaluations per implementation per scenario"
    )
    parser.add_argument(
        "--samples", type=int, default=10, help="timed samples per implementation per scenario"
    )
    parser.add_argument("--iterations", type=int, default=200, help="evaluations per timed sample")
    parser.add_argument(
        "--json", metavar="PATH", help="also write machine-readable results to PATH"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="tiny-count verification: native availability, construction, parity, "
        "timing loop, and human/JSON output; no timing assertion",
    )
    args = parser.parse_args(argv)

    if args.smoke:
        args.warmup = 2
        args.samples = 3
        args.iterations = 5
    if args.warmup < 0 or args.samples < 1 or args.iterations < 1:
        parser.error("--warmup must be >= 0 and --samples/--iterations must be >= 1")

    import tempfile

    # Smoke mode always exercises the JSON serialization path (to a
    # temporary file when no explicit --json path was given) and
    # validates that the result parses back as the expected shape.
    json_path = args.json
    if args.smoke and json_path is None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="mtmf-bench-smoke-"
        ) as handle:
            json_path = handle.name

    evaluator_python = PermissionEvaluator()
    evaluator_rust = RustPermissionEvaluator()
    environment = _environment()
    scenarios = _build_scenarios()
    if not scenarios:
        raise SystemExit("no benchmark scenarios were constructed")

    results = [
        _run_scenario(
            evaluator_python,
            evaluator_rust,
            scenario,
            warmup=args.warmup,
            samples=args.samples,
            iterations=args.iterations,
        )
        for scenario in scenarios
    ]
    _render_human(
        results,
        environment,
        warmup=args.warmup,
        samples=args.samples,
        iterations=args.iterations,
    )
    if json_path:
        _write_json(results, environment, json_path)
        if args.smoke:
            with open(json_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            assert set(payload) == {"environment", "scenarios"}, sorted(payload)
            assert len(payload["scenarios"]) == len(scenarios), len(payload["scenarios"])
            required = {
                "name",
                "sets_count",
                "permissions_count",
                "python_median_ns",
                "rust_median_ns",
                "ratio_python_over_rust",
            }
            for scenario in payload["scenarios"]:
                assert required <= set(scenario), sorted(required - set(scenario))
            print("smoke mode: JSON output validated")
    # A benchmark result is not an authorization correctness result: the
    # only failure modes are parity/native/config/format failures.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
