#!/usr/bin/env python3
"""Compiled-policy benchmark: compile-once vs repeated evaluation (PR 8G).

PR 8G tests an architectural hypothesis: compile already-applicable
Role policy once into an opaque immutable native indexed representation
(the private ``_mtmf_permission_engine.compile_policy`` object), then
evaluate many Actions without repeatedly traversing Roles/PermissionSets,
transferring policy, parsing Permission URNs, or scanning all
Permissions.

This harness measures, for the SAME deterministic scenarios:

- the production Python reference evaluator (``PermissionEvaluator``);
- the current Rust evaluator (``RustPermissionEvaluator``, the
  production default);
- the experimental compiled-policy evaluator
  (``CompiledPolicyEvaluator.compile`` once, then repeated
  ``evaluate``);
- the one-time native compile cost;
- the lifecycle cost: compile + 1/10/100/1000 evaluations;
- the unrelated-policy scaling diagnostic (25/200/1000/5000 unrelated
  Permissions characterized separately for exact hit, wildcard-only hit,
  and no-match - compiled evaluation is expected to be approximately
  independent of unrelated policy size; if it grows linearly, there is a
  hidden scan).

The deterministic multi-Action workload per scale scenario contains
exact hits, wildcard-only hits, wildcard DENY, and no-matches; repeated
evaluation is never benchmarked on only one identical Action (the
preserved PR 8E scenarios keep their single Action unchanged).

Correctness is checked before timing: for EVERY scenario the Python,
current-Rust, and compiled decisions must be fully equal (effect,
allowed, reason, matched specificity, matched allow/deny) and the
benchmark aborts on any parity failure or unavailable native module.
Timing is informational only: no speed threshold exists, ratios are
reported with an explicit direction, and no generalization beyond this
machine is claimed.

CLI:

    uv run --no-sync python benchmarks/compiled_policy_benchmark.py
    uv run --no-sync python benchmarks/compiled_policy_benchmark.py \\
        --extended --warmup 100 --samples 20
    uv run --no-sync python benchmarks/compiled_policy_benchmark.py \\
        --json /tmp/compiled-policy-bench.json --extended

``--extended`` adds the 5000-Permission scale and diagnostic scenarios.
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

from compiled_policy_evaluator import CompiledPolicyEvaluator
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

# Reuse the PR 8E scenario fixtures unchanged so the 8G benchmark runs
# against exactly the same policy as the 8E characterization.
from permission_evaluator_benchmark import _build_scenarios as _build_8e_scenarios

# Deterministic multi-Action workload reused by the scale scenarios: one
# exact hit, one wildcard-only hit, one wildcard DENY, and two
# no-matches (including a resource mismatch).
_ACTION_SET_ACTIVE = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:set-active"))
_ACTION_SET_ALIAS = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:set-alias"))
_ACTION_GET_OBJECT = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:get-object"))
_ACTION_DELETE_OBJECT = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:delete-object"))
_ACTION_TENANT_SET_ACTIVE = Action(ActionUrn("urn:mtmf:iam:actions:system:tenant:set-active"))
_MULTI_ACTION_WORKLOAD = (
    _ACTION_SET_ACTIVE,
    _ACTION_SET_ALIAS,
    _ACTION_GET_OBJECT,
    _ACTION_DELETE_OBJECT,
    _ACTION_TENANT_SET_ACTIVE,
)

# Deterministic policy scales for the compile/eval scaling family.
_EXTENDED_SCALE = 5000
_SCALE_PERMISSION_COUNTS = (1, 25, 200, 1000, 5000)

# Unrelated-policy diagnostic sizes.
_DIAGNOSTIC_SIZES = (25, 200, 1000, 5000)


@dataclass(frozen=True)
class Scenario:
    """A deterministic pre-built scenario with a fixed Action workload.

    ``actions`` is the deterministic evaluation sequence (exact hits,
    wildcard-only hits, no-match, mixed effects where applicable; a
    single-element sequence for the preserved PR 8E scenarios). All
    fixtures are constructed once, outside any timed region, and never
    mutated.
    """

    name: str
    description: str
    actions: tuple[Action, ...]
    roles: tuple[Role, ...]
    sets_count: int
    permissions_count: int
    kind: str


def _perm_text(resource: str, verb: str, qualifier: str) -> str:
    return f"urn:mtmf:iam:permissions:system:{resource}:{verb}-{qualifier}"


def _role(name_suffix: str, sets: tuple[PermissionSet, ...]) -> Role:
    urn = RoleUrn(f"urn:mtmf:iam:roles:system:bench-{name_suffix}")
    return Role(urn, f"benchmark-{name_suffix}", "", None, sets)


def _permission_set(
    role_urn: RoleUrn, effect: PermissionEffect, rules: tuple[tuple[str, str, str], ...]
) -> PermissionSet:
    """Build a PermissionSet of (resource, verb, qualifier) rules."""
    set_id = DomainId.generate()
    permissions = tuple(
        Permission(
            DomainId.generate(), set_id, PermissionUrn(_perm_text(resource, verb, qualifier))
        )
        for resource, verb, qualifier in rules
    )
    return PermissionSet(set_id, role_urn, effect, permissions)


def _unrelated_exact_rules(count: int) -> tuple[tuple[str, str, str], ...]:
    """Return ``count`` distinct unrelated exact-matcher rules.

    Resource ``filler`` with verb ``f{index//100}`` and qualifier
    ``q{index%100}``: every key is distinct for ``index`` in
    ``[0, 5000)`` and never collides with the query family
    (``principal``/``tenant`` resources and the ``set``/``get`` verbs).
    """
    return tuple(("filler", f"f{index // 100}", f"q{index % 100}") for index in range(count))


def _build_scale_roles(total_permissions: int) -> tuple[Role, ...]:
    """One Role mixing meaningful rules with unrelated exact fillers.

    The meaningful policy is:

    - ALLOW exact ``principal:set-active`` (exact hit on set-active);
    - ALLOW wildcard ``principal:get-*`` (wildcard-only hit on
      get-object);
    - DENY wildcard ``principal:set-*`` (wildcard DENY on set-alias,
      and lower specificity than the exact ALLOW on set-active).

    The remaining ``total_permissions - 3`` permissions are distinct
    unrelated exact ALLOW keys spread across PermissionSets of ~20
    permissions each, so the index scales with the unrelated count.

    ``total_permissions == 1`` special-cases to a single exact ALLOW so
    the smallest scale is genuinely one Permission.
    """
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:bench-scale")
    meaningful = (
        ("principal", "set", "active"),
        ("principal", "get", "*"),
        ("principal", "set", "*"),
    )
    if total_permissions == 1:
        return (
            _role(
                "scale",
                (_permission_set(role_urn, PermissionEffect.ALLOW, (meaningful[0],)),),
            ),
        )
    sets: list[PermissionSet] = [
        _permission_set(role_urn, PermissionEffect.ALLOW, (meaningful[0], meaningful[1])),
        _permission_set(role_urn, PermissionEffect.DENY, (meaningful[2],)),
    ]
    filler_rules = _unrelated_exact_rules(max(0, total_permissions - 3))
    for offset in range(0, len(filler_rules), 20):
        sets.append(
            _permission_set(role_urn, PermissionEffect.ALLOW, filler_rules[offset : offset + 20])
        )
    return (_role("scale", tuple(sets)),)


def _build_diagnostic_roles(total_permissions: int, outcome: str) -> tuple[Role, ...]:
    """One Role of ``total_permissions`` Permissions with a fixed outcome.

    ``outcome`` is one of ``"exact"`` (a matching exact ALLOW embedded),
    ``"wildcard"`` (a matching wildcard ALLOW embedded), or
    ``"nomatch"`` (successfully nothing matches). Every other Permission
    is a distinct exact ALLOW key unrelated to the queried Action, so
    compiled evaluation must be ~independent of the unrelated count.
    """
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:bench-diag")
    matching = {
        "exact": (("principal", "set", "active"),),
        "wildcard": (("principal", "set", "*"),),
        "nomatch": (),
    }[outcome]
    filler_rules = _unrelated_exact_rules(max(0, total_permissions - len(matching)))
    rules = (*matching, *filler_rules)
    sets = [_permission_set(role_urn, PermissionEffect.ALLOW, rules)]
    return (_role("diag", tuple(sets)),)


def _wrap_8e_scenarios() -> list[Scenario]:
    """Preserve the PR 8E scenarios unchanged (same action and roles)."""
    wrapped: list[Scenario] = []
    for base in _build_8e_scenarios():
        wrapped.append(
            Scenario(
                name=base.name,
                description=base.description,
                actions=(base.action,),
                roles=base.roles,
                sets_count=base.sets_count,
                permissions_count=base.permissions_count,
                kind="8e",
            )
        )
    return wrapped


def _policy_counts(roles: tuple[Role, ...]) -> tuple[int, int]:
    sets_total = sum(len(role.permission_sets) for role in roles)
    perms_total = sum(
        len(permission_set.permissions) for role in roles for permission_set in role.permission_sets
    )
    return sets_total, perms_total


def _build_scenarios(*, extended: bool) -> list[Scenario]:
    """Build every deterministic scenario once (never inside timed regions)."""
    scenarios = _wrap_8e_scenarios()

    for permission_count in _SCALE_PERMISSION_COUNTS:
        if permission_count == _EXTENDED_SCALE and not extended:
            continue
        roles = _build_scale_roles(permission_count)
        sets_count, perms_count = _policy_counts(roles)
        scenarios.append(
            Scenario(
                name=f"scale_{permission_count}",
                description=(
                    f"mixed-policy scale with {permission_count} Permissions "
                    "(exact hit, wildcard hit, wildcard DENY, no-match)"
                ),
                actions=_MULTI_ACTION_WORKLOAD,
                roles=roles,
                sets_count=sets_count,
                permissions_count=perms_count,
                kind="scale",
            )
        )

    for size in _DIAGNOSTIC_SIZES:
        if size == _EXTENDED_SCALE and not extended:
            continue
        for outcome in ("exact", "wildcard", "nomatch"):
            roles = _build_diagnostic_roles(size, outcome)
            sets_count, perms_count = _policy_counts(roles)
            scenarios.append(
                Scenario(
                    name=f"diag_{size}_{outcome}",
                    description=(
                        f"{size} Permissions, majority unrelated; queried Action outcome: {outcome}"
                    ),
                    actions=(_ACTION_SET_ACTIVE,),
                    roles=roles,
                    sets_count=sets_count,
                    permissions_count=perms_count,
                    kind=f"diag-{outcome}",
                )
            )
    return scenarios


def _full_decision_equality(left: AuthorizationDecision, right: AuthorizationDecision) -> bool:
    """Complete policy-evidence equality (never only ``allowed``)."""
    return (
        left == right
        and left.allowed == right.allowed
        and left.effect == right.effect
        and left.reason == right.reason
        and left.matched_specificity == right.matched_specificity
        and left.matched_allow == right.matched_allow
        and left.matched_deny == right.matched_deny
    )


def _check_parity(scenario: Scenario) -> None:
    """Require P == R == C complete-decision equality before timing."""
    python_evaluator = PermissionEvaluator()
    rust_evaluator = RustPermissionEvaluator()
    compiled = CompiledPolicyEvaluator.compile(scenario.roles)
    try:
        for action in scenario.actions:
            python_decision = python_evaluator.evaluate(action, scenario.roles)
            rust_decision = rust_evaluator.evaluate(action, scenario.roles)
            compiled_decision = compiled.evaluate(action)
    except RustEngineUnavailableError as exc:
        raise SystemExit(
            f"private native module is unavailable for scenario {scenario.name!r}; "
            "run `./build.sh --rust` first"
        ) from exc
    if not (
        _full_decision_equality(python_decision, rust_decision)
        and _full_decision_equality(python_decision, compiled_decision)
    ):
        raise SystemExit(
            f"P/R/C parity failure in scenario {scenario.name!r} for {action.urn.value!r}: "
            f"python={python_decision!r} rust={rust_decision!r} "
            f"compiled={compiled_decision!r}; timing is aborted"
        )


def _measure_python(evaluator: PermissionEvaluator, scenario: Scenario) -> float:
    """One full workload pass in nanoseconds (Python reference)."""
    start = time.perf_counter_ns()
    for action in scenario.actions:
        evaluator.evaluate(action, scenario.roles)
    return time.perf_counter_ns() - start


def _measure_rust(evaluator: RustPermissionEvaluator, scenario: Scenario) -> float:
    """One full workload pass in nanoseconds (current Rust evaluator)."""
    start = time.perf_counter_ns()
    for action in scenario.actions:
        evaluator.evaluate(action, scenario.roles)
    return time.perf_counter_ns() - start


def _measure_compiled(compiled: CompiledPolicyEvaluator, scenario: Scenario) -> float:
    """One full workload pass in nanoseconds (compiled-policy evaluator)."""
    start = time.perf_counter_ns()
    for action in scenario.actions:
        compiled.evaluate(action)
    return time.perf_counter_ns() - start


def _measure_compiled_native(compiled: object, scenario: Scenario) -> float:
    """Repeated native-only compiled evaluation (no domain conversion or mapping)."""
    start = time.perf_counter_ns()
    for action in scenario.actions:
        compiled.evaluate(action.urn.value)
    return time.perf_counter_ns() - start


def _measure_compile_ns(scenario: Scenario) -> float:
    start = time.perf_counter_ns()
    CompiledPolicyEvaluator.compile(scenario.roles)
    return time.perf_counter_ns() - start


def _measure_compile_plus_n(scenario: Scenario, evaluations: int) -> float:
    """One compile plus ``evaluations`` full workload passes."""
    start = time.perf_counter_ns()
    compiled = CompiledPolicyEvaluator.compile(scenario.roles)
    for _ in range(evaluations):
        for action in scenario.actions:
            compiled.evaluate(action)
    return time.perf_counter_ns() - start


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
    compiled_samples: list[float] = field(default_factory=list)
    compiled_native_samples: list[float] = field(default_factory=list)
    compile_samples: list[float] = field(default_factory=list)
    compile_plus_1_samples: list[float] = field(default_factory=list)
    compile_plus_10_samples: list[float] = field(default_factory=list)
    compile_plus_100_samples: list[float] = field(default_factory=list)
    compile_plus_1000_samples: list[float] = field(default_factory=list)

    def median(self, name: str) -> float:
        return statistics.median(getattr(self, name))

    @property
    def python_median_ns(self) -> float:
        return self.median("python_samples")

    @property
    def rust_median_ns(self) -> float:
        return self.median("rust_samples")

    @property
    def compiled_median_ns(self) -> float:
        return self.median("compiled_samples")

    def ratio(self, baseline_samples: str) -> float:
        """``baseline / compiled``; ``>1.0`` means compiled is faster."""
        if self.compiled_median_ns == 0:
            return float("inf")
        return self.median(baseline_samples) / self.compiled_median_ns

    def break_even(self, baseline_samples: str) -> float | None:
        """``N* = compile_cost / (baseline_cost - compiled_cost)``.

        Reports the number of evaluations at which ``compile + N*eval``
        equals ``N*eval`` on the baseline. Returns ``None`` when the
        math is not meaningful (compiled evaluation is not faster than
        the baseline).
        """
        compile_cost = self.median("compile_samples")
        baseline = self.median(baseline_samples)
        delta = baseline - self.compiled_median_ns
        if delta <= 0:
            return None
        return compile_cost / delta


def _run_scenario(scenario: Scenario, *, warmup: int, samples: int) -> ScenarioResult:
    _check_parity(scenario)
    python_evaluator = PermissionEvaluator()
    rust_evaluator = RustPermissionEvaluator()
    compiled = CompiledPolicyEvaluator.compile(scenario.roles)

    for _ in range(warmup):
        _measure_python(python_evaluator, scenario)
        _measure_rust(rust_evaluator, scenario)
        _measure_compiled(compiled, scenario)
        _measure_compile_ns(scenario)

    result = ScenarioResult(scenario)
    for sample_index in range(samples):
        # Rotate the measured implementation order across samples so one
        # side is never systematically favored by order effects.
        if sample_index % 3 == 0:
            py_ns = _measure_python(python_evaluator, scenario)
            rust_ns = _measure_rust(rust_evaluator, scenario)
            compiled_ns = _measure_compiled(compiled, scenario)
        elif sample_index % 3 == 1:
            rust_ns = _measure_rust(rust_evaluator, scenario)
            compiled_ns = _measure_compiled(compiled, scenario)
            py_ns = _measure_python(python_evaluator, scenario)
        else:
            compiled_ns = _measure_compiled(compiled, scenario)
            py_ns = _measure_python(python_evaluator, scenario)
            rust_ns = _measure_rust(rust_evaluator, scenario)
        result.python_samples.append(py_ns)
        result.rust_samples.append(rust_ns)
        result.compiled_samples.append(compiled_ns)
        result.compiled_native_samples.append(_measure_compiled_native(compiled.compiled, scenario))
        result.compile_samples.append(_measure_compile_ns(scenario))
        result.compile_plus_1_samples.append(_measure_compile_plus_n(scenario, 1))
        result.compile_plus_10_samples.append(_measure_compile_plus_n(scenario, 10))
        result.compile_plus_100_samples.append(_measure_compile_plus_n(scenario, 100))
        result.compile_plus_1000_samples.append(_measure_compile_plus_n(scenario, 1000))
    return result


def _environment() -> dict[str, str]:
    try:
        version = native_engine_version()
    except RustEngineUnavailableError:
        version = "<unavailable>"
    return {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "rust_engine_version": version,
    }


def _render_human(
    results: list[ScenarioResult],
    environment: dict[str, str],
    *,
    warmup: int,
    samples: int,
) -> None:
    print("MTMF compiled-policy benchmark (Python vs current Rust vs compiled; PR 8G)")
    print("Environment:")
    for key, value in environment.items():
        print(f"  {key}: {value}")
    print(
        f"  config: warmup={warmup} samples={samples} "
        "median primary over deterministic workload passes; characterization only"
    )
    print(
        "  ratio direction: compiled_vs_python = python/compiled; "
        "compiled_vs_current_rust = current_rust/compiled; >1.0 means compiled is faster"
    )
    header = (
        "scenario | perms/sets | python median | current rust median | compiled median | "
        "compile median | c/py | c/rust | break-even(py) | break-even(rust)"
    )
    print(header)
    print("-" * len(header))
    for result in results:
        scenario = result.scenario
        ratio_py = result.ratio("python_samples")
        ratio_rust = result.ratio("rust_samples")
        be_py = result.break_even("python_samples")
        be_rust = result.break_even("rust_samples")
        be_py_text = f"{be_py:.0f}" if be_py is not None else "none"
        be_rust_text = f"{be_rust:.0f}" if be_rust is not None else "none"
        print(
            f"{scenario.name:<18} "
            f"{scenario.permissions_count:>5}/{scenario.sets_count:>3} "
            f"{result.python_median_ns:>13.0f} "
            f"{result.rust_median_ns:>13.0f} "
            f"{result.compiled_median_ns:>13.0f} "
            f"{result.median('compile_samples'):>11.0f} "
            f"{ratio_py:>6.2f}x "
            f"{ratio_rust:>6.2f}x "
            f"{be_py_text:>15} "
            f"{be_rust_text:>18}"
        )
    print("Timing is characterization only; no speed gate exists. Results are machine-specific.")


def _write_json(results: list[ScenarioResult], environment: dict[str, str], path: str) -> None:
    payload = {
        "environment": environment,
        "scenarios": [
            {
                "scenario": result.scenario.name,
                "description": result.scenario.description,
                "kind": result.scenario.kind,
                "permission_count": result.scenario.permissions_count,
                "permission_set_count": result.scenario.sets_count,
                "action_count": len(result.scenario.actions),
                "python_eval_median_ns": result.python_median_ns,
                "current_rust_eval_median_ns": result.rust_median_ns,
                "compiled_eval_median_ns": result.compiled_median_ns,
                "compiled_native_eval_median_ns": result.median("compiled_native_samples"),
                "compile_median_ns": result.median("compile_samples"),
                "compile_plus_1_median_ns": result.median("compile_plus_1_samples"),
                "compile_plus_10_median_ns": result.median("compile_plus_10_samples"),
                "compile_plus_100_median_ns": result.median("compile_plus_100_samples"),
                "compile_plus_1000_median_ns": result.median("compile_plus_1000_samples"),
                "compiled_vs_python_ratio": result.ratio("python_samples"),
                "compiled_vs_current_rust_ratio": result.ratio("rust_samples"),
                "break_even_vs_python": result.break_even("python_samples"),
                "break_even_vs_current_rust": result.break_even("rust_samples"),
                "python_eval_dispersion": _dispersion(result.python_samples),
                "current_rust_eval_dispersion": _dispersion(result.rust_samples),
                "compiled_eval_dispersion": _dispersion(result.compiled_samples),
                "compile_dispersion": _dispersion(result.compile_samples),
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
        "--warmup", type=int, default=20, help="warmup passes per implementation per scenario"
    )
    parser.add_argument(
        "--samples", type=int, default=10, help="timed samples per implementation per scenario"
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help="include the 5000-Permission scale and diagnostic scenarios",
    )
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
        args.warmup = 1
        args.samples = 2
    if args.warmup < 0 or args.samples < 1:
        parser.error("--warmup must be >= 0 and --samples must be >= 1")

    import tempfile

    json_path = args.json
    if args.smoke and json_path is None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="mtmf-compiled-bench-smoke-"
        ) as handle:
            json_path = handle.name

    environment = _environment()
    scenarios = _build_scenarios(extended=args.extended)
    if not scenarios:
        raise SystemExit("no benchmark scenarios were constructed")

    results = [
        _run_scenario(scenario, warmup=args.warmup, samples=args.samples) for scenario in scenarios
    ]
    _render_human(results, environment, warmup=args.warmup, samples=args.samples)
    if json_path:
        _write_json(results, environment, json_path)
        if args.smoke:
            with open(json_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            assert set(payload) == {"environment", "scenarios"}, sorted(payload)
            assert len(payload["scenarios"]) == len(scenarios), len(payload["scenarios"])
            required = {
                "scenario",
                "permission_count",
                "permission_set_count",
                "python_eval_median_ns",
                "current_rust_eval_median_ns",
                "compiled_eval_median_ns",
                "compile_median_ns",
                "compile_plus_1_median_ns",
                "compile_plus_10_median_ns",
                "compile_plus_100_median_ns",
                "compile_plus_1000_median_ns",
                "compiled_vs_python_ratio",
                "compiled_vs_current_rust_ratio",
                "break_even_vs_python",
                "break_even_vs_current_rust",
            }
            for scenario in payload["scenarios"]:
                assert required <= set(scenario), sorted(required - set(scenario))
            print("smoke mode: JSON output validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
