#!/usr/bin/env python3
"""Reproducible P/R/M1/M2 permission-evaluator benchmark (PR 8F).

The benchmark compares four independent evaluator paths over identical
pre-built domain inputs:

    P   PermissionEvaluator                (Python semantic reference)
    R   RustPermissionEvaluator            (production/default; URN-text boundary)
    M1  MsgspecEvaluator("encode")         (experimental msgspec semantic buffer)
    M2  MsgspecEvaluator("encode_into")    (experimental msgspec reusable buffer)

Correctness is checked before timing: for EVERY scenario all four
implementation decisions must be fully equal (effect, ``allowed``,
deny reason, matched specificity, ``matched allow/deny``) and the
benchmark aborts on any parity failure or missing native/msgspec
capability. Timing is informational only: no speed threshold exists,
and a scenario where a candidate is slower is a valid result.

Measurements, per scenario:

- end-to-end medians for P, R, M1, M2 (all per-call work is inside the
  timed loop; the msgspec paths build the wire DTOs and encode **inside**
  the loop, never from a pre-encoded payload);
- component medians (separately labeled, never presented as
  production-comparable):
    C1 domain -> semantic wire DTO conversion;
    C2 msgspec ordinary ``encode``;
    C3 msgspec ``encode_into`` into a reusable buffer;
    C4 pre-encoded payload -> native decode/evaluate/result conversion.

Ratios are defined as ``baseline_median / candidate_median``: a value
> 1.0 means the candidate implementation was faster **in this
environment and scenario**. Any result is characterizable; nothing is a
gate.

CLI:

    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \\
        --warmup 100 --samples 20 --iterations 1000
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --extended
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --json /tmp/bench.json
    uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --smoke

``--extended`` adds the 5000-Permission scaling scenarios (they are
excluded from routine runs). ``--smoke`` verifies native/msgspec
availability, fixture construction, four-way parity, timing-loop
execution, and human/JSON output serialization with tiny counts. It
asserts no timing threshold.
"""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from functools import partial

from msgspec_evaluator import MsgspecEvaluator, native_build_profile
from msgspec_wire import build_payload

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
from mtmf_core.authorization.rust_engine import RustEngineUnavailableError
from mtmf_core.authorization.rust_engine import engine_version as native_engine_version
from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator

_NATIVE_MODULE_NAME = "_mtmf_permission_engine"


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


def _scale_role(permissions_total: int, *, matching: bool) -> Role:
    """One deterministic Role totaling exactly ``permissions_total`` Permissions.

    Permissions are spread over sets of 10 (the last set absorbs the
    remainder, so tiny totals still form valid non-empty sets). The
    pattern cycles exact/wildcard/non-match deterministically.
    """
    role_urn = RoleUrn("urn:mtmf:iam:roles:system:bench-scale")
    per_set = 10
    sets = []
    remaining = permissions_total
    set_index = 0
    while remaining > 0:
        count = min(per_set, remaining)
        rules: list[tuple[str, str]] = []
        for perm_index in range(count):
            choice = (set_index * 7 + perm_index) % 3
            if choice == 0:
                rules.append(("set", "active") if matching else ("get", "object"))
            elif choice == 1:
                rules.append(("set", "*") if matching else ("set", "alias"))
            else:
                rules.append(("get", "object") if matching else ("delete", "object"))
        sets.append(_permission_set(role_urn, PermissionEffect.ALLOW, tuple(rules)))
        remaining -= count
        set_index += 1
    return Role(role_urn, "bench-scale", "", None, tuple(sets))


def _build_scenarios(*, extended: bool) -> list[Scenario]:
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
    # Deterministic Permission-count scaling coverage (PR 8F section 18).
    for count in (1, 25, 200, 1000):
        scenarios.append(
            Scenario(
                name=f"scale_{count}",
                description=f"single role with exactly {count} Permissions",
                action=action,
                roles=(_scale_role(count, matching=True),),
                sets_count=(count + 9) // 10,
                permissions_count=count,
            )
        )
    scenarios.append(
        Scenario(
            name="scale_1000_full_scan",
            description="1000-Permission full scan ending in NO_MATCH",
            action=action,
            roles=(_scale_role(1000, matching=False),),
            sets_count=100,
            permissions_count=1000,
        )
    )
    if extended:
        scenarios.append(
            Scenario(
                name="scale_5000",
                description="single role with exactly 5000 Permissions (extended)",
                action=action,
                roles=(_scale_role(5000, matching=True),),
                sets_count=500,
                permissions_count=5000,
            )
        )
        scenarios.append(
            Scenario(
                name="scale_5000_full_scan",
                description="5000-Permission full scan ending in NO_MATCH (extended)",
                action=action,
                roles=(_scale_role(5000, matching=False),),
                sets_count=500,
                permissions_count=5000,
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


class _Evaluators:
    """The four independent evaluator implementations measured by PR 8F."""

    def __init__(self) -> None:
        self.python = PermissionEvaluator()
        self.rust = RustPermissionEvaluator()
        self.m1 = MsgspecEvaluator("encode")
        self.m2 = MsgspecEvaluator("encode_into")


def _load_semantic_native() -> object:
    """Import the private native module (semantic entry point must exist)."""
    try:
        module = importlib.import_module(_NATIVE_MODULE_NAME)
    except ImportError as exc:
        raise SystemExit(
            f"private native module {_NATIVE_MODULE_NAME!r} is unavailable; "
            "run `./build.sh --rust` first"
        ) from exc
    if not callable(getattr(module, "evaluate_semantic_msgpack", None)):
        raise SystemExit(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose "
            "'evaluate_semantic_msgpack'; run `./build.sh --rust` to rebuild"
        )
    return module


def _check_parity(evaluators: _Evaluators, scenario: Scenario) -> None:
    """Evaluate once per implementation and require exact decision equality."""
    try:
        python_decision = evaluators.python.evaluate(scenario.action, scenario.roles)
        rust_decision = evaluators.rust.evaluate(scenario.action, scenario.roles)
        m1_decision = evaluators.m1.evaluate(scenario.action, scenario.roles)
        m2_decision = evaluators.m2.evaluate(scenario.action, scenario.roles)
    except RustEngineUnavailableError as exc:
        raise SystemExit(
            f"private native module is unavailable for scenario {scenario.name!r}; "
            "run `./build.sh --rust` first"
        ) from exc
    implementations = {
        "python": python_decision,
        "rust": rust_decision,
        "m1": m1_decision,
        "m2": m2_decision,
    }
    for name, decision in implementations.items():
        if not _full_decision_equality(python_decision, decision):
            raise SystemExit(
                f"P/R/M1/M2 parity failure in scenario {scenario.name!r}: "
                f"python={python_decision!r} {name}={decision!r}; timing is aborted"
            )


def _measure_call(call: object, iterations: int) -> float:
    """One timed sample: mean nanoseconds per call."""
    start = time.perf_counter_ns()
    for _ in range(iterations):
        call()  # type: ignore[operator]
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
class ComponentResult:
    """Per-scenario component (non end-to-end) timing outcome."""

    domain_to_wire_samples: list[float] = field(default_factory=list)
    encode_samples: list[float] = field(default_factory=list)
    encode_into_samples: list[float] = field(default_factory=list)
    pre_encoded_native_samples: list[float] = field(default_factory=list)

    @property
    def domain_to_wire_ns(self) -> float:
        return statistics.median(self.domain_to_wire_samples)

    @property
    def encode_ns(self) -> float:
        return statistics.median(self.encode_samples)

    @property
    def encode_into_ns(self) -> float:
        return statistics.median(self.encode_into_samples)

    @property
    def pre_encoded_native_ns(self) -> float:
        return statistics.median(self.pre_encoded_native_samples)


@dataclass
class ScenarioResult:
    """Per-scenario timing outcome (informational; never a correctness gate)."""

    scenario: Scenario
    python_samples: list[float] = field(default_factory=list)
    rust_samples: list[float] = field(default_factory=list)
    m1_samples: list[float] = field(default_factory=list)
    m2_samples: list[float] = field(default_factory=list)
    components: ComponentResult = field(default_factory=ComponentResult)
    python_median_ns: float = 0.0
    rust_median_ns: float = 0.0
    m1_median_ns: float = 0.0
    m2_median_ns: float = 0.0

    @staticmethod
    def _ratio(baseline_ns: float, candidate_ns: float) -> float:
        """>1.0 means the candidate is faster than the baseline in this environment."""
        if candidate_ns == 0:
            return float("inf")
        return baseline_ns / candidate_ns

    @property
    def ratio_rust_over_python(self) -> float:
        return self._ratio(self.python_median_ns, self.rust_median_ns)

    @property
    def ratio_m1_over_python(self) -> float:
        return self._ratio(self.python_median_ns, self.m1_median_ns)

    @property
    def ratio_m2_over_python(self) -> float:
        return self._ratio(self.python_median_ns, self.m2_median_ns)

    @property
    def ratio_m1_over_rust(self) -> float:
        return self._ratio(self.rust_median_ns, self.m1_median_ns)

    @property
    def ratio_m2_over_rust(self) -> float:
        return self._ratio(self.rust_median_ns, self.m2_median_ns)


def _run_scenario(
    evaluators: _Evaluators,
    scenario: Scenario,
    *,
    warmup: int,
    samples: int,
    iterations: int,
) -> ScenarioResult:
    _check_parity(evaluators, scenario)

    # Pre-build the prior-stage component fixtures OUTSIDE all timed
    # regions (PR 8F section 22): wire DTO for encode timing, encoded
    # payload for native decode/evaluate timing. The end-to-end msgspec
    # paths still rebuild the payload + encode inside each timed call.
    m1 = evaluators.m1
    m2 = evaluators.m2
    wire = build_payload(scenario.action, scenario.roles)
    pre_encoded = m1.encoder.encode(wire)
    native = _load_semantic_native()

    # Warmup every implementation path before any sampling.
    for _ in range(warmup):
        evaluators.python.evaluate(scenario.action, scenario.roles)
        evaluators.rust.evaluate(scenario.action, scenario.roles)
        m1.evaluate(scenario.action, scenario.roles)
        m2.evaluate(scenario.action, scenario.roles)
        build_payload(scenario.action, scenario.roles)
        m1.encoder.encode(wire)
        m2.encoder.encode_into(wire, m2.buffer)
        native.evaluate_semantic_msgpack(pre_encoded)

    result = ScenarioResult(scenario)
    implementations = [evaluators.python, evaluators.rust, m1, m2]
    for sample_index in range(samples):
        # Alternate which implementation is measured first so no side is
        # systematically favored by order effects.
        order = [(sample_index + offset) % 4 for offset in range(4)]
        for position in order:
            implementation = implementations[position]
            call = partial(implementation.evaluate, scenario.action, scenario.roles)
            elapsed = _measure_call(call, iterations)
            if position == 0:
                result.python_samples.append(elapsed)
            elif position == 1:
                result.rust_samples.append(elapsed)
            elif position == 2:
                result.m1_samples.append(elapsed)
            else:
                result.m2_samples.append(elapsed)
    # Component samples (alternate C2/C3/C4 so the encode variants do
    # not systematically run first).
    for sample_index in range(samples):
        for position in [(sample_index + offset) % 3 for offset in range(3)]:
            if position == 0:
                elapsed = _measure_call(
                    lambda: build_payload(scenario.action, scenario.roles), iterations
                )
                result.components.domain_to_wire_samples.append(elapsed)
            elif position == 1:
                elapsed = _measure_call(lambda: m1.encoder.encode(wire), iterations)
                result.components.encode_samples.append(elapsed)
            else:
                elapsed = _measure_call(lambda: m2.encoder.encode_into(wire, m2.buffer), iterations)
                result.components.encode_into_samples.append(elapsed)
    # C4: pre-encoded payload -> native decode/evaluate (labeled as
    # component-only; never a production-comparable end-to-end number).
    for _ in range(warmup):
        native.evaluate_semantic_msgpack(pre_encoded)
    for _ in range(samples):
        result.components.pre_encoded_native_samples.append(
            _measure_call(lambda: native.evaluate_semantic_msgpack(pre_encoded), iterations)
        )

    result.python_median_ns = statistics.median(result.python_samples)
    result.rust_median_ns = statistics.median(result.rust_samples)
    result.m1_median_ns = statistics.median(result.m1_samples)
    result.m2_median_ns = statistics.median(result.m2_samples)
    return result


def _environment() -> dict[str, str]:
    try:
        engine_version = native_engine_version()
        build_profile = native_build_profile()
    except RustEngineUnavailableError:
        engine_version = "<unavailable>"
        build_profile = "<unavailable>"
    try:
        import msgspec

        msgspec_version = msgspec.__version__
    except ImportError:
        msgspec_version = "<unavailable>"
    return {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "rust_engine_version": engine_version,
        "native_build_profile": build_profile,
        "msgspec_version": msgspec_version,
        "python_evaluator": PermissionEvaluator.__module__,
        "rust_evaluator": RustPermissionEvaluator.__module__,
        "ratio_direction": "baseline_median / candidate_median: > 1.0 means the "
        "candidate (denominator) was faster in this environment",
    }


def _format_ns(value: float) -> str:
    if value == float("inf"):
        return "inf"
    return f"{value:.0f}"


def _format_ratio(value: float) -> str:
    if value == float("inf"):
        return "inf"
    return f"{value:.2f}x"


def _render_human(
    results: list[ScenarioResult],
    environment: dict[str, str],
    *,
    warmup: int,
    samples: int,
    iterations: int,
    extended: bool,
) -> None:
    print("MTMF permission-evaluator benchmark (Python vs current Rust vs msgspec M1/M2)")
    print("Environment:")
    for key, value in environment.items():
        print(f"  {key}: {value}")
    print(
        f"  config: warmup={warmup} samples={samples} iterations={iterations} "
        f"extended={extended} (median primary; characterization only)"
    )
    header = "scenario | sets/perms | P | R | M1 | M2 | R/P | M1/P | M2/P | M1/R | M2/R"
    print(header)
    print("-" * len(header))
    for result in results:
        scenario = result.scenario
        print(
            f"{scenario.name:<20} "
            f"{scenario.sets_count:>4}/{scenario.permissions_count:>5} "
            f"{_format_ns(result.python_median_ns):>10} "
            f"{_format_ns(result.rust_median_ns):>10} "
            f"{_format_ns(result.m1_median_ns):>10} "
            f"{_format_ns(result.m2_median_ns):>10} "
            f"{_format_ratio(result.ratio_rust_over_python):>6} "
            f"{_format_ratio(result.ratio_m1_over_python):>6} "
            f"{_format_ratio(result.ratio_m2_over_python):>6} "
            f"{_format_ratio(result.ratio_m1_over_rust):>6} "
            f"{_format_ratio(result.ratio_m2_over_rust):>6}"
        )
    print()
    component_header = (
        "scenario | C1 domain->wire | C2 encode | C3 encode_into | C4 pre-encoded native"
    )
    print(component_header)
    print("-" * len(component_header))
    for result in results:
        components = result.components
        print(
            f"{result.scenario.name:<20} "
            f"{_format_ns(components.domain_to_wire_ns):>14} "
            f"{_format_ns(components.encode_ns):>10} "
            f"{_format_ns(components.encode_into_ns):>14} "
            f"{_format_ns(components.pre_encoded_native_ns):>20}"
        )
    print()
    print(
        "Ratios are baseline_median / candidate_median; > 1.0 means the candidate "
        "(denominator) was faster. Components are labeled separately and are never "
        "production-comparable. Timing is characterization only; no speed gate "
        "exists. Results are machine-specific."
    )


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
                "m1_median_ns": result.m1_median_ns,
                "m2_median_ns": result.m2_median_ns,
                "ratio_python_over_rust": result.ratio_rust_over_python,
                "ratio_m1_over_python": result.ratio_m1_over_python,
                "ratio_m2_over_python": result.ratio_m2_over_python,
                "ratio_m1_over_rust": result.ratio_m1_over_rust,
                "ratio_m2_over_rust": result.ratio_m2_over_rust,
                "python_samples": result.python_samples,
                "rust_samples": result.rust_samples,
                "m1_samples": result.m1_samples,
                "m2_samples": result.m2_samples,
                "python_dispersion": _dispersion(result.python_samples),
                "rust_dispersion": _dispersion(result.rust_samples),
                "m1_dispersion": _dispersion(result.m1_samples),
                "m2_dispersion": _dispersion(result.m2_samples),
                "components": {
                    "domain_to_wire_ns": result.components.domain_to_wire_ns,
                    "encode_ns": result.components.encode_ns,
                    "encode_into_ns": result.components.encode_into_ns,
                    "pre_encoded_native_ns": result.components.pre_encoded_native_ns,
                    "domain_to_wire_dispersion": _dispersion(
                        result.components.domain_to_wire_samples
                    ),
                    "encode_dispersion": _dispersion(result.components.encode_samples),
                    "encode_into_dispersion": _dispersion(result.components.encode_into_samples),
                    "pre_encoded_native_dispersion": _dispersion(
                        result.components.pre_encoded_native_samples
                    ),
                },
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
        "--extended",
        action="store_true",
        help="include the 5000-Permission scaling scenarios (excluded from routine runs)",
    )
    parser.add_argument(
        "--json", metavar="PATH", help="also write machine-readable results to PATH"
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="tiny-count verification: native/msgspec availability, construction, four-way "
        "parity, timing loops, and human/JSON output; no timing assertion",
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

    evaluators = _Evaluators()
    environment = _environment()
    scenarios = _build_scenarios(extended=args.extended)
    if not scenarios:
        raise SystemExit("no benchmark scenarios were constructed")

    results = [
        _run_scenario(
            evaluators,
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
        extended=args.extended,
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
                "m1_median_ns",
                "m2_median_ns",
                "ratio_python_over_rust",
                "ratio_m1_over_python",
                "ratio_m2_over_python",
                "ratio_m1_over_rust",
                "ratio_m2_over_rust",
                "components",
            }
            for scenario in payload["scenarios"]:
                assert required <= set(scenario), sorted(required - set(scenario))
                assert set(scenario["components"]) >= {
                    "domain_to_wire_ns",
                    "encode_ns",
                    "encode_into_ns",
                    "pre_encoded_native_ns",
                }
            assert "msgspec_version" in payload["environment"]
            assert "native_build_profile" in payload["environment"]
            print("smoke mode: JSON output validated")
    # A benchmark result is not an authorization correctness result: the
    # only failure modes are parity/native/msgspec/config/format failures.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
