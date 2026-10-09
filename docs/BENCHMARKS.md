# MTMF permission-evaluator benchmark (Python vs Rust)

Reproducible benchmark harness for the domain-facing evaluator seam.

## Scope

The primary comparison is the retained linear evaluator seam (since
PR 8H the production `Authorizer` path is the pure-Python indexed
`CompiledPolicy` through `DefaultAuthorizationPolicyResolver`, not this
seam):

    PermissionEvaluator.evaluate(action, roles)      # Python semantic reference
    RustPermissionEvaluator.evaluate(action, roles)  # experimental, non-default

with identical pre-built domain inputs. This intentionally measures the
whole meaningful path: Role/PermissionSet traversal, domain-to-primitive
conversion, PyO3 overhead, Rust parse/match/evaluation, and mapping back
to `AuthorizationDecision`.

There is no native-kernel-only benchmark here. If one is ever added it
must be labeled separately and never presented as end-to-end evaluator
performance.

## Correctness before timing

For every scenario the harness evaluates once with Python and once with
Rust and requires complete `AuthorizationDecision` equality (effect,
`allowed`, deny reason, matched specificity, `matched_allow`,
`matched_deny`) before any timed sample. A parity failure, an
unavailable native module, or an invalid configuration aborts the run.

## Scenarios

| Scenario | Policy size | Purpose |
|---|---|---|
| `no_roles` | 0 sets / 0 perms | fixed call overhead / default deny |
| `tiny_exact` | 1 set / 1 perm | minimal successful exact match |
| `tiny_wildcard` | 1 set / 1 perm | wildcard path |
| `tiny_equal_conflict` | 2 sets / 2 perms | equal-specificity DENY precedence |
| `small` | 5 sets / 25 perms | modest realistic work |
| `medium` | 20 sets / 200 perms | amortize FFI overhead |
| `large` | 100 sets / 1000 perms | scaling characterization |
| `large_no_match` | 100 sets / 1000 perms | full scan, default deny |
| `late_match` | 10 sets / 1000 perms | full-policy scan with a late match |

Policy sizes are fixture scales, not product limits. All fixtures are
built outside timed regions; no UUID/policy is generated inside a timing
loop.

## Usage

```bash
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \
  --warmup 100 --samples 20 --iterations 1000
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \
  --json /tmp/mtmf-permission-benchmark.json
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --smoke
```

- `--warmup` evaluations per implementation per scenario (default 20);
- `--samples` timed samples per implementation per scenario (default 10);
- `--iterations` evaluations per timed sample (default 200);
- `--json PATH` writes the full machine-readable result set;
- `--smoke` verifies native availability, fixture construction,
  parity-before-timing, timing-loop execution, and human/JSON output
  formatting with tiny counts. It asserts no timing threshold.

## Methodology

- `time.perf_counter_ns()` from the standard library; `statistics`
  for aggregation (no external benchmark dependency).
- Both implementations are warmed up before sampling.
- Multiple samples per implementation; the **median** is the primary
  summary; min/max/stdev/p95 are reported as dispersion.
- The measured implementation order alternates across samples so one
  side is never systematically favored.
- No single-observation claims and no false nanosecond precision:
  report nanoseconds as rounded medians with dispersion.

## Output

Human output includes the environment (Python version, platform,
machine, Rust engine version, evaluator modules) and, per scenario, the
policy size, Python median, Rust median, ratio (Python/Rust; `>1.0`
means Rust was faster in this environment), and dispersion. `--json`
writes the same data machine-readably.

## Timing is characterization, not a gate

A benchmark performance result is **not** an authorization correctness
result. No speed threshold exists: PyO3/conversion overhead can make the
Rust path slower for tiny policy, and a scenario where Rust is slower is
a valid result. Results are machine-specific and must not be generalized
into universal claims. Timing never justifies weakening semantics; if
Rust is slower for some policies, record the result and optimize later
under a separately approved plan.

## Reproducing the canonical configuration

```bash
./build.sh --rust        # builds/installs the private native module the gate ships
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py
```

The canonical `./build.sh --rust` step installs the `maturin develop`
artifact. Characterizing the optimized `--release` wheel instead is an
explicit optional step (build with `maturin build --release`, install
into a scratch environment, run, then restore the canonical build); both
are characterization only and neither is part of CI.

## PR 8G experiment: compiled-policy benchmark

PR 8G (`dev/compiled-policy-perf`, branching directly from the PR 8E
baseline `af9daec`) is an independent, **experimental sibling** of PR 8F
and intentionally does not depend on PR 8F or msgspec. It tests a
different hypothesis: compile already-applicable policy **once** into an
indexed representation, then evaluate many Actions without repeatedly
traversing Roles/PermissionSets, transferring policy, parsing Permission
URNs, or scanning all Permissions.

The PR 8G amendment adds a pure-Python compiled-policy control so the
experiment separates the **algorithm/data-structure benefit** (compiling
and indexing the policy) from the **language/native-execution benefit**
(implementing the compiled evaluator in Rust).

Four paths are measured for the same deterministic scenarios:

```text
P   Python linear evaluator (PermissionEvaluator)
R   Rust linear evaluator (RustPermissionEvaluator)
PC  production Python CompiledPolicy (CompiledPolicy: compile once,
    pure-Python exact/wildcard index lookups; no FFI)
RC  Rust CompiledPolicy (CompiledPolicyEvaluator: compile once, native
    exact/wildcard index lookups; per-Action PyO3 call)
```

Experimental code and harness:

```text
mtmf_core.authorization.compiled_policy  # production PC implementation
benchmarks/compiled_policy_evaluator.py  # RC experimental adapter
benchmarks/compiled_policy_benchmark.py  # P/R/PC/RC harness
packages/mtmf-permission-engine/src/compiled_policy.rs  # native kernel
```

The production PC implementation mirrors the Rust `CompiledPolicy`
semantics: exact keys
`(namespace, resource, verb, qualifier)`, wildcard keys
`(namespace, resource, verb)`, pre-aggregated frozen
`EffectAggregate(matched_allow, matched_deny)`, duplicate collapse,
EXACT-beats-WILDCARD, equal-specificity DENY, default DENY, structural
ownership validation, and an immutable compiled representation (frozen
dataclass over `MappingProxyType` mappings). PC consumes the
already-parsed domain `PermissionUrn`/`ActionUrn` semantic components
directly (never stringify/reparse), so the PC/RC difference includes the
RC per-Action Action-URN transfer/parse and PyO3 crossing as real
architectural costs.

Usage:

```bash
uv run --no-sync python benchmarks/compiled_policy_benchmark.py
uv run --no-sync python benchmarks/compiled_policy_benchmark.py --extended \
  --warmup 100 --samples 20
uv run --no-sync python benchmarks/compiled_policy_benchmark.py \
  --json /tmp/mtmf-compiled-policy-bench.json --extended
uv run --no-sync python benchmarks/compiled_policy_benchmark.py --smoke
```

- preserves the PR 8E scenarios unchanged (no_roles, tiny_exact,
  tiny_wildcard, tiny_equal_conflict, small, medium, large,
  large_no_match, late_match);
- adds deterministic policy scales 1/25/200/1000/5000 Permissions in
  mixed multi-Action workloads (exact hit, wildcard-only hit, wildcard
  DENY, no-match);
- measures the one-time compile cost and the compile + 1/10/100/1000
  lifecycle cost for **both** PC and RC, and the repeated
  compiled-evaluation cost for both;
- characterizes unrelated-policy scaling (25/200/1000/5000, exact
  hit/wildcard-only hit/no-match) for PC and RC to detect any hidden
  full-policy scan;
- requires P == R == PC == RC complete-decision parity before every
  timing run, rotates the four-path measurement order across samples,
  reports median primary with dispersion, and records the environment;
  no timing correctness gate exists;
- ratios are defined as `baseline_time / candidate_time` (`>1.0` =
  candidate faster); for PC/RC the field is
  `python_compiled_time / rust_compiled_time` (`>1.0` = Rust compiled
  faster);
- `--extended` enables the 5000-Permission scenarios; `--smoke` verifies
  native availability, construction, four-way parity, timing-loop
  execution, and human/JSON output with tiny counts.

**Measured outcome (release build, WSL2 x86_64, Python 3.14.7):** both
compiled implementations beat their linear counterparts by large
factors (e.g. P/PC up to ~169x at 5000 Permissions; R/RC up to ~318x),
so compiling/indexing policy is the principal optimization,
independent of implementation language. In the same campaign, PC
evaluation beat RC evaluation in every scenario (PC/RC median ratio
~0.18-0.50x, meaning PC was ~2-5.5x faster per single-Action call),
and PC compiled faster than RC at every scale. RC's raw native lookup
cost is small; the per-Action PyO3 crossing, Action-URN
transfer/parse, and the Python-side native-result validation/mapping
overhead dominate. These results characterize this machine and this
architecture only. After PR 8H the production path adopts the
pure-Python indexed semantics as the production
:class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy` (PC);
the Rust compiled path (RC) remains experimental.

**Experimental status:** the RC Rust compiled adapter and the linear
Rust evaluator remain experimental and non-default. PR 8G was never a
production cutover; PR 8H productionizes the PC semantics as
``Authorizer() -> DefaultAuthorizationPolicyResolver ->
EffectivePolicy(CompiledPolicy, context) -> CompiledPolicy.evaluate(action)``
with no backend selection, environment-var selection, fallback, or
production cache. The benchmark harness measures P/R/PC/RC parity
before timing and remains runnable; results characterize an
architectural decision, and no speed gate exists.
