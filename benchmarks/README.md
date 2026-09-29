# MTMF permission-evaluator benchmark (Python vs Rust)

Reproducible benchmark harness for the domain-facing evaluator seam.

## Scope

The primary comparison is exactly the seam the `Authorizer` uses today:

    PermissionEvaluator.evaluate(action, roles)      # Python semantic reference
    RustPermissionEvaluator.evaluate(action, roles)  # active/default

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