# MTMF permission-evaluator benchmark (Python vs Rust vs msgspec M1/M2)

Reproducible benchmark harness for the domain-facing evaluator seam.

> **EXPERIMENTAL (PR 8F).** The msgspec paths (M1/M2) measure an
> alternative FFI representation for a deliberately isolated
> performance experiment. They are NOT the production authorization
> path, there is no runtime backend selection, and they are removable
> without changing production semantics. `msgspec` is a
> development/experimental dependency only.

## Scope

PR 8F compares four independent evaluator paths over identical pre-built
domain inputs:

    P   PermissionEvaluator                Python semantic reference
    R   RustPermissionEvaluator            production/default (URN-text boundary)
    M1  MsgspecEvaluator("encode")         experimental msgspec semantic buffer
    M2  MsgspecEvaluator("encode_into")    experimental msgspec reusable buffer

The experimental paths replace the current Rust FFI's nested
`list[tuple[str, list[str]]]` transfer and Rust-side URN reparsing with
a single MessagePack payload carrying **already-parsed semantic
components** (namespace, resource, verb, qualifier, explicit wildcard
flag) — never complete MTMF Action/Permission URN texts. The payload is
a versioned positional schema (`msgspec.Struct, array_like=True`; see
`benchmarks/msgspec_wire.py`) decoded by the private native entry point
`_mtmf_permission_engine.evaluate_semantic_msgpack`, which converges on
the same canonical decision loop as the production URN path (`evaluator.rs`).

## Correctness before timing

For every scenario the harness evaluates once with each implementation
and requires complete `AuthorizationDecision` equality (effect,
`allowed`, deny reason, matched specificity, `matched_allow`,
`matched_deny`) before any timed sample: P == R == M1 == M2. A parity
failure, an unavailable native/msgspec capability, or an invalid
configuration aborts the run.

Malformed wire data (empty/truncated payloads, random bytes, wrong
top-level type, missing fields, unsupported versions, unknown effects,
invalid wildcard state, invalid component types, bounded excessive
nesting) fails explicitly with `ValueError` at the native boundary and
is never ALLOW, NO_MATCH, or MATCHED_DENY.

## Scenarios

### Mandatory unchanged PR 8E scenarios

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

### PR 8F scaling scenarios

| Scenario | Policy size | Notes |
|---|---|---|
| `scale_1` | 1 perm | exact-count coverage |
| `scale_25` | 25 perms | exact-count coverage |
| `scale_200` | 200 perms | exact-count coverage |
| `scale_1000` | 1000 perms | exact-count coverage |
| `scale_1000_full_scan` | 1000 perms | full scan, NO_MATCH |
| `scale_5000` | 5000 perms | `--extended` only |
| `scale_5000_full_scan` | 5000 perms | `--extended` only |

These are benchmark scales, not MTMF limits. The 5000-Permission
scenarios are excluded from routine runs and gated behind `--extended`.

## Usage

```bash
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \
  --warmup 100 --samples 20 --iterations 1000
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --extended
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py \
  --json /tmp/mtmf-permission-benchmark.json
uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --smoke
```

- `--warmup` evaluations per implementation per scenario (default 20);
- `--samples` timed samples per implementation per scenario (default 10);
- `--iterations` evaluations per timed sample (default 200);
- `--extended` adds the 5000-Permission scaling scenarios;
- `--json PATH` writes the full machine-readable result set;
- `--smoke` verifies native/msgspec availability, fixture construction,
  four-way parity, timing-loop execution, component measurement, and
  human/JSON output formatting with tiny counts. It asserts no timing
  threshold.

`sources`: `benchmarks/msgspec_wire.py` (positional semantic wire
schema + domain-to-wire conversion) and `benchmarks/msgspec_evaluator.py`
(experimental adapter wrapping encode + PyO3 + validation/mapping).

## Measurements

### End-to-end (production-comparable)

All per-call work is inside the timed loop:

- P: `PermissionEvaluator.evaluate(action, roles)`;
- R: `RustPermissionEvaluator.evaluate(action, roles)` — domain-to-primitive
  conversion + PyO3 + URN parsing + evaluation;
- M1: domain → wire DTOs → `Encoder.encode` → one PyO3 call → Rust
  MessagePack decode → evaluation → result mapping;
- M2: same, but `Encoder.encode_into` a reused `bytearray` (msgspec
  truncates it to the message length, retaining capacity) instead of a
  fresh `bytes` allocation.

The msgspec end-to-end measurement NEVER starts from a pre-encoded
payload, and every evaluation transfers the full policy (no
compiled-policy handle, no caching).

### Components (separately labeled, never production-comparable)

| Id | Measured work | Fixture built outside timing |
|---|---|---|
| C1 | domain → semantic wire DTO conversion | domain objects |
| C2 | msgspec ordinary `encode` | wire DTO |
| C3 | msgspec `encode_into` (reusable buffer) | wire DTO |
| C4 | pre-encoded payload → native decode/evaluate/result | MessagePack payload |

C4 is explicitly a pre-encoded/native component result; it excludes the
Python-side conversion and encoding costs and must never be presented as
the production-comparable msgspec number.

## Methodology

- `time.perf_counter_ns()` from the standard library; `statistics` for
  aggregation (no external benchmark dependency).
- All implementations are warmed up before sampling.
- Multiple samples per implementation; the **median** is the primary
  summary; min/max/stdev/p95 are reported as dispersion.
- The measured implementation order rotates across samples so no side is
  systematically favored by order effects.
- No single-observation claims and no false nanosecond precision.

**Ratios** are defined unambiguously as
`baseline_median / candidate_median`: a value `> 1.0` means the
candidate (the denominator) was faster **in this environment and
scenario**. The JSON records `ratio_rust_over_python`,
`ratio_m1_over_python`, `ratio_m2_over_python`, `ratio_m1_over_rust`,
and `ratio_m2_over_rust` (the historical field
`ratio_python_over_rust` is kept as an alias of
`ratio_rust_over_python`).

## Output

Human output includes the environment (Python version, platform,
machine, Rust engine version, **native build profile**, **msgspec
version**, evaluator modules, ratio direction) and, per scenario, the
policy size, P/R/M1/M2 medians, the five ratios, the four component
medians, and dispersion. `--json` writes the same data
machine-readably.

## Release build requirement

Debug (`maturin develop`) and optimized release native builds can differ
materially. Performance conclusions must be based primarily on an
optimized **release** wheel, and the output must distinguish them: the
benchmark records `native_build_profile` (`"debug"` or `"release"` from
the native `build_profile()` capability). Do not present release Python
versus debug Rust as a headline comparison.

### Reproducing the release characterization

```bash
uv sync --locked                              # 1. canonical bootstrap
uv run --no-sync maturin build \
  --manifest-path packages/mtmf-permission-engine/Cargo.toml \
  --release --interpreter "$(uv run --no-sync python -c 'import sys; print(sys.executable)')" \
  --out /tmp/mtmf-release-wheel               # 2. build optimized wheel
uv run --no-sync python -m venv /tmp/mtmf-release-env
/tmp/mtmf-release-env/bin/python -m pip install /tmp/mtmf-release-wheel/*.whl
# 3. run against the release env (msgspec must be installed there too):
/tmp/mtmf-release-env/bin/python -m pip install msgspec
PYTHONPATH="$PWD/packages/mtmf-core/src:$PWD/packages/mtmf-api/src:$PWD/packages/mtmf-client/src:$PWD/packages/mtmf-service/src:$PWD/benchmarks" \
  /tmp/mtmf-release-env/bin/python benchmarks/permission_evaluator_benchmark.py --json /tmp/mtmf-release.json
# 4. verify the recorded native_build_profile is "release"
# 5. write the JSON result and record the environment
# 6. restore the canonical development environment (maturin develop)
```

The benchmark's own `native_build_profile` output line is the guard
against benchmarking a stale debug module accidentally.

## Timing is characterization, not a gate

A benchmark performance result is **not** an authorization correctness
result. No speed threshold exists: PyO3/conversion overhead can make the
native paths slower for tiny policy, and a scenario where msgspec is
slower is a valid result. Results are machine-specific and must not be
generalized into universal claims. Timing never justifies weakening
semantics; negative findings are recorded, not hidden. PR 8F is a
success if the experiment is correct, reproducible, fair, and honestly
documented — even if msgspec turns out slower.

## Non-goals (PR 8F)

The msgspec boundary does not change `Authorizer`, does not replace
`RustPermissionEvaluator`, adds no runtime backend selection, fallback,
caching, or compiled-policy handles, and is not exposed through
`mtmf-api`. The payload schema carries no complete Action/Permission
URNs, no numeric registries, no Role identity, and no authorization
context. No project-authored `unsafe` is used.