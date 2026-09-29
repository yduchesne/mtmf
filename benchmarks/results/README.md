# PR 8F benchmark result evidence

This directory records the machine-readable benchmark JSON produced for
the PR 8F completion report. The numbers are **characterization only,
strictly machine-specific**, and are part of the experiment's honest
record — they are not a correctness gate and never a speed threshold.

| File | Native build | Scenarios | Campaign |
|---|---|---|---|
| `release_default.json` | release | 14 (no 5000-Permission) | `--samples 9 --iterations 300` |
| `release_extended.json` | release | 16 (includes `scale_5000`, `scale_5000_full_scan`) | `--extended --samples 7 --iterations 150` |
| `debug_default.json` | debug | 14 (no 5000-Permission) | `--samples 9 --iterations 300` |

All files record `environment` (Python version, platform/machine, Rust
engine version, `native_build_profile`, `msgspec_version`), per-scenario
P/R/M1/M2 medians and dispersions, the five `baseline/candidate`
ratios, and the four separately labeled component measurements (C1
domain-to-wire, C2 encode, C3 encode_into, C4 pre-encoded native).

Reproduction:

1. `uv sync --locked`;
2. build/install the native engine (debug: `maturin develop`; release:
   `maturin build --release` + install into an isolated environment with
   `msgspec` installed);
3. `python benchmarks/permission_evaluator_benchmark.py --json <out>`
   (extended campaign: add `--extended`);
4. confirm the recorded `native_build_profile` matches the build under
   test before drawing conclusions.

See `benchmarks/README.md` for the full methodology and the completion
report in the PR for the interpreted findings.