# PR 19 Performance Report

**PR:** roadmap PR 19.
**Date:** 2026-10-13.
**Status:** **NOT EXECUTED.**

## What is required

A controlled comparison of the same fixed authorization workload against:
pre-PR-19 baseline, PR 19 instrumentation disabled, PR 19 enabled with a
healthy Collector, and PR 19 enabled with an unavailable Collector. Fixed
concurrency and batch sizes `{1, 10, 50}` (or the real v1 maximum), warmup
≥ 30 s, measurement ≥ 120 s, ≥ 3 runs per mode, steady-state medians and full
p50/p95/p99, throughput, CPU, RSS, and OTel drops/queue. Initial targets:
≤ 5% throughput degradation and ≤ 10% p99 increase for healthy telemetry
versus the equivalent baseline.

## Why it was not executed

The benchmark harness, the real observability stack, and a controlled
machine/seed were not available in this implementation cycle. No timing
claim is made; in particular, no "instrumentation is free" claim is
supported by evidence.

## Design properties that bound the risk (not a substitute for measurement)

- Disabled telemetry constructs no exporter, thread, or network client.
- Event emission is one OTel log record per completed request; there is no
  per-Action synchronous PostgreSQL insert and no per-Action log fanout.
- Metrics are bounded counters/histograms with closed enums.
- Export runs on the SDK's bounded batch processors; the request path only
  enqueues, and a full queue drops (bounded) rather than blocking.
- The service never waits for export during a request.

## How to run it

Record `docs/pr-artifacts/pr-19/PR19_PERFORMANCE_REPORT.md` with the raw
machine-readable results before PR 19 can be marked DONE. If the ≤5% / ≤10%
targets are exceeded, STOP for review rather than disabling required events.
