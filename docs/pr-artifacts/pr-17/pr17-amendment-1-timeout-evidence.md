# PR 17 — Amendment #1: timeout, concurrency and resource-lifetime evidence (G4)

**Scope:** `asyncio.wait_for(run_in_threadpool(...))` behavior, bounded
evaluation admission, permit lifetime, and cleanup.

## 1. Observed behavior (defect reproduced)

Starlette's `run_in_threadpool` uses `anyio.to_thread.run_sync` with
`abandon_on_cancel=True`. A controlled experiment (blocking worker, 2 s,
0.2 s deadline) showed:

```
run_in_threadpool timeout at 0.20
run_in_threadpool worker done at 2.11
anyio-abandon timeout at 0.20
anyio-abandon worker done at 2.00
```

So the HTTP response deadline **is** enforced (the response returns at 0.20 s)
but the synchronous worker is **abandoned, not stopped**, and keeps running to
completion. A second experiment filled the only anyio worker token, queued a
further `run_sync`, cancelled it at the deadline, and confirmed the queued
worker **never ran**:

```
queued timed out
queued started afterward: None
```

Conclusions:

1. `wait_for` is not a hard execution deadline; it only bounds the awaited
   result. A response deadline alone does not bound resource use.
2. A permit must not be released merely because the awaited call timed out: the
   worker may still be running.
3. A worker cancelled before it begins never runs, so a permit acquired before
   dispatch must be released by the transport when the worker never started.

## 2. Change

New module `mtmf_service.concurrency`:

- `EvaluationAdmission(max_in_flight)`: a thread-safe, process-local in-flight
  counter with `try_acquire()` (non-blocking, deterministic saturation) and
  `in_flight`/`peak_in_flight` observability.
- `EvaluationPermit`: `HELD -> RUNNING -> RELEASED` (or `HELD -> RELEASED`),
  idempotent release, with `mark_started()` and `release_if_not_started()`.

`mtmf_service.app` now:

1. acquires a permit before dispatch; saturation is an immediate
   `503 DEPENDENCY_UNAVAILABLE`;
2. runs the worker with `run_in_threadpool` (already abandon-on-cancel) and the
   worker releases the permit in a `finally` block **after** the synchronous
   evaluation returns;
3. on timeout/cancellation/exception, releases only via
   `release_if_not_started()`, so a running worker keeps its permit.

Configurable via `ServiceSettings.max_in_flight_evaluations`
(`MTMF_SERVICE_MAX_IN_FLIGHT_EVALUATIONS`, default 40).

**Residual race (documented):** if the deadline fires at the exact instant a
queued worker begins, the transport may release the permit while that worker
runs, transiently under-counting in-flight work by one. Peak over-admission is
therefore bounded by the number of simultaneous boundary races and never
unbounded. A fully race-free bound would require a dedicated bounded executor
and is explicitly deferred (plan G4.3 asks not to add a new executor without
reviewer agreement).

## 3. Deterministic tests (`tests/unit/service/test_concurrency.py`)

| Node | Proves |
| --- | --- |
| `test_a1_16_saturation_is_deterministic_503` | capacity 1: first blocks, second is a deterministic 503; releasing the first completes it with no ALLOW |
| `test_a1_17_timeout_retains_permit_until_worker_completes` | 0.1 s deadline: timed-out request is 503 with no ALLOW; the still-blocked worker keeps `in_flight == 1`; a subsequent request is 503; after worker release `in_flight == 0` and a later request is 200 |
| `test_a1_17_no_worker_runs_without_a_permit` | capacity 2 with 4 concurrent requests: exactly `[200, 200, 503, 503]`; `entered <= 2`; `peak <= 2` |
| `test_admission_unit_semantics` | idempotent release, `release_if_not_started` no-op for a running worker, `peak_in_flight` |
| `test_permit_release_if_not_started_releases_once` | never-started fallback releases once; later `release()` is a no-op |
| `test_admission_rejects_bad_capacity` | bad configuration rejected |

All six pass deterministically (no sleeps as the sole synchronization; a
`threading.Condition`/`Event` drive the workers).

## 4. Boundedness, cleanup and limits

- **Response/worker bound:** at most `max_in_flight_evaluations` workers are
  admitted at once; saturation fails fast instead of queueing.
- **No late ALLOW:** a timed-out request already returned a static 503 envelope;
  the abandoned worker's result is discarded and cannot write a second
  response.
- **No stale mutation:** evaluation is read-only with respect to authorization
  state, so a worker outliving the deadline cannot mutate bootstrap/authorization
  state.
- **DB sessions:** each `AuthorizationService.evaluate` uses `with
  spi.create_unit_of_work()`, so a worker that completes (even after the
  deadline) commits/rolls back and closes its session deterministically.
- **Retained caveat:** a synchronous worker cannot be forcibly interrupted.
  Downstream database statement/lock timeouts are not currently configurable
  through the MTMF runtime configuration; the bounded admission prevents
  unbounded accumulation but does not shorten an individual blocking call.
  This is recorded as a residual risk, not hidden by raising the HTTP timeout.
