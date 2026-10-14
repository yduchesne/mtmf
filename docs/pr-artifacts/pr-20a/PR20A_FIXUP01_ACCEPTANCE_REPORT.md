# PR20A_FIXUP01_ACCEPTANCE_REPORT

**Amendment:** PR 20A review fixup 01 (bounded worker lifetime + exact fixture Role reconciliation).
**Branch:** `dev/pr20a-reference-app`.
**Start-of-fixup HEAD:** `5e49b2b892a5e1cfab9c415b792c3a44dc6f4337` (reviewed).
**Validated fixup commit:** `f8b7eac142a1aadc822fb529930475766d7245af` (all gates and deployed acceptance below were executed on this revision; this report is a follow-up documentation commit).
**Baseline `origin/main`:** `56695c08e5b71a032877f319aa05193db31a47ec`.
**Status:** **DONE** — both defects corrected and every mandatory gate re-executed.

This is an amendment to PR 20A, not a new roadmap PR. It changes no external HTTP
contract, authorization semantics, fixture policy, deployment topology, or PR 20B
scope. Existing PR 20A reports are preserved unchanged and linked from
[PR20A_FINAL_ACCEPTANCE_REPORT.md](PR20A_FINAL_ACCEPTANCE_REPORT.md).

## 1. Defects confirmed at the reviewed SHA

1. `examples/mtmf-reference-app/src/mtmf_reference_app/app.py`, `BoundedWorker.run`
   used `asyncio.to_thread(...)` inside an `async with self._semaphore` whose
   permit was released when the **awaiting caller** timed out or was cancelled,
   even though the synchronous function could continue running in its thread.
   Repeated slow operations could exceed the configured outstanding-work bound.
2. `scripts/pr20a_reference_fixture.py`, `ensure_document_role` reconciled an
   existing Role only by the set of ALLOW Permission URNs. Extra DENY sets,
   duplicate sets, changed set/permission UUIDs, extra permissions, missing
   permissions, or wrong `role_urn`/parent links could escape validation.

## 2. Part A — bounded worker lifetime

### Fix

`BoundedWorker.run` now implements the required lifecycle:

1. `await self._semaphore.acquire()` (cancellable; a cancellation before
   acquisition releases nothing).
2. exactly one `loop.run_in_executor(None, ...)` submission; a synchronous
   submission failure releases the permit once and re-raises;
3. exactly one `add_done_callback` that releases the permit in a `finally` **when
   the executor future completes**, i.e. when the thread actually terminates;
4. `await asyncio.wait_for(asyncio.shield(future), timeout=self._timeout)`, which
   cancels only the shield on timeout/cancellation and never the submitted
   operation;
5. `TimeoutError` and `CancelledError` propagate unchanged; no `finally:
   semaphore.release()` after successful submission and no retry loop.

Per-worker semaphores and the existing `_verify_worker` (10 s) / `_evaluate_worker`
(15 s) instances with `limit=32` are unchanged. No global executor, daemon thread,
thread kill, or new dependency was introduced.

**Implementation note (documented deviation, semantics preserved).** On the
installed CPython 3.14.7, `asyncio.shield` attaches `_log_on_exception` to the
inner future when the outer future is cancelled; a late raise therefore logs
`<Exc> exception in shielded future` *even though the completion callback
retrieves `future.exception()`*. To satisfy the fixup's explicit "no
unhandled-future-exception warning / no exception text logging" requirement
without weakening the prescribed `wait_for(shield(...))` structure, the submitted
callable is wrapped in `BoundedWorker._invoke`, which returns `(True, result)` or
`(False, exception)` so the executor future never carries an ordinary exception.
The caller still sees the original exception re-raised while it is still awaiting;
an abandoned operation is simply discarded without a late-exception log.
`BaseException` (system-exiting) values still propagate through the executor
future unchanged. This is the only deviation from the plan's literal sketch; it is
a logging/lifetime detail, not an architectural change.

### Deterministic tests — `examples/mtmf-reference-app/tests/test_worker.py`

| ID | Scenario | Result |
| --- | --- | --- |
| W01 | normal return + slot reuse | pass |
| W02 | blocking exception propagates + slot reusable | pass |
| W03 | `limit=1`, caller timeout; second operation does not enter until the first thread finishes | pass |
| W04 | releasing the first thread after timeout lets the second run | pass |
| W05 | cancel the caller while blocked; slot held until the thread finishes | pass |
| W06 | cancel while waiting to acquire; no work submitted, no spurious release | pass |
| W07 | late raise after timeout; no exception text/`never retrieved` log; slot reusable | pass |
| W08 | `limit=2`, repeated timeouts; max concurrent entered blocking functions stays 2 | pass |

W03/W05/W06 distinguish caller completion from underlying-thread completion via
thread-side `threading.Event`s and bounded waits; no test asserts that a thread
can be killed by cancellation.

### PEP timeout regression

`examples/mtmf-reference-app/tests/test_pep.py::test_evaluate_worker_timeout_maps_to_503_without_late_body`
drives a blocking client through a 0.05 s evaluate worker and asserts HTTP **503**
with no document body — a timed-out evaluation never becomes a late success.

## 3. Part B — exact fixture Role aggregate reconciliation

### Fix

`ensure_document_role` keeps the privileged, idempotent contract:

- Role absent → `role_add` with the exact `reference_role_payload`.
- Role present but owned by another Tenant → `ReferenceFixtureError`, no read/write.
- Role present and Tenant-matching → one read-only, parameterized query

```sql
SELECT ps.id, ps.role_urn, ps.effect, p.id, p.permission_set_id, p.urn
FROM mtmf.permission_set AS ps
LEFT JOIN mtmf.permission AS p ON p.permission_set_id = ps.id
WHERE ps.role_urn = %s
ORDER BY ps.id, p.id
```

The `LEFT JOIN` preserves an empty permission set as a row of `NULL` permission
columns. Rows are canonicalized to `str` UUIDs and compared, **as an ordered list
preserving multiplicity**, against the single expected row derived from
`reference_role_payload(tenant_id)`. Any difference in count, ids, `role_urn`,
`effect`, parent link, or Permission URN raises
`ReferenceFixtureError("the reference Role aggregate differs from the approved
fixture")` without repair or write. `mtmf.permission_set.effect` is stored as the
string keys `allow`/`deny` (confirmed in revision `0001`), so no representation
mapping is invented.

**Security-relevant equality, not byte-for-byte equality.** The invariant is the
permission-set/permission aggregate (ids, ownership, effect, parent links, URNs,
multiplicity). Mutable display-only `role.name` / `role.description` and the
generic `extension` are deliberately not compared; the canonical payload still
sets them on creation. No shipped migration, built-in manifest, protected Role,
`mtmf_runtime` grant, or new stored function was touched.

### Tests — `examples/mtmf-reference-app/tests/test_fixture_role.py`

| ID | Existing state | Result |
| --- | --- | --- |
| R01 | no Role | `role_add` called once with the canonical payload |
| R02 | exact one ALLOW set + one Permission | accepted, no write |
| R03 | exact ALLOW + extra DENY set | rejected, no write |
| R04 | exact ALLOW + extra ALLOW set | rejected, no write |
| R05 | empty set / missing Permission | rejected, no write |
| R06 | wrong set UUID or Permission UUID | rejected, no write |
| R07 | wrong effect, role URN, or parent set id | rejected, no write |
| R08 | Role owned by another Tenant | rejected before any aggregate read |
| R09 | repeated initialization | idempotent, no writes |
| R10 | duplicate rows | rejected without collapsing to a set |

### Real-PostgreSQL idempotency

The authoritative deployed REPEAT cycle re-runs the privileged initializer against
the isolated PostgreSQL database; `ensure_document_role` reads and accepts the
persisted aggregate (no repair, no write). Direct inspection of the isolated
database after acceptance:

```text
59d30173-2e31-5032-b4f2-eef24312b00a|allow|urn:mtmf:iam:permissions:system:document:read-object
```

exactly one `allow` permission set owning exactly the approved Permission.

## 4. Mandatory gates (fresh after the fixup)

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | Ruff format/lint clean, strict Mypy clean, **2448 passed**, coverage **90.36%** |
| Security | `./build.sh --sec` | Bandit + Semgrep, **0 findings** |
| Example Semgrep | `uv run semgrep scan --config=auto examples` | **0 findings** (11 targets) |
| Rust/native | `./build.sh --rust` | **PASS** |
| Integration | `set -a; source .env; set +a; ./build.sh --integration` | **593 passed, 90 skipped** (documented opt-in live suites) |
| Example package | `uv run pytest examples/mtmf-reference-app/tests --cov=mtmf_reference_app --cov-fail-under=85` | **85 passed**, coverage **89.39%** |

## 5. Deployed acceptance (authoritative launcher)

`uv run python scripts/pr20a-reference-acceptance.py acceptance` — isolated
`mtmf-pr20a-acceptance` project, real Keycloak, real MTMF HTTP service, real
PostgreSQL, unprivileged reference-app container.

```text
5 passed in 18.07s
reference-app container 5edca5106162: 5 passed, 0 skipped
COLD-01 PASS
5 passed in 8.12s
reference-app container 5edca5106162: 5 passed, 0 skipped
REPEAT-01 PASS
5 passed in 11.56s
reference-app container ee6b363d1870: 5 passed, 0 skipped
RECREATE-01 PASS
default stack inventory unchanged
```

Each cycle executed all of L01–L05 with **0 skipped**, and the default `mtmf`
stack inventory was unchanged. Final-cycle containers: PostgreSQL
`3fc6c8602ef9`, Keycloak `e7c5f5622a3d`, forwarder `42f9315e135c`, restricted
service `ac21262c40e0`, TLS terminator `77d1abd9391d`, reference app
`ee6b363d1870`; Tenant `17ab63f3-16d9-57e9-a7a1-e42b9f0c0850`, Application
`dcc867e4-3841-59aa-b716-e88741661a13`.

Local HTTP unit tests (`TestClient`) were not substituted for deployed
acceptance. No ATI/Darkula deployment or browser matrix was required.

## 6. Failure classification

No unclassified failures. No introduced regression: every previously reported
gate result was reproduced (`--qa` 2448, `--integration` 593/90, example suite now
85 tests) and the two defects were closed by the new W/R tests. The `--integration`
90 skips are the documented opt-in live suites, unchanged from the PR 20A baseline.

## 7. Files changed by this fixup

```text
examples/mtmf-reference-app/src/mtmf_reference_app/app.py
examples/mtmf-reference-app/tests/test_worker.py      (new)
examples/mtmf-reference-app/tests/test_fixture_role.py (new)
examples/mtmf-reference-app/tests/test_pep.py         (timeout regression test)
examples/mtmf-reference-app/tests/helpers.py          (test fakes/worker seam)
examples/mtmf-reference-app/tests/conftest.py         (scripts import path for fixture tests)
scripts/pr20a_reference_fixture.py
docs/pr-artifacts/pr-20a/PR20A_FIXUP01_ACCEPTANCE_REPORT.md
docs/pr-artifacts/pr-20a/PR20A_FINAL_ACCEPTANCE_REPORT.md (link/addendum only)
```

**Unchanged:** `packages/**`, `sql/**`, `compose.yaml`, `compose.dev.yaml`,
`compose.pr19c-acceptance.yaml`, `compose.pr20a-acceptance.yaml`,
`dev/keycloak/expected-*.json`, `docs/ROADMAP_V01.md`, HTTP v1 schemas, and all
production authorization logic. No new migration, dependency, generic management
API, cross-request cache, or PR 20B feature was added.
