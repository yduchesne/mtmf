# PR 17 — Amendment #2 timeout and admission-safety evidence (Part C)

## 1. Configurable PostgreSQL session timeouts (A2-13)

`PostgresConfig` now carries runtime-only `statement_timeout_ms` and
`lock_timeout_ms`, read from `MTMF_RUNTIME_STATEMENT_TIMEOUT_MS` and
`MTMF_RUNTIME_LOCK_TIMEOUT_MS` for the restricted runtime identity only
(administrator and migrator are unaffected). They are applied through the
libpq `options` parameter in `psycopg_dsn`, so **every** runtime connection
inherits them and connection reuse cannot silently drop them.

Invariants enforced by `__post_init__`/`from_env`:

- both values are positive and bounded (`1..600000 ms`);
- `lock_timeout_ms < statement_timeout_ms` when both are set;
- defaults are 10,000 ms / 3,000 ms;
- no global database configuration is changed and no grant is added.

The statement timeout (10 s) is shorter than the HTTP evaluation deadline
(15 s) with a 5 s allowance for non-database work (trust/attestation).
The total downstream budget is not contractually bounded per batch (each DB
statement has the 10 s cap); this residual is recorded.

## 2. Real-PostgreSQL verification (A2-14)

`tests/integration/postgres/test_pr17_runtime_timeouts.py` (5 passed):

| Test | Proves |
| --- | --- |
| `test_a2_13_default_runtime_config_applies_conservative_timeouts` | defaults and ordering |
| `test_a2_13_short_timeouts_apply_to_the_session` | `SHOW statement_timeout/lock_timeout` on the actual runtime login |
| `test_a2_14_blocked_statement_is_cancelled_and_rolled_back` | `pg_sleep(2)` → `QueryCanceled`; rollback; session healthy |
| `test_a2_14_blocked_lock_is_cancelled` | blocked advisory lock → `LockNotAvailable`; session healthy |
| `test_a2_14_timeout_does_not_leave_a_broken_transaction` | fresh transaction works after cancellation |

The evaluation path uses `with spi.create_unit_of_work()`, so a terminated
statement raises, the UoW context rolls back, and the connection closes. No
timeout is converted into an ALLOW.

## 3. Closed permit race (A2-15)

Amendment #1 acquired a permit in the transport, released it in the worker's
`finally`, and used `release_if_not_started()` on timeout. If the transport
released while a queued worker was just beginning, the worker still called
`authorization_service.evaluate(...)` — i.e. it executed authorization logic
**after** its permit was released, violating the invariant.

Correction: new `concurrency.run_admitted(permit, work)`:

1. `mark_started()` must succeed (returns `True`) or the work is **not**
   invoked (`EvaluationNotAdmittedError` raised in the abandoned thread);
2. otherwise the permit is released exactly once in `finally`.

Because `mark_started()` and `release_if_not_started()` are serialized by the
permit lock, exactly one wins:

- worker starts first → state `RUNNING`; transport cannot release; worker
  releases after completion;
- transport releases first → state `RELEASED`; `mark_started()` returns
  `False`; the worker does not execute.

Deterministic tests (`tests/unit/service/test_concurrency.py`):

| Test | Proves |
| --- | --- |
| `test_a2_15_premature_release_prevents_worker_execution` | released permit → work never runs; in-flight 0 |
| `test_a2_15_worker_start_blocks_transport_release` | RUNNING blocks transport release; in-flight stays 1 |
| `test_a2_15_run_admitted_releases_exactly_once` | exactly-once release; later use rejected |

The earlier bounded-admission tests (`test_a1_16_*`, `test_a1_17_*`) continue to
pass, so saturation, timeout retention and peak-runner bounds are preserved.

## 4. Residual, corrected

The race described in Amendment #1 is now closed at the permit-state level.
The worker can still outlive the HTTP deadline (a synchronous blocking call
cannot be forcibly interrupted); this is bounded by admission and by the
PostgreSQL statement/lock timeouts above.
