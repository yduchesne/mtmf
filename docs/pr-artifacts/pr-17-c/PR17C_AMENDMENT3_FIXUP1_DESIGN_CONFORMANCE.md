# PR 17-C Amendment 3 Fixup 1 — Design Conformance

## Part A — Bounded, race-safe DNS

### Contract

- `RESOLVE_TIMEOUT_SECONDS` defaults to `2.0`, configurable via
  `MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT`; parsed and validated at import/startup
  with `math.isfinite` and `> 0`. An invalid value raises `SystemExit` (nonzero
  exit) **before** any listener is created. Verified for `0`, `-1`, `nan`,
  `inf`, and nonnumeric input.
- `_TargetResolver.resolve()` uses
  `await asyncio.wait_for(asyncio.to_thread(self._lookup), timeout=...)`; the
  IPv4-only `getaddrinfo` parameters are unchanged.
- A timeout, `OSError`, or empty result returns `None`, never propagates into the
  listener, and **never writes the cache**. `CancelledError` propagates.

### No route for a worker to mutate cache

`_lookup()` is a pure blocking function run via `asyncio.to_thread`; it returns
a value only. The cache is committed **exclusively** by the awaiting
`resolve()` coroutine after the `await`. A timed-out or late worker result is
discarded by `asyncio.wait_for`/task cancellation and has no reference to
resolver state. Covered by FX-U06/FX-U07.

### Serialization and invalidation generation

- One `asyncio.Lock` serializes `resolve()`; while the cache is empty the first
  caller performs the lookup and the rest observe the populated cache, so
  concurrent uncached callers coalesce into a single `getaddrinfo` (FX-U03).
- `invalidate()` is synchronous on the event loop: it increments
  `self._generation` and clears `self._address`, and never awaits the lock.
- `resolve()` snapshots the generation before the lookup and commits the result
  only when `generation == self._generation` and the cache is still empty.
  Invalidating while a lookup is in flight therefore discards the stale result
  (FX-U08). No background refresh task or TTL was added; the `address` property
  remains read-only.

### Connect-attempt bounds

`_open_target()` retains `CONNECT_ATTEMPTS = 3` and a 5 s TCP timeout, uses
`resolver.resolve()` whenever the address is absent, tolerates `None`, backs off
`0.2 s` between attempts, and invalidates on TCP connect failure. The worst-case
attempt bound is resolver deadline + TCP timeout + backoff per attempt
(≤ 3 attempts); DNS timeout cannot cause an unbounded wait before the connect
timeout. No whole HTTP/TLS request is retried (FX-U10).

## Part B — Cancellation-safe task and writer lifecycle

### Task ownership

`_handle()` declares `tasks: set[asyncio.Task[None]]` before the outer `try` and
registers each pump immediately on creation. `_handle` owns both pumps and both
writers; `_pipe` owns one direction; the resolver owns only endpoint identity;
`_open_target` owns only connect attempts.

### Single bounded shielded cleanup

- `_finish_cleanup(tasks, target_writer, client_writer)` is the single owner
  cleanup path. It cancels unfinished pumps, joins **all** registered pumps via
  `asyncio.gather(*tasks, return_exceptions=True)` under
  `asyncio.wait_for(..., timeout=CLEANUP_TIMEOUT_SECONDS=2.0)`, then closes the
  target writer and the client writer with bounded `wait_closed()`.
- Ordering is exactly: cancel pumps → join pumps → close target writer → await
  target close → close client writer → await client close. Writers are never
  closed before the pumps' cancellation/join.
- The outer `finally` of `_handle` creates exactly one cleanup task and awaits
  it with `asyncio.shield(...)`. If the handler is cancelled while waiting, the
  `except asyncio.CancelledError` branch awaits the **same** cleanup task via
  `asyncio.shield(...)` and then re-raises cancellation. No duplicate cleanup
  task is created.
- Expected disconnect errors (`OSError`, `CancelledError`) are suppressed;
  an unexpected pump exception is surfaced as one bounded, non-secret stderr
  diagnostic (`unexpected pump error (<Type>)`) and cleanup still completes.
  `except BaseException` and blanket suppression are not used.
- On cleanup-join timeout, remaining pumps are cancelled and cleanup proceeds to
  close the writers; the handler cannot hang indefinitely.
- `_pipe()` keeps `read(65536)`/`write()`/`drain()`, EOF half-close via
  `can_write_eof`/`write_eof`, and logs no payload.

### Cancellation propagation

Cancellation propagates to the caller (`CancelledError` re-raised after
cleanup), and no pump or writer is left pending when `_handle` returns.

## Ownership summary

| Component | Owns |
| --- | --- |
| `_TargetResolver` | cached endpoint identity + serialized/deadline-bound resolution |
| `_open_target` | bounded target-connect attempts and invalidation on failure |
| `_handle` | both pump tasks and both writers (via `_finish_cleanup`) |
| `_pipe` | one transfer direction only |
| DNS worker thread | nothing — returns a value only |
