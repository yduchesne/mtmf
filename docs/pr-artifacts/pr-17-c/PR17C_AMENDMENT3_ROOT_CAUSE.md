# PR 17-C Amendment 3 — Root Cause

## Demonstrated mechanism

Two independent defects in `scripts/mtmf-dev-forwarder.py` combined to produce
the intermittent 5 s client handshake timeouts observed in Amendment 2 and
reproduced in the baseline.

### 1. Per-connection bare-name DNS resolution (primary)

`_open_target()` called `asyncio.open_connection(TARGET_HOST, TARGET_PORT)` with
`TARGET_HOST = "keycloak"` for every accepted client. Because `keycloak` has no
dot, the resolver applies the `search dns.podman` entry before the bare name,
and that query intermittently exceeded the resolver timeout. Instrumentation
showed `socket.getaddrinfo("keycloak", 8443)` inside the long-running forwarder
taking **5.006 s / 10.010 s / 10.011 s** while the following TCP connect took
~1 ms. The client's 5 s TLS handshake timeout therefore fired even though
Keycloak was healthy:

- direct host (`127.0.0.1:28443`) and direct container (`keycloak:8443`)
  controls were 0/15 failures;
- a fresh process resolved `keycloak` in ~1 ms;
- only the long-running forwarder's event loop hit the resolver timeouts,
  because it issued the search query on every connection.

### 2. Non-robust pump lifecycle (secondary, connection-close trigger)

The committed lifecycle had three flaws that the `check_tcp` connection-close
exercise exposed:

- **Eager target connect:** `_handle` opened the Keycloak connection before the
  client sent any bytes, so a bare TCP reachability probe created an incomplete
  TLS connection to Keycloak.
- **`write_eof` exception escape:** `_pipe`'s `finally` called
  `writer.write_eof()` under `contextlib.suppress(AttributeError,
  ConnectionError, RuntimeError)`. A half-closed transport raises a plain
  `OSError(107)` (not `ConnectionError`), which escaped, made `asyncio.gather`
  raise, and aborted the per-client handler without a clean completion — the
  pump log showed `pipe-eof` with no `pumps-done` and a `write_eof` traceback.
- **Unbounded/completed-less teardown:** `_handle` closed writers but never
  awaited `wait_closed()`, and a pipe could wait on a peer that would never
  close.

## Fix

Minimal forwarder-only change:

1. **`_TargetResolver` cache.** Resolve once with bounded IPv4-only
   `getaddrinfo(... family=AF_INET ... AI_ADDRCONFIG)`, cache the address, and
   reuse it. Any connect failure calls `invalidate()`, so a rebuilt Keycloak is
   re-resolved rather than assumed to keep its IP. The cache is warmed at
   startup so the first client request does not pay the resolver search cost.
   The cached value is an address, not a connection; no connection or writer is
   shared between clients.
2. **Bounded connect.** `CONNECT_ATTEMPTS` reduced to 3 with a 5 s per-attempt
   timeout; re-resolves between attempts.
3. **Lazy connect.** `_handle` waits (bounded) for the client's first bytes
   before opening the target, so `check_tcp` never touches Keycloak.
4. **Robust pumps.** `_pipe` streams bytes and propagates EOF via
   `write_eof()` only when `can_write_eof()`, suppressing `OSError`/`RuntimeError`.
   `_handle` runs both pumps, cancels the peer when the target closes, gives the
   target a bounded drain window after a client half-close, `gather`s with
   `return_exceptions=True`, and closes/`await wait_closed()` on both writers.
   Per-client `OSError` is contained; `CancelledError` propagates; the listener
   is never terminated by a client.

## Why the fix addresses the observed stalls

- The DNS search query is issued once (cache warm) instead of per connection, so
  the 5–10 s resolver timeout no longer sits in the client handshake path.
- A bare TCP probe no longer opens a Keycloak connection at all.
- The `write_eof` `OSError` no longer aborts the pump, and teardown is explicit
  and bounded.

## Comparative evidence

| Measurement | Before | After |
| --- | --- | --- |
| Fresh-container `check_tcp`→TLS, 20–30 iters | 2/20, 3/30 fail (5 s) | **0/30 fail** |
| D1 container path, 100 sequential | (flake on `preflight`) | **100/100, max 0.051 s** |
| D1 container path, 50 @ concurrency 10 | — | **50/50, max 0.125 s** |
| Forwarder `getaddrinfo` stalls | 5–10 s observed | none observed |
| Forwarder `write_eof` tracebacks | present | none (0 since restart) |
| Forwarder FDs after 10 connect/close | grew | 7 → 7 |

## Alternatives rejected

- **Increasing the probe timeout / launcher retries:** forbidden by the plan and
  hides the defect; the resolver stall was the cause, not the timeout.
- **Trusting a fixed/hard-coded Keycloak IP:** stale after Keycloak recreation;
  rejected. The cache invalidates and re-resolves on connect failure.
- **Adding a reverse proxy / new dependency / TLS termination:** out of scope
  and would break the opaque-TLS invariant.
- **Keeping eager connect / `write_eof` and only retrying:** leaves the
  connection-close defect and log noise.
