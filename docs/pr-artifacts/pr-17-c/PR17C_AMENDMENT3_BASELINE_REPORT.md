# PR 17-C Amendment 3 — Baseline Report

**Branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `ce22c11` (PR 17-C Amendment 2)
**Comparator:** `main` = `669337c1b496a5660d36e5d72cff5544f6c04722`
**Date:** 2026-10-13
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose` 1.0.6;
Python 3.14.7; Keycloak `quay.io/keycloak/keycloak:26.8.0-1`; PostgreSQL 18.
**Path under test:** container → `keycloak.mtmf.test:28443` → forwarder →
`keycloak:8443`, TLS verified against the development CA with SNI
`keycloak.mtmf.test`.

Amendment 1 (exact issuer/JWKS/PKI) and Amendment 2 (stable Compose lifecycle)
were present and preserved.

## Reproduction

The forwarder-origin stall was reproduced with the committed forwarder by
replaying the canonical probe's connection pattern — a bare TCP reachability
check (`connect`, no data, `close`) immediately followed by a verified TLS
connection on the same path. Fresh throwaway container, 20 iterations:

```text
tcp-check -> TLS: 2/20 FAIL (5.00s handshake timeout), 18/20 ok
```

Within a single long-lived container (50 iterations) there were no failures,
confirming the defect is a state/lifecycle effect rather than a client bug.

## A/B/C phased controls (5s timeout, first attempt, no retry)

The reliability harness (`tests/integration/pr17c_forwarder_reliability.py`)
performs a full discovery + JWKS check with a fresh connection per GET.

```text
A (host -> 127.0.0.1:28443)                     50/50 ok  p95 0.031s
B (container -> keycloak:8443, direct)          50/50 ok  p95 0.033s
C (container -> keycloak.mtmf.test:28443)       50/50 ok  p95 0.045s
C concurrent 20 @10                             20/20 ok  p95 0.104s
```

The pure-TLS C path did **not** reproduce the stall in this window; the trigger
is the short-lived connection-close (`check_tcp`) that the canonical probe and
the standalone `preflight` perform.

## Instrumentation (evidence, not assumption)

A temporary diagnostic build of the forwarder separated DNS resolution from TCP
connect and logged per-connection pump outcomes. Reproducing the
`check_tcp`-then-TLS pattern:

```text
diag dns=0.001 connect=0.001
diag dns=5.006 connect=0.001     <- client handshake timed out at 5s
diag dns=10.010 connect=0.001
diag dns=10.011 connect=0.001
...
diag[36] handle-start            <- check_tcp connection
diag[36] target-open 0.002
diag[36] pipe-eof bytes=0
diag[36] pumps-done 0.004
diag[37] handle-start            <- TLS connection
diag[37] target-open 0.002
diag[37] pipe-start / pipe-eof   <- pumps ended without a "pumps-done"
```

Findings:

1. `_open_target()` occasionally spent 5–10 s in
   `socket.getaddrinfo("keycloak", 8443)` while the subsequent TCP connect was
   always ~1 ms. The bare service name triggers the DNS **search-domain** query
   (`search dns.podman`), which intermittently exceeded the resolver timeout.
   Direct `B`/`A` controls and a fresh process resolved quickly, so this is a
   per-process/per-query resolver timeout, not a network outage.
2. The committed pump lifecycle could terminate a connection without a clean
   completion: `_pipe`'s `write_eof()` in `finally` raised a bare
   `OSError(107)` that was **not** in `contextlib.suppress(AttributeError,
   ConnectionError, RuntimeError)`, so `asyncio.gather` raised and the client
   saw a truncated/failed handshake; `_handle` never `await`ed writer close, and
   the eager target connect on a no-data client opened an incomplete TLS
   connection.

Both mechanisms were observed directly (timings and pump outcome logs); the
second is corroborated by the `write_eof` traceback in the forwarder logs.

## Reconciliation classification

| Capability | Class |
| --- | --- |
| Amendment 1 issuer/JWKS/PKI | DONE + VERIFIED (preserved) |
| Amendment 2 stable Compose lifecycle | DONE + VERIFIED (preserved) |
| Forwarder transport reliability | DEFECT REPRODUCED + ROOT-CAUSED; fixed in this amendment |

## Environment note (host crash recovery)

The workstation crashed mid-session and rebooted, clearing `/tmp` (the
generated development CA, secret files, and the ephemeral admin password file).
The MTMF volumes persisted. The CA/leaf and secret files were regenerated, and
a **second** master-realm admin (`mtmf-pr14-admin2`) was added with Keycloak's
supported `bootstrap-admin user` command; the existing realm/clients were left
intact. This is a harness-recovery deviation, recorded in
`PR17C_AMENDMENT3_STOP_DEVIATIONS.md`; no MTMF volume was deleted.
