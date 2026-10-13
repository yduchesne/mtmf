# PR 17-C Amendment 3 Fixup 1 — Baseline Report

**Branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `0a114a4a3ceb54cee78ab9d4dae0faf50ae1a6c0` (Amendment 3)
**Comparator:** `main` = `669337c1b496a5660d36e5d72cff5544f6c04722`
**Date:** 2026-10-13
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose` 1.0.6;
Python 3.14.7; Keycloak `26.8.0-1`; PostgreSQL 18.
**Canonical issuer:** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

Ancestry and tree confirmed: `0a114a4` is an ancestor of the working HEAD,
the working tree was clean, and the MTMF stack (PostgreSQL, Keycloak,
forwarder, service) was healthy and MTMF-owned.

## Inventory of the base implementation

`scripts/mtmf-dev-forwarder.py` (`0a114a4`):

- `_TargetResolver.resolve()` awaited
  `loop.run_in_executor(None, lambda: socket.getaddrinfo(... AF_INET ...))`
  **without a deadline** and assigned `self._address` directly, so a stalled
  `getaddrinfo` could block the awaiting handler indefinitely and a timed-out
  caller could still have its result committed.
- `invalidate()` synchronously cleared the address with no generation guard, so
  an in-flight lookup could repopulate the cache after invalidation.
- `_handle()` created the two `_pipe` tasks, but its inner `finally` only called
  `task.cancel()` on unfinished pumps **without joining them**; if the handler
  was cancelled during the `FIRST_COMPLETED` wait or the drain window, pump
  tasks could outlive the owner, and writer close was unbounded.
- `_close_writer()` awaited `wait_closed()` with no timeout.

## Reproduced gaps

| Finding | Evidence on the base | Class |
| --- | --- | --- |
| A. Unbounded DNS | `resolve()` had no `wait_for` deadline and committed the address directly; a blocked `_lookup` kept the caller pending (deterministic unit reproduction). | Feature defect |
| B. Cancellation ownership | Inner `finally` cancelled pumps without joining; `wait_closed()` unbounded. A cancelled handler could leave pending pumps and unclosed writers (deterministic unit reproduction). | Feature defect |
| C. Recovery admin | Live master realm: `mtmf-pr14-admin2` enabled with realm role `admin` and authenticates; `mtmf-pr14-admin` enabled with realm role `admin` but **does not authenticate** with the only recoverable credential (the pre-crash password was lost when the workstation crashed/reblocked and `/tmp` was cleared). | Environment/security STOP |

## New acceptance tests against the base

The FX-U/FX-I acceptance was written against the fixup contract. Against the
base, the bounded-DNS cases (FX-U06–U11), the cache-race cases (FX-U08),
the cancellation-ownership cases (FX-U19–U26), and startup validation
(FX-U12) fail or cannot pass by construction; they are the regression tests for
this fixup. On the fixup tip all 51 forwarder unit tests pass.

## Preserved capabilities (not re-litigated here)

Amendment 1 exact issuer/JWKS/PKI, Amendment 2 stable Compose lifecycle and
DNS-first routing, and Amendment 3's live 100 sequential / 50 concurrent
success remain; they were re-executed on the fixup tip and are reported in
`PR17C_AMENDMENT3_FIXUP1_ACCEPTANCE_REPORT.md`.
