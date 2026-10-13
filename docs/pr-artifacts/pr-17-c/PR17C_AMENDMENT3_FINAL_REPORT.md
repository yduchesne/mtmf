# PR 17-C Amendment 3 — Final Report

## Objective

Remove the demonstrated forwarder-origin intermittent connection stalls and
prove reliable, bounded, byte-transparent TLS forwarding under sequential,
concurrent, and connection-close conditions.

## Root cause (evidence-based)

1. **Bare-name DNS search query per connection.** The forwarder resolved
   `keycloak` on every accepted client. The undotted name triggered the
   `search dns.podman` query, which intermittently exceeded the resolver timeout
   (measured 5.006 s / 10.010 s / 10.011 s) while the TCP connect was ~1 ms; the
   client's 5 s handshake timeout fired against a healthy Keycloak.
2. **Non-robust pump lifecycle.** Eager target connect on a no-data client,
   `_pipe`'s `write_eof()` raising an unsuppressed `OSError(107)` that aborted
   the handler mid-close, and no `await wait_closed()`.

## Fix (forwarder-only)

- `_TargetResolver`: bounded IPv4-only resolution cached until a connect fails,
  warmed at startup — no per-connection DNS, and a rebuilt Keycloak is
  re-resolved rather than assumed to keep its IP.
- Lazy connect after the client's first (bounded) bytes, so a bare TCP probe
  never opens a Keycloak connection.
- Bounded connect attempts (3 × 5 s), explicit cancel/join of pumps, bounded
  drain after client half-close, `close` + `await wait_closed`, and containment
  of per-client `OSError`/`CancelledError`.

## Changed files

```text
scripts/mtmf-dev-forwarder.py                         (fix)
tests/unit/service/test_pr17c_dev_forwarder.py        (new; FW01-FW20)
tests/integration/pr17c_forwarder_reliability.py      (new; A/B/C harness)
docs/pr-artifacts/pr-17-c/PR17C_AMENDMENT3_*.md       (new reports)
docs/ROADMAP_V01.md                                   (status)
```

`scripts/mtmf-dev-probe.py`, `scripts/mtmf-dev-certs.py`,
`scripts/mtmf-dev-stack.py`, `dev/nsswitch.conf`, and `compose.dev.yaml` were
**not** modified.

## Evidence

- Reproduced: fresh-container `check_tcp`→TLS **2/20** fail (5 s) before; **0/30**
  after.
- Mandatory real-topology gate: C **100/100** sequential (max 0.051 s) and
  **50/50** at concurrency 10 (max 0.125 s); B control **30/30**.
- Negative/recovery: Keycloak down → bounded failure; restore → **20/20**
  without forwarder restart; client abort → listener survives.
- Lifecycle: three unchanged `up` cycles preserve all four container IDs and
  `State.StartedAt` with zero `podman stop`/`rm`; `preflight` exit 0; service
  ready 200.
- Gates: `--qa` **2035 passed / 90.75%**, `--sec` 0 findings, `--rust` PASS,
  `--integration` **564 passed / 65 skipped**.
- Live regressions: PR 17-B **13/13**, PR 14 **22/22**, PR 17 **26/26**.
- Isolation: forwarder `publish=none`; all publications loopback-only; no
  privileged runtime secrets; discovery `issuer`/`jwks_uri`/token `iss` exact;
  forwarder logs clean (0 tracebacks), FDs stable.

## Remaining issues / disposition

- Windows N17/N18 remain unexecuted (out of scope here).
- Host-crash recovery added a second master admin; recorded as AM3-D1.
- PR 17-C remains **AWAITING HUMAN REVIEW — NOT DONE**.
