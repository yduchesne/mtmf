# PR 17-C Amendment 3 Fixup 1 — Acceptance Report

**Fixup tip:** `dev/pr17c-keycloak-issuer` working tree on base `0a114a4`.
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose`
1.0.6; Keycloak `26.8.0-1`; PostgreSQL 18; Python 3.14.7.
**Canonical issuer:** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

## Authoritative gates (fixup tip)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — **2065 passed** (+30 FX tests), coverage **90.75%** |
| `./build.sh --sec` | PASS — Bandit Medium/High 0, Semgrep 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |
| PR 17-B live (`MTMF_PR17B_LIVE=1`) | **13 passed** |
| PR 14 live (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live (`MTMF_PR17_LIVE=1`) | **26 passed** |

## Live real-topology acceptance (FX-I01–FX-I08)

Real isolated Podman network; real Keycloak TLS; real forwarder; throwaway
verifying client with `dev/nsswitch.conf` and the dev CA mounted read-only;
5 s per-request deadline; **no per-request retry**.

| Case | Result |
| --- | --- |
| FX-I01 `up` + `preflight` + ready | `up` 0, `preflight` 0, `/health/ready` **200** |
| FX-I02 100 sequential discovery+JWKS | **100/100**, max 0.0188 s, p95 0.0127 s, median 0.011 s |
| FX-I03 50 @ concurrency 10 | **50/50**, max 0.0828 s, p95 0.0811 s |
| FX-I04 30 direct-to-Keycloak control | **30/30**, max 0.015 s |
| FX-I05 Keycloak down → bounded failure → restore → 20 | down: bounded `SSLEOFError`/`TimeoutError` (no hang); restore: **20/20** max 0.583 s; forwarder **not restarted** |
| FX-I06 30 aborted connects + 20 valid TLS | **20/20**; forwarder FDs 7 → 7; **0** tracebacks |
| FX-I07 three unchanged `up` cycles | all four IDs and `State.StartedAt` identical; **0** `podman stop`/`rm`; `preflight` 0; ready 200 each |
| FX-I08 ports/privilege/secrets/issuer | forwarder `publish=none` `privileged=false`; loopback-only host ports; no privileged runtime secrets; `issuer`/`jwks_uri`/token `iss` exact canonical |
| FX-I09 DNS stall under fake | covered by unit FX-U06–FX-U11 (no live DNS tampering) |
| FX-I10 recovery admin | **STOP** — original admin cannot be authenticated; recovery admin left enabled (see STOP register) |

Lifecycle snapshot (FX-I07 baseline, unchanged across all three cycles):

```text
mtmf_postgres_1  id=89b0674e394a started=2026-10-13T09:04:49.391183216-07:00
mtmf_keycloak_1  id=ef1c7975f17a started=2026-10-13T09:24:41.130549789-07:00
mtmf_forwarder_1 id=817b72427b1d started=2026-10-13T09:23:20.586952781-07:00
mtmf_service_1   id=78282d8c76fd started=2026-10-13T08:51:51.38700587-07:00
```

## Baseline vs feature vs regression

- **Baseline (base `0a114a4`):** unbounded `resolve()`; unjoined pump cancel;
  unbounded `wait_closed()`; recovery admin unresolved.
- **Feature (fixup):** bounded `wait_for` DNS deadline, generation-guarded
  cache, single bounded shielded cleanup with joined pumps and bounded writer
  close.
- **Regression:** all prior FW01–FW20 tests, PR 17-C live reliability, and live
  PR 17-B/14/17 suites pass on the fixup tip.

## Failure classification

No introduced regressions. No gate was accepted on a retry, xfail, or skip.
The single unresolved item is the FX-I10 recovery-admin **STOP**, an
environment/security reconciliation blocked by the lost pre-crash credential,
recorded with human action required.
