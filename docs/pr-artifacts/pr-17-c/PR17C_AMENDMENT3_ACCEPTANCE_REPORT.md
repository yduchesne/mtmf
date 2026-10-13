# PR 17-C Amendment 3 — Acceptance Report

**Amended code:** `dev/pr17c-keycloak-issuer` working tree on base `ce22c11`.
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose`
1.0.6; Keycloak `26.8.0-1`; PostgreSQL 18; Python 3.14.7.
**Canonical issuer:** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

## Canonical gates (amended tip)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — **2035 passed** (+21 FW tests), coverage **90.75%** |
| `./build.sh --sec` | PASS — Bandit Medium/High 0, Semgrep 0 findings |
| `./build.sh --rust` | PASS — no native change |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |

## D1 — first-attempt real-topology reliability (mandatory)

Real isolated Podman network; actual Keycloak TLS leaf; actual forwarder
container; throwaway verifying client with `dev/nsswitch.conf` and the dev CA
mounted read-only; **5 s per-request timeout and no retry of any request**.

| Case | Requirement | Result |
| --- | --- | --- |
| C sequential discovery+JWKS | 100/100, all ≤5 s | **100/100**, max **0.051 s**, p95 0.041 s, median 0.028 s |
| C concurrency 10 | 50/50, all ≤5 s | **50/50**, max **0.125 s**, p95 0.106 s, median 0.073 s |
| B direct-to-Keycloak control | timing/failure comparison | **30/30**, max 0.033 s |
| connect/close leak cycle | no growth/unhandled exceptions | FDs **7 → 7**, 0 tracebacks |
| `check_tcp`→TLS (connection-close) | no stalls | **0/30 failures** |

No launcher retry was counted as a request, and launcher retry settings were
not modified.

## D2 — lifecycle and regression

- `up` succeeded (exit 0) and the restricted service returned
  `http://127.0.0.1:28001/health/ready` **200**.
- Three consecutive unchanged `up` cycles: each exit 0, **0** `podman stop`/`rm`
  lines, and **identical container IDs and `State.StartedAt`** for PostgreSQL,
  Keycloak, forwarder and service; immediate `preflight` exit 0 after each.
- Forwarder is **not host-published** (`publish=none`); PostgreSQL
  `127.0.0.1:25432`, Keycloak `127.0.0.1:28080/28443`, service
  `127.0.0.1:28001` are loopback-only; the service environment has no
  migrator/admin/bootstrap/owner/development-user variables.
- Discovery `issuer`, `jwks_uri`, and token `iss` are exactly canonical; the
  service resolves `keycloak.mtmf.test` to the current forwarder.

## D3 — negative-path recovery

With only MTMF-owned resources:

- Keycloak stopped → forwarded requests failed bounded (immediate
  `TimeoutError`/`SSLEOFError`, no hang), listener survived;
- Keycloak restored → **20/20** forwarded requests succeeded with **no forwarder
  restart** (the cached address invalidated and re-resolved to the new Keycloak
  IP);
- client abort midstream → listener survived and served the next connection
  (unit FW07/FW17 and live).

## Live regression suites (amended tip)

| Suite | Result |
| --- | --- |
| PR 17-B live (`MTMF_PR17B_LIVE=1`) | **13 passed** |
| PR 14 live (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live HTTP (`MTMF_PR17_LIVE=1`) | **26 passed** |

## Failure classification

- Forwarder DNS stall: **feature implementation defect**, reproduced and fixed.
- Forwarder pump/`write_eof` lifecycle: **feature implementation defect**,
  reproduced and fixed.
- No introduced regressions. No gate was accepted on a masked retry.

## Not executed / out of scope

- Windows N17/N18 (unchanged classification).
- A deliberate live "forwarder-only rebuild" was not required for the transport
  gate; the target-down/restore case (D3) already exercises address invalidation
  and re-resolution.
