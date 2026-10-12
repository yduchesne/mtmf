# PR 17 — Amendment #2 baseline reconciliation

**Branch:** `dev/pr17-http-service` (continued). **Reported head:** `5b9616a`;
**verified head:** `5b9616a`. **`origin/main`:** `4eea688`. Clean working tree.

## 1. Toolchain and MTMF-owned resources

| Item | Value |
| --- | --- |
| Podman | `4.9.3` |
| `podman-compose` | `1.0.6` (no `service_completed_successfully`) |
| Host privilege | no passwordless `sudo` (cannot edit `/etc/hosts`) |
| PostgreSQL container | `mtmf_postgres_1` (project `mtmf`, `25432`, healthy) |
| Keycloak fixture | project `mtmf-pr14-keycloak`, image `quay.io/keycloak/keycloak:26.8.0-1`, loopback `28080`/`28443` |
| Keycloak volume | `mtmf-pr14-keycloak-data` (MTMF-owned, disposable) |
| Service image | `localhost/mtmf-service:dev` (built from `Dockerfile.service`) |

Only MTMF-owned resources were inspected or touched.

## 2. Capability classification at baseline

| Capability | Status |
| --- | --- |
| FastAPI/Uvicorn authenticated PDP, PR 15 contract, PR 14 trust, PR 13 eligibility, PR 16 Python batch | DONE + VERIFIED (unit/ASGI and live) |
| Conservative 15 s TTL, `mtmf_owned` deny, unknown-Action deny | DONE + VERIFIED |
| Bounded in-process evaluation admission (Amendment #1) | DONE (permit race still open) |
| Privileged idempotent development initializer (real PostgreSQL + live Keycloak) | DONE + VERIFIED (PostgreSQL layer) |
| Fully containerized MTMF service deployment with the approved issuer | NOT VERIFIED (loopback namespace) |
| Canonical issuer hostname (`keycloak.mtmf.test`) resolvable from host **and** containers | BLOCKED (no sudo for host DNS; issuer-identity change needs approval) |
| Configurable PostgreSQL runtime statement/lock timeouts | NOT STARTED |
| Permit race (premature release vs worker start) | DONE but potentially racy |
| V01–V16 live acceptance | PARTIAL |
| Acting-user carrier approval (G1) | BLOCKED (no human approval) |
| MTMF-only destroy/recreate (V13) | NOT STARTED |
| Production issuer/root recovery | BLOCKED (separate release gate; out of scope) |

## 3. Historical evidence (re-verified as historical)

Amendment #1 reported 12/12 live HTTP and 22/22 live actor tests, 1,750 QA
tests at 89.99%, and passing security/Rust/integration gates. Those are
historical; this amendment re-runs affected and final gates on its own tree.

## 4. Open STOP conditions carried into Amendment #2

- STOP-02: acting-user carrier approval absent.
- STOP-01: any change to the trusted issuer identity/manifest needs approval.
- Container networking: loopback namespace plus the two-identity issuer problem.
- V13 destructive lifecycle not yet executed.
- V12 second live client not provisioned.

## 5. Amendment #2 additions (recorded here for traceability)

- `PostgresConfig` runtime session timeouts (`MTMF_RUNTIME_STATEMENT_TIMEOUT_MS`,
  `MTMF_RUNTIME_LOCK_TIMEOUT_MS`), applied via the connection DSN.
- `run_admitted` guard closing the permit race.
- Extended live V tests (V04 states, V05 org/different-client, V15 rate limit).
- Containerized service demonstration (host networking) preserving the approved
  issuer identity.
- Discovery: the development initializer's Keycloak client drifts the whole-realm
  attestation manifest (see the network/stop reports).
