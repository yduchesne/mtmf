# PR 17-C Baseline Report

**PR-ID:** `pr-17-c`
**Base revision:** `669337c1b496a5660d36e5d72cff5544f6c04722` (merge of PR #52, PR 17-B)
**Branch:** `dev/keycloak`
**Date:** 2026-10-13
**Environment:** Windows browser → Ubuntu 24.04.5 on WSL2 (kernel `6.18.33.2-microsoft-standard-WSL2`) → rootless Podman 4.9.3 + `podman-compose` 1.0.6 (`netavark`, rootless) → Keycloak `quay.io/keycloak/keycloak:26.8.0-1`, PostgreSQL 18.

## Scope confirmed against fresh `main`

The plan's baseline assertions were checked against the actual tree:

- `scripts/mtmf-dev-stack.py` owns `up` / `up-host-network` / `status` / `down` / `destroy`; there is no second orchestrator.
- `compose.dev.yaml` pinned Keycloak `26.8.0-1`, internal HTTPS `8443`, loopback host `28443`, `--hostname-strict=false`, and did **not** pass `--https-certificate-file`/`--https-certificate-key-file`, so Keycloak served an auto-generated self-signed certificate.
- `compose.yaml` published PostgreSQL as `"${MTMF_POSTGRES_PORT:-25432}:5432"` (all interfaces).
- `.env.example` used the loopback issuer `https://127.0.0.1:28443/realms/mtmf-pr14-dev`.
- `dev/keycloak/README.md` documents the isolated `mtmf-pr14-keycloak` **evidence** fixture, distinct from the standard stack.
- PR 17-B is merged; its `development_user.py` provisioning and secret-file protections were left unchanged.

## Confirmed defects / impediments on the baseline

1. **Standard `up` cannot succeed even before DNS/TLS:** `_postgres_inspect()` reads
   `result.stdout.strip()` from `_run()`, but `_run()` did not capture output, so
   `subprocess.CompletedProcess.stdout` was `None`. The launcher raised
   `AttributeError: 'NoneType' object has no attribute 'strip'` as soon as it polled
   PostgreSQL health.
2. **Loopback-only authentication guards:** `IssuerConfig` and `HttpAdminRestReader`
   rejected any non-loopback issuer/admin authority, so a canonical
   `keycloak.mtmf.test` issuer could not be configured.
3. **Port mismatch:** the issuer authority uses `28443` while Keycloak only listened on
   `8443`; a DNS alias alone does not solve this.
4. **Missing CA trust in containers:** `compose.dev.yaml` mounted no CA into the
   initializer/service and set no `SSL_CERT_FILE`.
5. **Host `/etc/hosts` leaks into containers:** Podman copies the host `/etc/hosts`
   into every container. With an operator `127.0.0.1 keycloak.mtmf.test` entry, the
   network alias is shadowed and containers resolve the canonical name to their own
   loopback.
6. **`0.0.0.0` PostgreSQL publication:** the development PostgreSQL port was bound on
   all interfaces, contrary to the loopback-only development invariant.
7. **Secret leakage in tooling output:** `podman-compose` echoes the fully substituted
   `podman run` command, including environment secrets, to stdout; the launcher did not
   redact it.

## Baseline reproduction (pre-change)

- `podman inspect mtmf_postgres_1` showed `0.0.0.0:25432->5432/tcp`.
- `podman ps` for the standard stack showed no `keycloak`/`forwarder`/`service`
  containers after a failed `up`.
- `python scripts/mtmf-dev-stack.py up` failed at the PostgreSQL-health poll with the
  `AttributeError` above.
- Container `/etc/hosts` (e.g. `podman run --rm --network mtmf_default <image> cat
  /etc/hosts`) contained the host's `127.0.0.1 keycloak.mtmf.test` line, confirming the
  shadowing hazard.

The fresh `main` facts in the execution plan matched the tree; no material divergence
required a STOP before implementation.

## Prior-art reconciliation

PR 17 Amendment #2/#3 had already investigated a canonical `keycloak.mtmf.test`
issuer and recorded it as BLOCKED on host `/etc/hosts` control (no passwordless
`sudo`) and on the issuer-identity change (STOP-01). PR 17-C resolves both: the
operator supplied the Windows/WSL `hosts` mapping, the issuer identity change is the
explicit purpose of the PR, and the containers no longer depend on host DNS because the
canonical authority is pinned to the MTMF-owned forwarder.
