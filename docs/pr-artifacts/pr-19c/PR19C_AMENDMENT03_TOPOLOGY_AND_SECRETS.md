# PR19C_AMENDMENT03_TOPOLOGY_AND_SECRETS

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

## Canonical topology (validated live)

Host test runner / live HTTP client -> TLS-verified `https://keycloak.mtmf.test:28443/realms/mtmf-dev` (MTMF-owned Keycloak 26.8.0-1 + TCP forwarder) -> real Uvicorn service (development mode, restricted `mtmf_runtime`) -> PostgreSQL 18 with the v012 audited stored function.

The host resolves `keycloak.mtmf.test` to loopback; TLS uses `/tmp/mtmf-dev-ca/dev-ca.crt` (CN/SAN `keycloak.mtmf.test`, `localhost`, `127.0.0.1`). No OS DNS/trust file is edited by any tool.

## Resource ownership

- Default Compose project `mtmf` (persistent development stack; volumes preserved).
- Disposable acceptance project `mtmf-pr19c-acceptance` (orchestrator). Postgres is project-scoped and disposable. **Keycloak is not isolated** because `compose.dev.yaml` gives its volume a global name.

## Secret lifecycle

- The orchestrator stages secrets in an owner-only `0700` directory with `0600` files (`admin_password`, `user_password`, `dev-user-password`).
- `MTMF_DEV_KC_ADMIN_PASSWORD` must equal `MTMF_AUTH_ADMIN_PASSWORD` (the canonical `mtmf-admin` bootstrap/reconcile credential); the orchestrator supplies it automatically and never asks a human.
- Secrets are passed to child processes through the environment only; `_redact` scrubs generated secret values from every captured/printed subprocess line and error message (`SECRET-01` verified: the generated admin/user password appears zero times in the acceptance logs).
- The HTTP service environment never receives the bootstrap admin or migrator credentials (Compose separation retained).
- Cleanup removes the run directory; the `--keep` diagnostic retains the fixture containers but still removes secrets on the next `--fresh` teardown.
