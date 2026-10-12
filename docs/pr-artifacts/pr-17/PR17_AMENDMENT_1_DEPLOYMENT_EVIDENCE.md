# PR 17 — Amendment #1: development deployment evidence (G3)

**Status: PARTIAL — executed host-run deployment against Podman-hosted
PostgreSQL 18 + live Keycloak; containerized Compose path implemented but not
fully executed.**

## 1. Portable orchestration (resolves the unsupported Compose condition)

`podman-compose 1.0.6` does not honor
`depends_on: condition: service_completed_successfully`. The new
`scripts/mtmf-dev-stack.py` launcher performs the ordering explicitly and
fails closed at each step:

```
postgres + keycloak up  ->  wait for PostgreSQL health + Keycloak discovery
->  privileged one-shot initializer (migrations + postflight + fixtures)
->  unprivileged service up  ->  wait for /health/ready 200
```

`compose.dev.yaml` now uses `condition: service_started` for the service and
documents that the launcher, not Compose, enforces the ordering. The launcher
manages only the explicit `mtmf` project, binds loopback, and keeps the MTMF
prefix-2 host ports (`25432`, `28080`, `28443`, `28001`).

## 2. Executed evidence

| Step | Command (redacted environment) | Result |
| --- | --- | --- |
| Build image | `podman build -f Dockerfile.service -t mtmf-service:dev .` | exit 0, image `localhost/mtmf-service:dev` |
| Start issuer | `podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml up -d` | exit 0; `mtmf-pr14-keycloak_keycloak_1` up on `127.0.0.1:28080/28443` |
| Configure realm | `python dev/keycloak/setup-realm.py` | exit 0; realm `mtmf-pr14-dev`, clients and users created |
| Fresh initializer | `python scripts/mtmf-dev-initialize.py` (fresh schema) | exit 0 |
| Idempotent re-run | same command again | exit 0; no duplicates (below) |
| Secret delivery | `MTMF_DEV_SECRET_DIR=/tmp/mtmf-dev-secrets` | `/tmp/mtmf-dev-secrets/mtmf-sample-app.secret` mode `0600`, never printed |
| Service readiness | `.venv/bin/python -m mtmf_service` with runtime role | `/health/live` 200, `/health/ready` 200 only after initialization |

## 3. Fresh-state fixture verification (sanctioned reads)

After the fresh initializer run, the real PostgreSQL state was:

| Object | Count / value |
| --- | --- |
| `root_registry` | 1 |
| ordinary Tenants (`scope=2`) | 1, `lifecycle=1` (ACTIVE) |
| Applications | 1 |
| Application-Tenant registrations | 1 |
| TenantApplicationSubscriptions | 1, `lifecycle=1` (ACTIVE) |
| active service-credential bindings | 1 |
| active external-subject bindings | 1 |
| stewardship designations | 1 |

The second initializer run produced identical counts and left the Keycloak
client and secret untouched (no rotation). The concurrent PostgreSQL
serialization/idempotency/conflict cases are additionally covered by
`tests/integration/postgres/test_pr17_dev_initializer.py` (3 passed).

## 4. Negative/blocked cases

| Case | Result |
| --- | --- |
| Conflicting existing root | fails closed (`test_dev17_initializer_rejects_conflicting_root`) |
| Incomplete/partial privileged state | reconciled idempotently or fails closed by design; conflicting Application/registration/subscription bindings raise `BootstrapError` |
| PostgreSQL unavailable | `apply_migrations_and_verify` / SPI acquisition fails closed; readiness false |
| Keycloak unavailable | initializer `ensure_client`/`verify_issuer` fails closed; readiness false |
| Issuer manifest drift | live HTTP `test_v07_manifest_mismatch_fails_closed` → 503 |
| Runtime role broad SQL | covered by `tests/integration/postgres/test_postgres_runtime_security.py` and `test_runtime_privileges.py` (75-signature allowlist) |
| Containerized fresh `up` via Compose | **NOT EXECUTED** — blocked by issuer hostname networking (see §5) |

## 5. Blockers and scope limits

- **Keycloak hostname inside containers:** the trusted issuer is
  `https://127.0.0.1:28443/...`; from inside a service container this resolves
  to the container itself. Running the ASGI service on the host over loopback
  (explicitly permitted for development) avoids this. A container-to-container
  deployment requires a reviewed issuer/frontend-URL and network-alias design.
- **`compose.dev.yaml` container path** is provided but was **not** executed end
  to end; only the image build and the host-run service were executed.
- **Fresh MTMF volume destroy/recreate (V13)** was not executed; the clean
  schema was reset without dropping the cluster-wide MTMF roles.
- **Host-run service environment:** the readiness demonstration used the
  restricted `mtmf_runtime` role; a formal proof that the service process
  environment excludes migrator/admin variables was not captured (the Compose
  file scopes them to the initializer only, and the runtime role privilege
  surface is independently verified by the integration suite).
- Production profile and production root recovery remain disabled; nothing
  here is production-ready.
