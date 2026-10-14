# PR19C_AMENDMENT02_LIVE_ACCEPTANCE

**PR:** roadmap PR 19C.
**Date:** 2026-10-14.
**Status:** **BLOCKED — H01–H05 NOT EXECUTED.** No live Keycloak acceptance run was performed, so it is not reported as PASS.

## 1. Required live topology (Amendment 02 §6)

- real development Keycloak issuer and real Uvicorn/ASGI service process;
- real PostgreSQL 18, `mtmf_runtime` restricted login, schema migrated through v012;
- approved seeded Action/Permission/Role, live test Identities/bindings/registrations/subscriptions and stewardship.

## 2. What was available in this environment

| Requirement | Available? |
| --- | --- |
| PostgreSQL 18 + provisioned roles + v012 schema | YES (`mtmf_postgres_1`, host `127.0.0.1:25432`) |
| Real Uvicorn/ASGI app from `create_app_from_env` | YES (buildable) |
| Keycloak container | Exited (`mtmf_keycloak_1`); volume `mtmf-dev-keycloak-data` exists |
| `MTMF_AUTH_*` / `MTMF_DEV_KC_ADMIN_PASSWORD` | **NO** — not present in `.env`; operator-generated dev-only secret, not committed |
| `MTMF_PR14_KC_ADMIN_PASSWORD` / `MTMF_PR14_KC_USER_PASSWORD` / `/tmp/mtmf-pr14-kc.env` | **NO** — the isolated fixture env file is absent; passwords are generated per run (`dev/keycloak/README.md`) |
| Canonical issuer hostname `keycloak.mtmf.test:28443` + forwarder/TLS | Not running; requires the host-network launcher and trust-store setup |
| `MTMF_PR17_LIVE=1` / `MTMF_PR19C_LIVE=1` opt-in | Not set |

The standard development stack (`scripts/mtmf-dev-stack.py up`) requires `MTMF_DEV_KC_ADMIN_PASSWORD` to equal the stored canonical `mtmf-admin` credential and `MTMF_AUTH_ADMIN_PASSWORD` to match it, plus the canonical issuer base and container-resolved database URLs. The isolated PR 14 fixture requires freshly generated admin/user passwords and TLS material, then realm/client/user provisioning. Neither credential set is present, and generating new bootstrap passwords does not authenticate against the already-initialized Keycloak volumes.

## 3. Decision

Amendment 02 §10 STOP condition (8) applies: "the live Keycloak acceptance harness cannot run or H01–H05 cannot be exercised". Per the live gate rule ("If the harness cannot execute, mark BLOCKED, not DONE"), H01–H05 remain **NOT EXECUTED** and PR 19C is **not DONE**.

Smallest human decision required: provide (or authorize retrieval of) the development Keycloak administrator/user credentials and the canonical issuer configuration, and confirm the supported host-network/forwarder setup may be started, so H01–H05 can be executed against the real issuer.

## 4. What is proven instead (not a substitute)

- HTTP contract, DTO/codec, transport guards, status selection, opaque denial, bounded admission/timeout and single terminal management telemetry: deterministic unit suite (`tests/unit/service/test_management_http.py`, `tests/unit/api/test_api_management_dtos.py`).
- Real restricted-runtime persistence, atomic audit, duplicate no-op, rollback, guard rejection and concurrent duplicate: `tests/integration/postgres/test_pr19c_management_membership.py` on `mtmf_runtime`.
- Lock-conflict proof: `PR19C_CONCURRENCY_PROOF.md`.

These are necessary but are explicitly **not** accepted as H01–H05 live feature acceptance.
