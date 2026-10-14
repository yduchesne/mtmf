# PR19C_AMENDMENT04_LIVE_ACCEPTANCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Status:** **COLD-01, REPEAT-01 and RECREATE-01 all EXECUTED and PASSED**, zero skips, on the isolated acceptance topology.

## Exact harness

```
uv run --no-sync python scripts/mtmf-pr19c-live.py acceptance-pr19c
# internally: reset -> up -> test; up -> test; reset -> up -> test
# test: uv run --no-sync pytest tests/integration/postgres/test_pr19c_live_management.py -q --no-cov
```

Environment: acceptance-only project `mtmf-pr19c-acceptance`, issuer `https://keycloak.mtmf.test:29443/realms/mtmf-dev`, real Keycloak 26.8.0-1, real PostgreSQL 18 (`mtmf_runtime`), real Uvicorn service on `127.0.0.1:29001`, v012 schema.

## Results (exact output)

```
4 passed in 8.57s
COLD-01 PASS
4 passed in 7.34s
REPEAT-01 PASS
4 passed in 8.59s
RECREATE-01 PASS
default stack inventory unchanged
```

Four test functions cover **five scenarios** H01–H05:

| Phase | H01 201+audit | H02 200 no-op | H03 non-steward 403 | H04 cross-Tenant 403 | H05 bad token |
| --- | --- | --- | --- | --- | --- |
| COLD-01 | PASS | PASS | PASS | PASS | PASS |
| REPEAT-01 | PASS | PASS | PASS | PASS | PASS |
| RECREATE-01 | PASS | PASS | PASS | PASS | PASS |

Zero skipped/xfailed. Real Keycloak service + authorization-code user tokens; no mocked issuer/authorizer/SPI/database.

## Lifecycle assertions

- **COLD-01**: no acceptance containers/volumes/CA/secrets existed; the orchestrator created a fresh realm, project-scoped volumes and ran H01–H05.
- **REPEAT-01**: `up` without reset retained the acceptance volumes/containers (same `State.StartedAt`), reused validated secrets, and H01–H05 passed again.
- **RECREATE-01**: `reset` verified ownership, removed only the two acceptance project volumes (`podman volume ls` showed them absent), recreated CA/secrets/realm/DB from scratch, and H01–H05 passed.
- Default `mtmf` stack inventory was byte-identical before/after.
