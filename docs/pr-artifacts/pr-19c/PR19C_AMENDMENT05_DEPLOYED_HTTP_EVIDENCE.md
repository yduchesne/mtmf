# PR19C_AMENDMENT05_DEPLOYED_HTTP_EVIDENCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Status:** deployed-service H01–H05 executed in all three lifecycle phases, **4 passed / 0 skipped** each.

## Topology

Real Keycloak `https://keycloak.mtmf.test:29443/realms/mtmf-dev` (TLS verified, exact issuer/JWKS) -> Compose-managed MTMF `service` on `http://127.0.0.1:29001` running as the restricted `mtmf_runtime` role -> PostgreSQL 18 `127.0.0.1:29432`. The test process is a separate privileged fixture seeder/reader; it never constructs an MTMF app.

## Exact command

```
uv run python scripts/mtmf-pr19c-live.py acceptance-pr19c
# performs: reset -> up -> test; up -> test; reset -> up -> test
```

## Results (exact output)

```
4 passed in 8.95s
acceptance service container 59f9a47004ef: 4 passed, 0 skipped
COLD-01 PASS
4 passed in 6.66s
acceptance service container 59f9a47004ef: 4 passed, 0 skipped
REPEAT-01 PASS
4 passed in 7.76s
acceptance service container 7c1755ca49e6: 4 passed, 0 skipped
RECREATE-01 PASS
default stack inventory unchanged
```

`service` container identity: COLD/REPEAT `59f9a47004ef` (same container across repeat, proving no recreate); RECREATE `7c1755ca49e6` (fresh). Published binding verified read-only as `127.0.0.1:29001 -> 28001` with project label `mtmf-pr19c-acceptance` before pytest.

Separate standalone repeat: `uv run python scripts/mtmf-pr19c-live.py test` -> `4 passed in 10.27s`, `acceptance service container 8aaa7909dc04: 4 passed, 0 skipped`.

## H01–H05 (five scenarios, four tests)

| Case | HTTP result | Committed-state assertion |
| --- | --- | --- |
| H01 | 201 `created:true`, no-store | exactly one membership; exactly one matching audit row (actor=steward, exact Action, target=group, subject=identity, outcome CREATED) |
| H02 | 200 `created:false` | membership still one; matching audit rows still one |
| H03 | 403 `FORBIDDEN` | zero target membership; zero matching audit |
| H04 | 403 `FORBIDDEN` | no cross-Tenant disclosure; zero target/other-group membership and audit |
| H05 | 401/403 missing/wrong-slot token | zero target membership; zero matching audit |

Fixture rows are committed by the autocommit privileged test connection before each request; audit assertions are scoped to this test's target and exact Action rather than a global table count.
