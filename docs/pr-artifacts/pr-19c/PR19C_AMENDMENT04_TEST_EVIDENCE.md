# PR19C_AMENDMENT04_TEST_EVIDENCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

## Authoritative gates (final HEAD)

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — 2439 passed, coverage 90.45% |
| `./build.sh --sec` | PASS — 0 findings |
| `./build.sh --rust` | PASS (pre-commit hook) |
| `./build.sh --integration` | PASS — 574 passed, 90 skipped (live opt-in skipped, as designed) |
| `scripts/mtmf-pr19c-live.py acceptance-pr19c` | PASS — COLD/REPEAT/RECREATE, H01–H05 zero skips |

## ISO matrix

| ID | Check | Coverage | Result |
| --- | --- | --- | --- |
| ISO-01 | external/global volume in Compose | `_validate_compose_isolation` unit (external + global name) | PASS |
| ISO-02 | acceptance volume resolves to default | actual `podman inspect` mounts (project-scoped, default untouched) | PASS |
| ISO-03 | resource project label mismatch | `_assert_owned` refuses non-acceptance names | PASS (unit + live) |
| ISO-04 | default stack active during acceptance | `_default_inventory` before/after | PASS (live) |
| ISO-05 | host port owned by foreign process | `_ports_free` fails without killing | implemented |
| ISO-06 | issuer != discovery/token iss | exact `--expected-issuer` probe + issuer constants | PASS |
| ISO-07 | wrong CA/SAN | probe TLS verification (no insecure fallback) | PASS (live) |
| ISO-08 | partial/invalid acceptance cert set | `mtmf-dev-certs.py check` fails closed | implemented |
| ISO-09 | secret symlink/bad mode/foreign owner | `_stage_secrets` enforces 0600 | PASS (unit) |
| ISO-10 | target default project via acceptance command | `ACCEPTANCE_PROJECT != "mtmf"` unit | PASS |
| ISO-11 | `down` preserves volumes | `down` uses `down` (no `-v`) | implemented |
| ISO-12 | `reset` removes only acceptance | `reset` uses project-scoped `down -v` + ownership check | PASS (live) |
| ISO-13 | issuer unavailable | bounded readiness failure, no mutation | implemented |
| ISO-14 | default launcher unchanged | `mtmf-dev-stack.py` PROJECT/issuer/COMPOSE_FILES unit | PASS |

## Failure classification

No failing mandatory gate. The prior Amendment 03 COLD-01 failure (global Keycloak volume name) is resolved by the standalone Compose model; it is not reclassified.

## Executed vs skipped

- Executed: canonical gates, isolated acceptance lifecycle, live H01–H05 (three phases), orchestrator unit tests.
- Skipped: the same live tests inside `--integration` (by design, opt-in); not counted as H01–H05 evidence there.
