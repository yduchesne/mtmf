# PR 17-C Amendment 3 Fixup 2 — Configuration Inventory

Every tracked reference to the administrator-related identifiers was classified
before any edit. Only **standard-stack active configuration** and its tests/docs
were changed; the PR 14 evidence-only fixture and historical reports were
preserved.

| Location | Identifier(s) | Class | Treatment |
| --- | --- | --- | --- |
| `compose.dev.yaml` (keycloak) | `MTMF_PR14_KC_ADMIN_USERNAME/PASSWORD` | Standard stack active | **Changed** to `MTMF_DEV_KC_ADMIN_USERNAME` (default `mtmf-admin`) / `MTMF_DEV_KC_ADMIN_PASSWORD` |
| `compose.dev.yaml` (initializer) | `MTMF_AUTH_ADMIN_USERNAME/PASSWORD` | Standard stack active | **Kept**; username default `mtmf-admin`, password required; launcher enforces same account/credential |
| `compose.dev.yaml` (initializer) | `MTMF_PR14_KC_ADMIN_USERNAME/PASSWORD` | Standard stack active (unused) | **Removed** (not read by the initializer or its dependencies) |
| `.env.example` | `MTMF_AUTH_ADMIN_*`, `MTMF_PR14_KC_ADMIN_*` | Standard stack active docs | **Changed** to `MTMF_DEV_KC_ADMIN_*` + `MTMF_AUTH_ADMIN_*` canonical, passwords commented |
| `scripts/mtmf-dev-stack.py` | new validation | Standard stack active | **Added** `_require_canonical_dev_admin()` (rejects legacy/empty/whitespace/uppercase and mismatched initializer identity/credential) |
| `scripts/mtmf-dev-admin-migrate.py` | new tool | Standard stack active | **Added** development-only `--inspect`/`--apply` migration |
| `scripts/mtmf-dev-initialize.py` | `MTMF_AUTH_ADMIN_USERNAME/PASSWORD` | Standard stack active | **Preserved** (initializer Admin REST interface) |
| `packages/mtmf-service/.../authentication/config.py` | `MTMF_AUTH_ADMIN_REALM/BASE` | Standard stack active | **Preserved** (non-secret realm/base) |
| `dev/keycloak/compose.yaml` | `MTMF_PR14_KC_ADMIN_USERNAME/PASSWORD` | Independent PR 14 fixture | **Preserved unchanged** |
| `dev/keycloak/setup-realm.py`, `dev/keycloak/README.md` | `MTMF_PR14_KC_ADMIN_*` | Independent PR 14 fixture | **Preserved unchanged** |
| `scripts/pr14-g0a-mapper-attestation.py`, `scripts/pr14-g0-token-class-evidence.py` | `MTMF_PR14_KC_ADMIN_*` | PR 14 evidence tooling | **Preserved unchanged** |
| `tests/integration/postgres/test_pr17b_live_acceptance.py`, `test_pr14_live_actor_context.py`, `test_pr17_live_http.py` | `MTMF_PR14_KC_ADMIN_*` | Test fixture (regression harness) | **Preserved**; the canonical admin is supplied via environment at run time |
| `tests/integration/postgres/test_pr17b_compose_isolation.py` | `MTMF_PR14_KC_ADMIN_PASSWORD` | Test fixture (standard stack) | **Updated**: removed from `_INITIALIZER_SECRETS`; added `MTMF_DEV_KC_ADMIN_PASSWORD` to `_FORBIDDEN_ON_SERVICE` |
| `tests/unit/service/test_pr17b_initialize_script.py` | `MTMF_PR14_KC_ADMIN_*` | Test fixture | **Preserved** (forbidden-on-service list only) |
| `tests/unit/authentication/test_config.py` | `MTMF_AUTH_ADMIN_*` | Test fixture | **Preserved** |
| `tests/unit/service/test_pr17c_dev_stack.py` | new CA-U01–CA-U08 | Test | **Added** |
| `tests/unit/service/test_pr17c_dev_admin_migrate.py` | new CA-U09–CA-U32 | Test | **Added** |
| `docs/DEVELOPMENT_SETUP.md` | admin guidance | Normative docs | **Updated** with the canonical-admin section |
| `docs/ROADMAP_V01.md` | status | Normative docs | **Updated** (Fixup 2 status; N17/N18 optional) |
| `docs/pr-artifacts/pr-17-c/**` | historical reports | Historical evidence | **Preserved unchanged** |

## Grep baseline

Searched tracked source/config/test/docs for `mtmf-pr14-admin`,
`mtmf-pr14-admin2`, `MTMF_PR14_KC_ADMIN_USERNAME`, `MTMF_PR14_KC_ADMIN_PASSWORD`,
`MTMF_AUTH_ADMIN_USERNAME`, `MTMF_AUTH_ADMIN_PASSWORD`,
`KC_BOOTSTRAP_ADMIN_USERNAME`, `KC_BOOTSTRAP_ADMIN_PASSWORD`, and
`MTMF_DEV_KC_ADMIN_`. No blind global replacement was performed; the PR 14
fixture identifiers were deliberately retained.
