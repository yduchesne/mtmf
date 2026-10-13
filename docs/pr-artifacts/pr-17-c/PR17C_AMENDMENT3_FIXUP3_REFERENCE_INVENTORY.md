# PR 17-C Amendment 3 Fixup 3 — Reference Inventory

`git grep -n 'mtmf-pr14-dev' -- ':!docs/pr-artifacts/**'` classified each
occurrence. Only **standard-stack active** references changed; the independent
PR 14 evidence-only fixture and historical evidence were preserved.

| Location | Count | Class | Disposition |
| --- | --- | --- | --- |
| `scripts/mtmf-dev-stack.py` | — | Standard stack active | Changed `CANONICAL_KC_ISSUER`; added `CANONICAL_KC_REALM`/`CANONICAL_KC_JWKS_URI` + exact validation |
| `scripts/mtmf-dev-probe.py` | 1 impl + docstring | Standard stack active | Changed to `mtmf-dev` |
| `scripts/mtmf-dev-initialize.py` | 2 | Standard stack active | Changed defaults to `mtmf-dev`; added realm/issuer consistency check |
| `scripts/mtmf-dev-admin-migrate.py` | 1 (`TARGET_REALM`) | Standard stack active | Changed to `mtmf-dev` |
| `.env.example` | 3 | Standard stack active docs | Changed issuer/JWKS/realm to `mtmf-dev` |
| `compose.dev.yaml` | 1 comment + 2 defaults | Standard stack active | Changed to `mtmf-dev` |
| `dev/keycloak/expected-realm-security.json` | 1 (`"realm"`) | Standard stack active | Changed to `mtmf-dev` (standard-stack manifest only) |
| `docs/DEVELOPMENT_SETUP.md` | 5 | Standard stack active docs | Changed to `mtmf-dev`; added realm/reset section |
| `docs/ROADMAP_V01.md` | status | Normative docs | Updated (Fixup 3 entry) |
| `dev/keycloak/README.md` | 1 cross-reference + 1 fixture cert CN | Standard-stack cross-reference / fixture | Cross-reference updated; fixture certificate CN preserved |
| `dev/keycloak/compose.yaml` | 0 (`MTMF_PR14_KC_ADMIN_*`) | Independent PR 14 fixture | **Unchanged** |
| `dev/keycloak/setup-realm.py` | `DEFAULT_REALM` | Independent PR 14 fixture | **Unchanged**; standard stack passes `--realm mtmf-dev` |
| `dev/keycloak/expected-config-manifest.json`, `expected-realm-security.json` historical evidence, `evidence/*.json` | many | Historical evidence / fixture | **Unchanged** |
| `scripts/pr14-*.py` (G0-A, token-class, keycloak evidence) | many | PR 14 evidence tooling | **Unchanged** |
| `tests/evidence/test_pr14_*.py` | many | PR 14 fixture tests | **Unchanged** |
| `tests/unit/authentication/*`, `tests/unit/service/conftest.py`, `test_development_bootstrap.py`, `test_pr17b_*` | many | Test fixture (realm-agnostic) | **Unchanged** (arbitrary fixture realm) |
| `tests/integration/postgres/test_postgres_authentication_bindings.py` | 9 | Test fixture (DB data) | **Unchanged** |
| `tests/integration/postgres/test_pr17_dev_initializer.py`, `test_pr17b_compose_isolation.py` | several | Fixture/test (gated) | **Unchanged** (not standard-stack live) |
| `tests/unit/service/test_pr17c_dev_*.py`, `tests/integration/pr17c_forwarder_reliability.py` | several | Standard-stack tests | **Changed** to `mtmf-dev` |
| `tests/integration/postgres/test_pr17_live_http.py`, `test_pr17b_live_acceptance.py`, `test_pr17_attestation_reader_permissions.py`, `pr17b_fault_proxy.py` | 1 each | Standard-stack live harness | **Changed** to `MTMF_AUTH_ADMIN_REALM`-driven with `mtmf-dev` default |
| `tests/integration/postgres/test_pr14_live_actor_context.py` | 1 | PR 14 live harness | Realm now `MTMF_AUTH_ADMIN_REALM`-driven, default `mtmf-pr14-dev` (fixture preserved) |
| `docs/pr-artifacts/**` | many | Historical evidence | **Unchanged** |

No call site was left unclassified; no blind global replacement was performed.
