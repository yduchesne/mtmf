# PR 17-B Baseline Report

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Base commit:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3` (`origin/main`, merge PR #51)
**Implementation commit:** `362aae664c4f76a88c69ae25421249346b5591c7`
**Branch:** `dev/pr17b-keycloak-user-provisioning`
**Date:** 2026-10-12
**Author:** coding agent

## 1. Baseline reconciliation

- Fetched `origin/main`; `HEAD` and `origin/main` were the same commit (`b60c50b`), a clean
  working tree (`git status --short` empty).
- Created the implementation branch `dev/pr17b-keycloak-user-provisioning` from that commit.
- Read the authoritative sources before editing: `AGENTS.md`, `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`,
  `docs/ROADMAP_V01.md` (PR 17, 17-B, 18, 20), `docs/DEVELOPMENT_SETUP.md`, `docs/ARCHITECTURE.md`,
  `docs/SECURITY_MODEL.md`, `docs/DATABASE.md`, `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`, and the
  detailed PR 17-B plan.
- No material drift from the plan's verified source-level baseline was found. Proceeded.

## 2. Actual existing implementation inspected

- `scripts/mtmf-dev-initialize.py` — `KeycloakCredentialProvisioner` (admin-cli password grant, Admin REST
  `_request`, approved-policy client provisioning/attestation, owner-only secret delivery), `_dev_fixture`
  (which used `os.environ.get("MTMF_DEV_USER_SUBJECT", "mtmf-dev-user")`), `PostgresProvisioner`
  (`ensure_root`, `ensure_ordinary_tenant`, `ensure_user_binding`, `ensure_application`,
  `ensure_registration_and_subscription`, `ensure_service_binding`), and `main`.
- `packages/mtmf-service/src/mtmf_service/development_bootstrap.py` — `DevelopmentBootstrap.run`,
  `BootstrapFixture`, `UserFixture`, `ProvisioningPort`, `CredentialPort`, `LockPort`, exception
  conversion, lock behavior and ordering.
- `compose.dev.yaml`, `scripts/mtmf-dev-stack.py`, `Dockerfile.service`, `.env.example`,
  `dev/keycloak/setup-realm.py`, `dev/keycloak/expected-realm-security.json`,
  `dev/keycloak/expected-client-policy.json`, `dev/keycloak/README.md`.
- Existing tests: `tests/unit/service/test_development_bootstrap.py`,
  `tests/integration/postgres/test_pr17_dev_initializer.py`,
  `tests/integration/postgres/test_pr14_live_actor_context.py`,
  `tests/integration/postgres/test_pr17_live_http.py`,
  `tests/integration/postgres/test_pr17_attestation_reader_permissions.py`.

### Key source-level findings

- The Admin REST seam is `KeycloakCredentialProvisioner._request()`; the plan requires reuse and forbids a
  second authentication implementation.
- `PostgresProvisioner.acquire()` opens a **session-level** `pg_advisory_lock` on an `autocommit=True`
  connection (no PostgreSQL transaction is held), and `DevelopmentBootstrap.run()` holds that advisory
  lock across the existing `ensure_client` / `verify_issuer` remote calls.
- The realm-security projection (`dev/keycloak/expected-realm-security.json`) contains `realmSecurity`,
  `clientScopes`, and `realm` fields only; **it does not include users**, so creating a development user
  does not change the approved trust projection. The expected-client policy is likewise unaffected.
- `compose.dev.yaml` did not forward `MTMF_DEV_TENANT_KEY`/`MTMF_DEV_TENANT_NAME` even though
  `_dev_fixture()` read them, and passed a fabricated `MTMF_DEV_USER_SUBJECT` default of `mtmf-dev-user`.

## 3. Baseline gate execution

All gates were run from the base commit before any edit.

| Gate | Command | Result |
| --- | --- | --- |
| Bootstrap | `uv sync --locked` | applied |
| QA | `./build.sh --qa` | **PASS** — 1517 passed, 177 skipped, coverage 90.21% (native tests skipped because `_mtmf_permission_engine` was not yet installed at this point) |
| Security | `./build.sh --sec` | **PASS** — Bandit 0 Medium/High, Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, installed-native probe, focused tests, clean wheel build/install/use, benchmark smoke |
| Integration | `set -a; . ./.env; set +a; ./build.sh --integration` | **PASS** — 564 passed, 51 skipped |
| Live PR 14/17 | — | **NOT RUN at baseline** (opt-in flags `MTMF_PR14_LIVE`/`MTMF_PR17_LIVE` unset; live Keycloak was not running) |

Note: after `./build.sh --rust` installs the native module, the unit suite executes the previously skipped
native tests (final QA on the implementation commit: 1861 passed).

## 4. Environment used for live acceptance

- MTMF-owned PostgreSQL container `mtmf_postgres_1` published on prefix-2 loopback port `25432`.
- MTMF-owned Keycloak project `mtmf-pr14-keycloak` (image `quay.io/keycloak/keycloak:26.8.0-1`) with
  persisted volume `mtmf-pr14-keycloak-data`, realm `mtmf-pr14-dev`, loopback ports `28080`/`28443`,
  self-signed TLS from `/tmp/mtmf-pr14-kc-tls/server.crt`.
- Live Keycloak admin/user credentials supplied through the operator's `/tmp/mtmf-pr14-kc.env`; PostgreSQL
  role configuration through the repository `.env`. No secret is reproduced in this report.

## 5. Conclusion

No drift, no blocking STOP condition at baseline. Proceeded to implementation.
