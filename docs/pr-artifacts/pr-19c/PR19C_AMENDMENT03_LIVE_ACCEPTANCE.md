# PR19C_AMENDMENT03_LIVE_ACCEPTANCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Status:** **H01–H05 EXECUTED AND PASSED** against the real canonical development Keycloak + real PostgreSQL 18 + real Uvicorn service. The disposable cold-start orchestration remains BLOCKED (see `PR19C_AMENDMENT03_STOP_REPORT.md`).

## Topology used

Canonical MTMF development stack (`mtmf` project): real Keycloak `https://keycloak.mtmf.test:28443/realms/mtmf-dev` (image `quay.io/keycloak/keycloak:26.8.0-1`), real PostgreSQL 18 restricted `mtmf_runtime`, v012 schema, in-process real Uvicorn via `create_app` with the production `ManagementMembershipHttpService`. The `mtmf-dev` realm was reconciled with `dev/keycloak/setup-realm.py --realm mtmf-dev --allow-nonlocal`.

## Exact command

```
MTMF_PR19C_LIVE=1 \
MTMF_PR14_KC_BASE=https://keycloak.mtmf.test:28443 \
MTMF_PR14_KC_ADMIN_USERNAME=mtmf-admin \
MTMF_PR14_KC_ADMIN_PASSWORD=<redacted> \
MTMF_PR14_KC_USER_PASSWORD=<redacted> \
MTMF_PR14_KC_CA_FILE=/tmp/mtmf-dev-ca/dev-ca.crt \
MTMF_AUTH_ADMIN_REALM=mtmf-dev \
SSL_CERT_FILE=/tmp/mtmf-dev-ca/dev-ca.crt \
uv run --no-sync pytest tests/integration/postgres/test_pr19c_live_management.py -q --no-cov
```

Result: **4 passed, 0 skipped, 0 failed.**

## Case evidence

| Case | Test | Result | Committed-state assertion |
| --- | --- | --- | --- |
| H01 | `test_h01_h02_live_created_then_authorized_no_op` (first request) | **201** with `created:true`, `Cache-Control: no-store` | exactly one membership row and exactly one `security_mutation_audit` row with verified actor/Action/target/subject/outcome `CREATED` |
| H02 | same test, repeated request | **200** with `created:false` | membership still one; audit count unchanged (1) |
| H03 | `test_h03_non_steward_actor_is_opaque_forbidden` | **403 `FORBIDDEN`** | zero membership, zero audit |
| H04 | `test_h04_cross_tenant_target_is_denied_without_disclosure` | **403 `FORBIDDEN`** | zero audit; no target disclosure |
| H05 | `test_h05_invalid_or_wrong_slot_tokens_never_succeed` | **403** missing user token; **403** wrong token class | zero membership, zero audit |

All tokens were obtained from the live issuer via OAuth client credentials (service) and authorization-code flow (acting user, `mtmf-user-bob` steward / `mtmf-user-carol` non-steward). No mocked issuer, authorizer, SPI or database was used. The actor's Keycloak `sub` was bound through `external_subject_identity`; the service client through `service_credential_application`; the Tenant Administrator Role and steward designation supplied the approved guard.

## Verification notes

- Real PostgreSQL inspection used the administrator connection; the HTTP service used only `mtmf_runtime`.
- The legacy unaudited `identity_group_membership_add` is not runtime-executable (v012); the audited function is the only mutation path.
- Each test starts from a freshly migrated schema and seeds its own fixture; no cross-test coupling.

This supersedes the `BLOCKED` H01–H05 status recorded in `PR19C_AMENDMENT02_LIVE_ACCEPTANCE.md`.
