# PR 17-B Security Report

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Implementation commit:** `362aae664c4f76a88c69ae25421249346b5591c7` (core) + `9e074fb09e92b1db37f96496f3f256ef49196e1a` (brokered-account hardening); final tip `9e074fb09e92b1db37f96496f3f256ef49196e1a`

## 1. Trust model

Keycloak owns authentication and the immutable OIDC `sub`. MTMF owns its Principal, Identity, Tenant
membership, stewardship, and authorization state. The privileged development one-shot is the only
component that may create/verify a Keycloak user and the only component that holds the Keycloak admin
credential. The long-running HTTP service and consuming applications never receive admin, root, migrator,
owner, or development-user password material.

## 2. Invariants and how they are enforced

| Invariant | Enforcement |
| --- | --- |
| Development-only provisioning | `main()` checks `DeploymentMode.DEVELOPMENT` and returns before constructing any privileged object in any other profile; `DevelopmentBootstrap` re-checks. Unit test `test_u16_production_profile_is_refused_before_any_keycloak_or_db_work`. |
| Keycloak `sub` is authoritative | The verified Keycloak user `id` is passed as `UserFixture.subject`; the fabricated `mtmf-dev-user` fallback is removed. `MTMF_DEV_USER_SUBJECT` is an assertion only. |
| No mutation of an existing user | The existing-user path only reads and validates; the password file is not opened. Tests U01/U04/U22 and live I05/I08. |
| No fabricated or asserted identity | Exact lookup + optional exact-equality assertion before any MTMF write. Tests U07, live I07. |
| Deny/fail closed | Missing user + creation disabled, ambiguity, disabled/federated/drifted account, unsafe secret, malformed response, HTTP/network failure, and subject mismatch all raise `BootstrapError`. |
| No privileged credential to runtime/ATI | The `MTMF_DEV_USER_*`/`MTMF_AUTH_ADMIN_*`/`MTMF_PR14_KC_ADMIN_*` variables are present only in the `initializer` service; unit test `test_u26_service_never_receives_privileged_or_provisioning_configuration` inspects `compose.dev.yaml`. |
| Preserve approved trust | The realm-security projection does not include users; no realm/client policy or attestation file was changed. Live PR 14/17 suites pass. |
| No new DB privilege/schema | No migration, stored function, grant, or direct SQL mutation was added. |

## 3. Secret handling

- The initial password is read only for creation, from a path that must be a regular file, not a symlink or
  directory, owned by the initializer user, not group/other-accessible, bounded to 8 KiB, valid UTF-8, and
  non-empty. Tests `test_u11_*`, `test_password_file_*`.
- The password and user record are never logged, echoed, or placed in exception messages. The POST body is
  constructed in memory only.
- Compose never contains a plaintext password: it forwards the container path and mounts the host secret
  directory read-only. `.env.example` uses an owner-only-file path, not a password value.
- HTTP error bodies are not surfaced. `_call`/`_create_once` report only the status code or a generic
  transport reason. Live negative test: wrong admin credential produced
  `"the development issuer preflight failed with HTTP 400"` with no credential material.
- Admin REST responses and token responses are bounded to 1 MiB.

## 4. Fail-closed negative coverage

Unit: HTTP 401/403/404/5xx, network failure, malformed JSON, non-list/non-object payloads, missing ID,
non-boolean `enabled`, invalid email type, federated/managed/brokered account, ambiguous lookup, fuzzy-only lookup,
missing/empty/insecure/symlink/directory/oversized/NUL/non-UTF-8 password files, invalid boolean, blank
username, control characters, uppercase username, invalid email, whitespace-only assertion, and uncertain
POST outcomes (409/timeout/5xx).

Live: missing user with creation disabled, assertion mismatch, email drift, disabled user, wrong admin
credential, wrong issuer, unsafe password file, and `--migrations-only` with no user configuration.

## 5. Privilege / data-flow review

- `main()` performs the new remote Keycloak user I/O **before** acquiring the PostgreSQL advisory lock, so
  the new work does not extend the lock's duration across remote calls. See
  `PR17B_LOCK_AND_TRANSACTION_DECISION.md`.
- No PostgreSQL transaction is held across remote Keycloak I/O (`autocommit=True`; the advisory lock is
  session-level).
- The initializer still runs only the existing sanctioned stored functions; the verified subject flows into
  the existing deterministic binding path.
- No secret is written to `/tmp`, the repository, Git, or a world-readable file by the new code.

## 6. Residual risk

- The development realm projection is a curated reviewed allowlist (PR 17 residual), and the attestation
  reader is the realm admin in the local fixture (PR 17 residual). PR 17-B does not change either.
- The development password is non-temporary by explicit decision so the approved OIDC flow can be exercised
  without enabling direct-access grants. This is a development-only convenience; the production boundary is
  unaffected.
- No cross-system atomicity is claimed: if Keycloak creation succeeds and MTMF fails, the Keycloak account
  remains and a safe rerun reconciles it.

## 7. Security scan

`./build.sh --sec` on the implementation commit: Bandit Medium/High 0, Semgrep 0 findings.
