# PR 17-B Amendment Security Review

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Amendment:** acceptance-completion amendment
**Final amendment tip:** `e860e214d7cbddbe0b58d82267041a687ad39907` (reports; code/test tip `ca23d11ebbb2f7c316be444aeb594c38d7114d6f`)

## 1. New production-code changes (smallest delta)

Only two production behaviours changed, both in the development-only initializer:

1. **Tenant-name drift fails closed.** `PostgresProvisioner.ensure_ordinary_tenant`
   now compares an existing Tenant's persisted name with the configured fixture name
   and raises `BootstrapError` on mismatch instead of silently reusing/renaming.
2. **Test-only failpoint.** `MTMF_DEV_TEST_FAILPOINT=after-user-verify` terminates the
   initializer immediately after Keycloak user verification and before any MTMF write.

No change to `mtmf_core`, the Rust engine, the HTTP DTOs, the database schema, stored
functions, grants, or the approved realm/client policy.

## 2. Failpoint safety review

- Read only by `scripts/mtmf-dev-initialize.py`; it is not read by the HTTP service
  (`mtmf_service`) or any consuming application.
- Inert unless the environment variable is explicitly set to the exact value.
  It is not present in `compose.dev.yaml` and no code sets it.
- It exits before any MTMF write, so it cannot create partial MTMF state; it can only
  leave a Keycloak account that the normal reconciliation path reuses.
- Unit tests `test_test_failpoint_is_inert_by_default_and_triggers_when_set` and
  `test_entry_point_failpoint_stops_before_any_mtmf_write` prove the default inertness
  and the exact boundary.

## 3. Fault-proxy safety review

`tests/integration/postgres/pr17b_fault_proxy.py`:

- Loopback-only (`127.0.0.1`, ephemeral port); test-only, never imported by production.
- Pure pass-through to the **real** Keycloak with the approved CA; it never replaces or
  fakes Keycloak.
- Faults are scoped to the user-creation `POST` (forward-then-drop or reject) and, in the
  indeterminate mode, to post-create user-lookup `GET`s.
- It suppresses request logging, relays only reviewed headers, and never records bodies
  or credentials.

## 4. Credential and mount isolation (I16)

Real Compose containers (`compose.yaml` + `compose.dev.yaml`) inspected via `podman inspect`:

- Initializer container: `MTMF_AUTH_ADMIN_PASSWORD`, `MTMF_PR14_KC_ADMIN_PASSWORD`,
  `MTMF_MIGRATOR_DATABASE_URL`, and `MTMF_DEV_USER_*` present; `/run/mtmf-secrets`
  mounted **read-only** (`RW=false`).
- HTTP service container: **none** of those variables and **no** `/run/mtmf-secrets`
  mount. It retains only the restricted `MTMF_RUNTIME_DATABASE_URL` and the dedicated
  least-privilege attestation-reader credential, matching the approved PR 17 boundary.
- The live composed-image initializer run succeeded against real Keycloak; the generated
  initial password did not appear in stdout/stderr, and the mounted password file was
  `0600` (the initializer also validates type, ownership, mode, size and encoding).

## 5. Destructive-action scoping

- I10 seeds a conflicting binding only in the per-test disposable schema using the
  sanctioned `mtmf.external_subject_identity_add` operator function.
- Every live test uses unique, test-created Keycloak usernames and deletes only those
  users in `finally`; the per-test `db` fixture drops/recreates only the `mtmf` schema.
- The Compose test removes only the explicitly named MTMF-owned containers it creates
  and never runs `podman-compose down` (which would remove the MTMF PostgreSQL
  container). No non-MTMF resource is touched.

## 6. Transaction/lock invariants

The new remote Keycloak user I/O remains before `DevelopmentBootstrap.run()` and thus
outside the advisory lock; the existing session-level (non-transactional) lock is
unchanged. The fault-proxy test exercises a lost POST response after the real Keycloak
commit and confirms bounded re-read reconciliation with no blind duplicate POST.

## 7. Security scan

`./build.sh --sec` on `ca23d11`: Bandit Medium/High 0 (the new test files use `httpx`
and runtime-generated values to avoid the `urllib`/hardcoded-temp findings), Semgrep 0
findings, Gitleaks clean.

## 8. Residual risk

- The development realm projection and admin-based attestation reader remain PR 17
  residuals; unchanged.
- The `mtmf-dev-stack.py` single-command topology remains limited by the pre-existing
  issuer-hostname blocker; the documented host-network composed-image run is used for
  I16/I20 and does not relax any security boundary.
- No production provisioning interface, credential path, or policy was added.
