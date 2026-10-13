# PR 17-B Implementation Report

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Base commit:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Implementation commit:** `362aae664c4f76a88c69ae25421249346b5591c7` (core) + `9e074fb09e92b1db37f96496f3f256ef49196e1a` (brokered-account hardening); final tip `9e074fb09e92b1db37f96496f3f256ef49196e1a`
**Branch:** `dev/pr17b-keycloak-user-provisioning`

## 1. Scope delivered

The privileged, development-only one-shot initializer now creates or verifies a real Keycloak user and
binds MTMF to Keycloak's authoritative immutable user ID / OIDC `sub`. The fabricated `mtmf-dev-user`
subject fallback is removed. No production provisioning endpoint, no schema/migration/stored-function
change, no new runtime grant, and no change to the Rust engine or HTTP/`/v1` DTO contract.

## 2. Files changed

| File | Change |
| --- | --- |
| `packages/mtmf-service/src/mtmf_service/development_user.py` | **New.** Fail-closed `DevUserConfig`, `load_dev_user_password`, `KeycloakAdminTransport` protocol, and `KeycloakDevUserProvisioner`. |
| `scripts/mtmf-dev-initialize.py` | Bounded Admin REST responses; public `request` transport; `preflight_issuer`; `verify_issuer` reuses preflight; `_dev_fixture(subject)` (no default); `main` parses config, preflights issuer, verifies/creates the user, then runs the existing bootstrap with the verified subject. |
| `compose.dev.yaml` | Forwards `MTMF_DEV_USER_*` and `MTMF_DEV_TENANT_*` to the initializer only; read-only `/run/mtmf-secrets` mount; fabricated subject default removed. |
| `.env.example` | Documents the new development-user variables and secret-file rules. |
| `tests/unit/service/test_pr17b_development_user.py` | **New.** Config + provisioner matrix (U01–U28-relevant). |
| `tests/unit/service/test_pr17b_initialize_script.py` | **New.** Compose wiring, entry-point, production refusal, migrations-only, preflight normalization. |
| `docs/DEVELOPMENT_SETUP.md`, `docs/ARCHITECTURE.md`, `README.md`, `docs/ROADMAP_V01.md` | Human-readable operator/architecture/status updates. |

## 3. Configuration contract implemented

| Variable | Behavior |
| --- | --- |
| `MTMF_DEV_USER_USERNAME` | Required. Trimmed, lowercase (canonical), no control characters, no `/ \ ? #`, bounded length. No default. |
| `MTMF_DEV_USER_EMAIL` | Optional. Empty means unset. Basic shape validation. Compared case-insensitively against an existing account; mismatch fails closed and never repairs. |
| `MTMF_DEV_USER_CREATE` | Explicit `true`/`false` (case-insensitive); default `false`. Any other non-empty value fails validation. |
| `MTMF_DEV_USER_PASSWORD_FILE` | Optional path in configuration; required only when a user is missing and creation is enabled. Loaded lazily, so an existing-user run never opens it. |
| `MTMF_DEV_USER_SUBJECT` | Optional assertion. Empty (Compose's unset form) means absent; whitespace-only/control values are rejected. A non-empty value must equal the actual Keycloak ID. |

The settings live in `development_user.py`, not in the runtime `ServiceSettings`, so the HTTP service
cannot receive them.

## 4. Keycloak create-or-verify behavior

1. **Exact lookup:** `GET /admin/realms/{realm}/users?username=<quoted>&exact=true`, then an explicit
   case-insensitive exact-username filter. 0 matches → missing; 1 → verify; >1 → fail closed. A transient
   zero is retried a bounded number of times; a fuzzy-only match is treated as absent and never selected.
2. **Response validation:** each row must be a JSON object with a non-empty stable `id`, a username,
   and a boolean `enabled`. A non-list / non-object / missing-field / malformed response fails closed.
3. **Existing user:** verify ID, `enabled`, federated/managed status, and optional email. The password
   file is **not opened**; no password, email, role, MFA, required-action, or client change is made.
4. **Missing user + creation disabled:** fail before any POST or MTMF write.
5. **Missing user + creation enabled:** securely load the password (regular file, owner-only mode,
   owned by the initializer user, bounded size, UTF-8, non-empty), POST once with a **non-temporary**
   credential and generic profile names, then perform a bounded authoritative re-read. A 409 or an
   uncertain timeout/network failure after POST is reconciled by re-reading and accepting only an exact,
   verified match; no blind retry.
6. **Expected subject:** compared by exact equality to the retrieved Keycloak ID *before* any MTMF write.
7. **Redaction:** HTTP status and a generic transport reason are surfaced; response bodies (which may
   contain secrets) are never included. The user record and password are never logged.

## 5. Ordering and lock decision

`main()` now performs, before `DevelopmentBootstrap.run()`:

```
deployment-mode check (no mutation)
-> DevUserConfig.from_env() (no network/DB I/O)
-> issuer preflight (discovery + JWKS reachability)
-> Keycloak user create/verify  (remote I/O, OUTSIDE the advisory lock)
-> DevelopmentBootstrap.run()
   -> advisory lock acquire
   -> migrations + privilege postflight
   -> root / ordinary Tenant / user binding (verified subject)
   -> per-Application client ensure + service binding + subscription
   -> full issuer/client attestation
   -> advisory lock release
```

This keeps the **new** remote user I/O outside the advisory lock and before MTMF writes, while preserving
PR 17 behavior. The advisory lock is a session-level lock on an `autocommit=True` connection; no
PostgreSQL transaction is held across remote calls. See
`PR17B_LOCK_AND_TRANSACTION_DECISION.md`.

## 6. Decisions made during implementation (non-secret, within scope)

- **D1 — Generic profile names on creation.** The development realm's user profile requires
  `firstName`/`lastName`; without them Keycloak routes an OIDC login through `VERIFY_PROFILE`, so the
  created user could not complete the approved browser flow without a profile-update detour. Creation sets
  `firstName=MTMF`, `lastName=Development User`. This does not weaken any realm or client policy; it
  satisfies the existing required profile.
- **D2 — Preflight error normalization.** Live negative testing exposed a raw `urllib.error.HTTPError`
  traceback when the Keycloak admin credential was wrong. `preflight_issuer` now normalizes HTTP, network,
  TLS, and malformed-response failures to a redacted `BootstrapError` (for example
  "the development issuer preflight failed with HTTP 400").
- **D3 — Bounded responses.** `KeycloakCredentialProvisioner` now bounds every Admin REST/token response to
  1 MiB and fails closed when exceeded.
- **D4 — Compose secret mount.** The initializer mounts `$MTMF_DEV_SECRET_DIR` (default
  `/tmp/mtmf-dev-secrets`, `0700` host directory) read-only at `/run/mtmf-secrets`; the default password
  path is `/run/mtmf-secrets/dev-user-password`. No plaintext password is written to Compose or `.env`.

- **D5 — Reject brokered accounts.** The federated/managed rejection also fails closed when a user carries a
  non-empty brokered identity `origin`, not only `federationLink`/`serviceAccountClientId`.

## 7. Regression preservation

- `DevelopmentBootstrap`, `BootstrapFixture`, `UserFixture`, `PostgresProvisioner`, the sanctioned stored
  functions, the approved client policy, the issuer attestation, and the runtime privilege boundary are
  unchanged except for the verified-subject fixture input.
- `--migrations-only` still does not read development-user configuration and never touches Keycloak.
- `ensure_user_binding` continues to key identity/binding UUIDs deterministically off the subject; the
  subject is now the verified Keycloak ID.

## 8. Unresolved / not done

- The full I01–I20 live matrix includes concurrency, kill/restart-during-create, network-timeout-after-POST,
  and container environment-inspection cases that are covered by design and unit tests but were not all
  exercised against the live stack. See `PR17B_ACCEPTANCE_REPORT.md` §4.
- No human review has yet approved the PR. **Not DONE.**
