# PR 17-B Creation-Provenance Security Review

**PR:** PR 17-B — strict created-resource provenance follow-up
**Starting tip:** `f84cadd371a3f889fe79fd98464908b3a88b4225`

## 1. Defect closed

The `CREATED` branch accepted a successful `POST` even when Keycloak's
created-resource `Location` was missing/blank/malformed, because the guard was
`created_subject is not None and created_subject != verified.subject`. A
successful create with no usable `Location` therefore bound the merely
username-matching account. `_created_subject` also extracted the last path
segment of any URL without validating the realm/user-resource path or origin.

## 2. Fix

`_created_subject(location, realm, admin_base_url)` now returns the created
immutable id only when **all** of the following hold:

- the value is a string, non-empty after trimming, with no control characters;
- it parses as an absolute URL with `http`/`https` and a netloc (rejecting
  protocol-relative `//host/...`);
- it carries no embedded username/password, query, fragment, or `%` in the path;
- its scheme **and** netloc equal the configured trusted admin base (`https` in
  production; the documented loopback test fault proxy is the only `http`
  exception);
- its path is exactly `/admin/realms/<configured-realm>/users/<id>` (six
  segments, no extras, no case-folded realm);
- the id is non-empty, not `.`/`..`, and free of `/`, `\`, `;`, or control
  characters.

`ensure_user` now enforces `created_subject is None or created_subject !=
verified.subject` → `BootstrapError`, so a successful create with an unverifiable
location fails closed **before any MTMF write**. `MTMF_DEV_USER_SUBJECT` cannot
substitute for a valid `Location` on `CREATED` (PV11).

## 3. Trust anchor

The trusted origin is the same `MTMF_AUTH_ADMIN_BASE` already used by the
privileged Admin REST transport, passed into the provisioner from
`main()` (`admin_base_url=credentials.base_url`). Production is HTTPS. The
test-only loopback fault proxy is the single documented HTTP exception; the proxy
rewrites the upstream `Location` origin to its own loopback origin so the test
exercises path/realm validation rather than an origin mismatch, and the
provisioner requires the location scheme to equal the configured trusted scheme.
No new privileged runtime setting or public interface was introduced.

## 4. Redaction

The failure message is
`"Keycloak creation provenance could not be verified; no MTMF identity binding was created"`
and never echoes attacker-controlled URL content. No token, password, or
credential-bearing URL is logged.

## 5. Preserved invariants (unchanged)

- Existing-account read-only reuse; no password reset, disable, or deletion.
- `REJECTED` remains immediate fail-closed; `CONFLICT`/`INDETERMINATE` retain the
  explicit-subject correlation and bounded re-read; no blind second POST.
- `emailVerified=false`; descriptor-based password read; test-only failpoint
  isolation (no change; absent from `compose.dev.yaml`).
- Keycloak I/O outside PostgreSQL transactions; no MTMF persistence after a
  provenance failure.
- No schema/migration/grant/public API/realm/client-policy/issuer-hostname change.

## 6. Failure behavior on unverifiable provenance

A failed provenance verification does **not** delete or mutate the Keycloak
account (the remote create may have committed). Keycloak may contain the
account; a later run reuses it under the existing verified-account contract
(live `test_pv_live_stripped_location_fails_closed_then_reconciles`). No
automatic cleanup or credential change is attempted.

## 7. Scan and gates

`./build.sh --sec`, `--qa` (strict mypy/Ruff), `--rust`, and `--integration`
passed on the amended code tip; full live keycloak/PostgreSQL matrix 65 passed.
