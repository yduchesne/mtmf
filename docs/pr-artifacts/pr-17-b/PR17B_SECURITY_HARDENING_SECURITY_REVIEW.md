# PR 17-B Security-Hardening Security Review

**PR:** PR 17-B — security-hardening amendment
**Amended code tip:** `6471e392d4b2f0ecc617ced9c70e33ef10c489ba`
**Starting tip:** `0c9ee1e6ae75d41b56d4353c85c65060a0432f64`

## 1. Finding 1 — unearned email verification (fixed)

**Before:** `_attempt_create` submitted `emailVerified: true` whenever
`MTMF_DEV_USER_EMAIL` was configured, asserting an email-control proof the
initializer never obtained.

**After:** the create body sets `emailVerified: false`. An existing account's
`emailVerified` state is never modified, and a valid existing account is not
rejected solely for an unverified email.

**Residual semantics:** email remains an attribute consistency check, not proof
of email control, and is never used as creation provenance. No realm-level email
verification, registration, required-action, browser-flow, or client policy was
changed. SH16 proves the approved real OIDC authorization-code login still
succeeds for a newly created `emailVerified=false` user.

## 2. Finding 2 — weak create reconciliation (fixed)

**Threat:** an attacker (or an unrelated process) who knows the configured
username could create the account during a rejected or uncertain create `POST`;
the old code swallowed every failure and accepted any subsequently visible
matching username as if this invocation had created it. Username/email are
mutable and are not ownership proof.

**Fix — explicit outcome classification (`_CreateOutcome`):**

| Outcome | Trigger | Behavior |
| --- | --- | --- |
| `CREATED` | 2xx | Re-read; require exactly one valid account whose immutable `id` equals the `Location` header id from the create response. |
| `REJECTED` | non-409 4xx except 408 | Fail closed immediately; **no** re-read acceptance. |
| `CONFLICT` | 409 | Re-read; accept only with an independent `MTMF_DEV_USER_SUBJECT` correlation. |
| `INDETERMINATE` | timeout / transport / dropped / malformed / 5xx / 408 | Bounded re-read; accept only with the correlation; no second POST. |

**Provenance authority:** real Keycloak `26.8.0-1` returns `201` with a
`Location` header whose final segment is the created immutable `id` (probed, see
baseline §5). The successful-create path therefore binds `Location`-provenanced
accounts, not merely username matches. For conflict/uncertain outcomes, only an
operator-asserted exact subject is accepted; a mutable profile marker is
explicitly rejected as insufficient.

**Concurrency:** the minimum-scope policy preserves I12. A losing initializer
that receives a 409 without an assertion fails closed on that invocation; a
subsequent rerun reuses the now-existing account. The I12 test already permits
one bounded failure plus an idempotent retry and was **not** rewritten. Two
initializers that share the same `MTMF_DEV_USER_SUBJECT` may both succeed.

**No new attack surface:** no production API, marker attribute, realm/client
policy relaxation, or second Keycloak client was introduced.

## 3. Finding 3 — password-file TOCTOU (fixed)

**Before:** `lstat()` validated the path, then `Path.read_bytes()` reopened it by
pathname; a substitution between the two calls could be read.

**After:** the file is opened **once** with
`os.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)`; `os.fstat` on
that same descriptor performs every type/size/mode/owner check; a bounded
`os.read` loop reads at most `_MAX_PASSWORD_BYTES + 1` bytes from the same
descriptor; a post-read size check rejects growth after `fstat`; and the
descriptor is closed in a `finally`. `O_NOFOLLOW` makes a final-component symlink
fail with `ELOOP`; a platform without `O_NOFOLLOW` refuses to read rather than
silently reverting to the pathname race.

**Scope honesty:** `O_NOFOLLOW` protects the final component only; ancestor
directory symlink substitution and a pre-open path attack remain out of scope for
this small fix and are not claimed. The configured secret mount and directory
protections are unchanged. The password is never logged, printed, put in an
exception, or persisted.

## 4. Part D — failpoint and isolation audit (no code change necessary)

- `MTMF_DEV_TEST_FAILPOINT` is read only by `scripts/mtmf-dev-initialize.py`.
- It is absent from `compose.dev.yaml` (verified) and from the service
  environment; it is inert unless it exactly equals `after-user-verify`.
- It fires after Keycloak user verification and **before** any MTMF persistence.
- Unit tests cover absent, near-miss, different-value (inert), and exact
  (exit before any MTMF write).
- No new exposure was found; **no code change necessary**.

## 5. Credential / privilege isolation

- I16 re-verified on real Compose containers: the initializer carries the
  Keycloak admin / migrator / development-user variables and a read-only
  `/run/mtmf-secrets` mount; the HTTP service carries none of them and no secret
  mount.
- The new `create_user` transport uses the same privileged admin credential path
  as the existing client attestation; no credential is added to the runtime or to
  ATI.
- No external Keycloak I/O is placed inside a PostgreSQL transaction; the
  advisory-lock design is unchanged.

## 6. Policy changes

**None.** No migration, stored function, grant, public DTO, realm/client policy,
service setting, or product authorization semantic was changed.

## 7. Scan

`./build.sh --sec` on the amended tree: Bandit Medium/High 0, Semgrep 0 findings.
