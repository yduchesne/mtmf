# PR 18 — Failures and Deviations

No unresolved blocking failure. This register records every deliberate
deviation, deferred item, and environment limitation.

## 1. Deferred: controlled service-token-expiry `401` retry (CL-U24)

**Decision:** NOT IMPLEMENTED — deferred by contract.

**Reason:** the plan permits a single controlled retry only when a
*definitive, machine-readable* service-token-expiry signal exists. The PR 17
endpoint returns `401` with the static `UNAUTHENTICATED` envelope
(`"Service authentication failed"`); there is no header or code that
distinguishes "expired service token" from any other authentication
failure. Implementing a retry would retry arbitrary 401s, which the plan
forbids (`STOP condition 6`). No retry path exists; `CL-U25` proves exactly
one authorization POST for 401/403/timeout/503 and `CL-I12` proves a token
endpoint failure yields a typed error and no snapshot.

**Action requested:** none. A future approved signal may enable the retry
without changing this client's failure semantics.

## 2. Conservative universal 15-second snapshot cap

**Decision:** every client snapshot is capped at 15 seconds.

**Reason:** the authoritative Action sensitivity classifier
(`mtmf_service.sensitivity`) is not exposed as a public contract, and the
v1 response carries one `expires_at`. The plan (§6 Step 9) directs a
conservative whole-snapshot 15-second cap in that situation, and its STOP
condition 5 is not triggered because the conservative cap is accepted. A
future approved sensitivity input may lift the client cap for non-sensitive
batches; the client never increases a server-issued duration.

## 3. Live-slice disposable Keycloak user (environment recovery)

**Deviation:** the PR 18 live test creates one additive, disposable
Keycloak user and deletes it afterwards.

**Reason:** the interactive session was interrupted by a WSL/Podman
restart; the ephemeral `/tmp` development secret files (including the PR 14
fixture user password) were cleared and the MTMF containers stopped. The
stack was restored non-destructively (volumes preserved). Keycloak stores
password hashes only, so the fixture password was unrecoverable. Creating a
new disposable user avoids mutating the existing PR 14 fixture user while
still exercising the real issuer and real end-to-end slice.

**Boundary:** no existing Keycloak user/client, PostgreSQL volume, PR 14
fixture, or evidence artifact was modified, reset, renamed, or deleted. No
`podman` destroy/prune/reset was executed.

## 4. CL-I16 not executed

**Item:** "Restart service/Keycloak while a snapshot exists."

**Status:** **NOT TESTED** (not PASS).

**Reason:** restarting the shared development Keycloak would disrupt the
environment and other in-flight work. The underlying invariant (no implicit
snapshot renewal; new calls require valid tokens) is exercised by CL-I11
(token renewal does not extend the snapshot), CL-I12 (token failure yields
no snapshot), and the monotonic expiry unit tests.

## 5. PR 17 sensitivity classifier is not a public contract

Confirmed by inspection; no client-only wire field was added and no PR 17
endpoint change was made. This is the basis for deviation 2, not a wire
mismatch.

## 6. Bandit B108 in new tests (resolved)

Two Medium `/tmp` hardcoded-directory findings were introduced by the first
draft of the new tests and resolved by deriving temporary paths from
`tempfile.gettempdir()` / `tmp_path`. Final Bandit result for the new files:
0 Medium / 0 High. No suppression was used.

## 7. Non-blocking observations

- `httpx 0.28` deprecated `verify=<path str>`; the transport now builds an
  `ssl.SSLContext` from the configured CA bundle, removing the warning and
  keeping verification explicit.
- The client is synchronous by design; no async API was added.
