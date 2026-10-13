# PR 18 — Live Acceptance Report

**Test file:** `tests/integration/postgres/test_pr18_live_client.py`
**Opt-in:** `MTMF_PR18_LIVE=1`
**Status:** CL-I01–CL-I15, CL-I17, CL-I18 **PASS** (three consecutive clean
runs); CL-I16 **NOT TESTED**. The optional CL-I11 controlled-renewal loop was
executed as a 20-iteration forced-renewal loop.

## 1. Required topology (actually used)

- **Issuer:** real Keycloak `26.8.0-1`, canonical development realm
  `mtmf-dev`, issuer `https://keycloak.mtmf.test:28443/realms/mtmf-dev`.
- **Service:** real Uvicorn running the actual PR 17 FastAPI app
  (`mtmf_service.app.create_app`) on `127.0.0.1:28012`, terminated with a
  leaf certificate signed by the development CA for `127.0.0.1` — real TLS,
  no `verify=False`, no HTTP downgrade.
- **PDP internals:** real PR 9 effective-Role resolver, PR 13 eligibility,
  PR 14 trust, PR 16 batch evaluator, PR 15 conformance.
- **Database:** real PostgreSQL 18, migrated fresh per test, accessed by the
  service through the restricted `mtmf_runtime` login.
- **Client:** the actual `mtmf_client.HttpMtmfClient` (not a fake transport).

## 2. Commands

Canonical real-PostgreSQL gate (does not perform the Keycloak slice; the
live module is collected and skipped unless opted in):

```bash
./build.sh --integration
# 564 passed, 80 skipped in 276.87s
```

Feature-specific PR 18 live slice (additional mandatory gate):

```bash
MTMF_PR18_LIVE=1 uv run --no-sync pytest \
  tests/integration/postgres/test_pr18_live_client.py --no-cov
```

Environment: `MTMF_PR14_KC_BASE`, `MTMF_PR14_KC_ADMIN_USERNAME`,
`MTMF_PR14_KC_ADMIN_PASSWORD`, `MTMF_PR14_KC_CA_FILE`,
`MTMF_AUTH_ADMIN_REALM=mtmf-dev`, and the `MTMF_RUNTIME_POSTGRES_*`
configuration. All secrets were supplied from the running development
containers/secret files; none appear in this report or in the test output.

## 3. Results — three consecutive clean runs

| Run | Result | Duration |
| --- | --- | --- |
| 1 | **15 passed**, retries = 0 | 30.9 s |
| 2 | **15 passed**, retries = 0 | 35.7 s |
| 3 | **15 passed**, retries = 0 | 24.7 s |

(Additional full-suite repetitions were also clean; no first-attempt
failure occurred.)

## 4. CL-I matrix

| ID | Case | Test | Result |
| --- | --- | --- | --- |
| CL-I01 | Real Client Credentials grant to Keycloak | `test_cl_i01_i02_i03_real_client_mixed_batch` | PASS |
| CL-I02 | Real user token passed unchanged in the separate header | `test_cl_i01_i02_i03_real_client_mixed_batch` | PASS |
| CL-I03 | Batch with ALLOW and DENY; correct local helpers | `test_cl_i01_i02_i03_real_client_mixed_batch` | PASS |
| CL-I04 | 100 occurrences with duplicates; ordered correlation | `test_cl_i04_hundred_ordered_occurrences` | PASS |
| CL-I05 | Unknown syntactically valid Action → DENY | `test_cl_i05_unknown_action_denies` | PASS |
| CL-I06 | Forged user assertion rejected; no snapshot | `test_cl_i06_forged_user_token_is_rejected` | PASS |
| CL-I07 | Cross-client service/user pairing rejected | `test_cl_i07_cross_client_pairing_is_rejected` | PASS |
| CL-I08 | Missing subscription rejected | `test_cl_i08_missing_subscription_is_rejected` | PASS |
| CL-I09 | Revocation visible to new evaluation; stale window bounded | `test_cl_i09_revocation_is_visible_to_new_evaluations` | PASS |
| CL-I10 | Resource/actor replay denied without HTTP | `test_cl_i10_local_replay_is_denied_without_http` | PASS |
| CL-I11 | Service-token renewal; snapshot TTL unchanged (20-loop) | `test_cl_i11_service_token_renewal_loop` | PASS |
| CL-I12 | Token endpoint failure → typed error, no snapshot | `test_cl_i12_token_endpoint_failure_creates_no_snapshot` | PASS |
| CL-I13 | MTMF unavailable → no snapshot, no fabricated DENY | `test_cl_i13_mtmf_unavailable_does_not_create_snapshot` | PASS |
| CL-I14 | Invalid CA → TLS failure, no insecure fallback | `test_cl_i14_invalid_ca_fails_closed` | PASS |
| CL-I15 | App-owned row isolation remains PEP-owned | `test_cl_i15_app_owned_row_isolation_is_pep_owned` | PASS |
| CL-I16 | Restart service/Keycloak while a snapshot exists | — | **NOT TESTED** |
| CL-I17 | Two clients/actors do not cross-contaminate | `test_cl_i17_two_clients_do_not_cross_contaminate` | PASS |
| CL-I18 | Typed error envelopes (forged user) | `test_cl_i18_typed_error_envelopes` | PASS |

## 5. Execution deviations (environment)

1. **Ephemeral development credentials were lost** when the interactive
   session was interrupted and the WSL/Podman environment restarted: the
   `/tmp` development secret files (`dev-user-password`, the PR 14 user
   password) were cleared and the MTMF containers were stopped. The stack
   was restored non-destructively (persistent volumes preserved) via
   `scripts/mtmf-dev-stack.py up`; the Keycloak bootstrap admin and
   attestation-reader secrets were recovered from the existing container
   environments.
2. Because the PR 14 fixture user passwords were unrecoverable (Keycloak
   stores only hashes), the PR 18 slice creates one **additive, disposable**
   Keycloak user (`mtmf-pr18-live-<random>`) with a random password and
   deletes it after the module. **No existing fixture user, client, realm,
   volume, or PR 14 evidence artifact was modified or reset.**
3. No destructive Podman reset was performed.

## 6. Not executed

- **CL-I16** (restart the running service/Keycloak while a snapshot exists)
  was not performed: restarting the shared development Keycloak would
  disrupt the environment and other work. The equivalent invariant — a
  snapshot is never implicitly renewed and a new call requires a valid
  service and user token — is covered by CL-I11, CL-I12 and the unit
  snapshot-expiry tests. This is recorded as **NOT TESTED**, not PASS.
