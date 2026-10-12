# PR 17 — Amendment #1 acceptance report

**PR:** `PR 17` (Independent HTTP service).
**Branch:** `dev/pr17-http-service`.
**Base:** `4eea688b12005b59aa8dbee9981f08551dcb7702`; prior feature `6a33352`;
prior evidence `6e92fca`.
**Amendment feature commit:** recorded at the branch head (§7); this report is
committed with it.
**Disposition: STOPPED — NOT READY FOR HUMAN REVIEW as DONE.**

## 1. Final gates

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1,750 passed, 0 skipped, coverage 89.99% |
| Security | `./build.sh --sec` | PASS — Bandit 0 Medium/High; Semgrep 0 findings |
| Rust/native | `./build.sh --rust` | PASS (run on final tree; see commit log) |
| Integration | `./build.sh --integration` (exported `.env`) | see §7 |
| Pre-commit | commit hook (gitleaks + `--rust` + `--qa` + `--sec`) | PASS |
| Live actor | `MTMF_PR14_LIVE=1 SSL_CERT_FILE=… pytest tests/integration/postgres/test_pr14_live_actor_context.py` | **22 passed** |
| Live HTTP | `MTMF_PR17_LIVE=1 SSL_CERT_FILE=… pytest tests/integration/postgres/test_pr17_live_http.py` | **12 passed** |
| Initializer (live) | `python scripts/mtmf-dev-initialize.py` (fresh + re-run) | exit 0, idempotent |
| G4 concurrency | `pytest tests/unit/service/test_concurrency.py` | 6 passed |

## 2. Summary of the amendment

- **G1 (carrier):** proposal written; **human approval PENDING** → STOP.
- **G2 (live V):** real Keycloak + real Uvicorn + real PostgreSQL harness added;
  12 live HTTP cases pass and the PR 14 live suite passes 22/22. Several
  original V cases remain partial/not executed (see live matrix).
- **G3 (deployment):** image builds; Keycloak runs; the privileged one-shot
  initializer provisions a fresh fixture against real PostgreSQL + live
  Keycloak and is idempotent on re-run with owner-only secret delivery; the
  host-run ASGI service reports readiness 200. Containerized Compose path
  implemented via `scripts/mtmf-dev-stack.py` but not fully executed.
- **G4 (timeout/concurrency):** defect reproduced; bounded admission
  implemented with permits released on worker completion; deterministic tests
  and evidence recorded.
- **G5 (contract/security):** PR 15 DTOs/errors unchanged; PR 14 fresh
  attestation preserved; PR 13 eligibility preserved; one PR 16 Python batch
  call with one shared context; conservative 15 s TTL; `mtmf_owned` denied;
  no new schema/grant/root recovery; production gated.

## 3. Files changed by Amendment #1

```
packages/mtmf-service/src/mtmf_service/concurrency.py     (new)
packages/mtmf-service/src/mtmf_service/app.py             (admission)
packages/mtmf-service/src/mtmf_service/composition.py     (admission dep)
packages/mtmf-service/src/mtmf_service/asgi.py            (admission wiring)
packages/mtmf-service/src/mtmf_service/settings.py        (max_in_flight_evaluations)
scripts/mtmf-dev-initialize.py                            (secret delivery)
scripts/mtmf-dev-stack.py                                 (new portable launcher)
compose.dev.yaml                                          (started condition + doc + env)
.env.example                                              (max-in-flight var)
tests/unit/service/test_concurrency.py                    (new, G4)
tests/unit/service/conftest.py                            (admission injection)
tests/unit/service/test_settings_clock_rate.py            (settings case)
tests/integration/postgres/test_pr17_live_http.py         (new, live V)
tests/integration/postgres/test_pr14_live_actor_context.py (stale category fix)
docs/pr-artifacts/pr-17/pr17-amendment-1-*.md             (this suite)
```

## 4. Cross-references

- Carrier decision: `pr17-amendment-1-carrier-decision.md` (**PENDING**).
- Live matrix: `pr17-amendment-1-live-matrix.md`.
- Deployment evidence: `pr17-amendment-1-deployment-evidence.md`.
- Timeout evidence: `pr17-amendment-1-timeout-evidence.md`.
- Baseline: `pr17-amendment-1-baseline.md`.
- STOP/deviation: `pr17-amendment-1-stop-deviation-register.md`.

## 5. Live HTTP redacted evidence (representative)

```
POST /v1/authorization/evaluate   (tenant=<redacted uuid>, action=principal:get-object)
  Authorization: Bearer <redacted service token>
  X-MTMF-User-Authorization: Bearer <redacted user token>
-> 200  {"schema_version":"1","decisions":[{"request_id":"r1",
          "effect":"ALLOW","reason":"PERMITTED"}], ...}
  cache-control: no-store

POST (wrong Tenant selector)                      -> 403 UNTRUSTED_ACTOR
POST (forged user token)                          -> 403 UNTRUSTED_ACTOR
POST (suspended subscription)                     -> 403 INELIGIBLE_APPLICATION
POST (body 65537 bytes)                           -> 413 REQUEST_TOO_LARGE
POST (media type text/plain)                      -> 415 UNSUPPORTED_MEDIA_TYPE
POST (manifest mismatch / no attestation cache)   -> 503 DEPENDENCY_UNAVAILABLE
```

No token, secret, admin credential, or Keycloak Admin REST body is printed or
committed. Keycloak attestation is the PR 14 `BaselineConfigurationAttestor`
comparing the live realm against `dev/keycloak/expected-config-manifest.json` on
every operation.

## 6. PostgreSQL / runtime evidence

- Runtime role: `mtmf_runtime` (restricted; no direct table access; exact
  EXECUTE allowlist). Privilege surface verified by
  `test_postgres_runtime_security.py`/`test_runtime_privileges.py`.
- Podman (MTMF-owned only): project `mtmf-pr14-keycloak`, container
  `mtmf-pr14-keycloak_keycloak_1`, volume `mtmf-pr14-keycloak-data`; host
  `25432` PostgreSQL. No ATI/Digr/Darkula resource touched.

## 7. Final SHA and integration count

- Amendment feature commit: recorded at the branch head after the commit below.
- `./build.sh --integration`: **559 passed, 34 skipped** (the 34 skipped are the opt-in PR 14 live actor suite (22) and PR 17 live HTTP suite (12), both executed separately and passing).

## 8. Remaining risks and disposition

- **G1 carrier unapproved** → cannot merge or mark DONE.
- V01/V04/V05/V08/V12/V13/V15 partially executed (container issuer networking,
  volume destroy/recreate, live rate/timeout); see STOP register SD-2/SD-3.
- Non-interruptible synchronous worker; transient permit race; DB statement
  timeouts not configurable (SD-5/SD-6).
- Production issuer/root recovery remain gated (SD-8).

**Final disposition: STOPPED.** The amendment is not DONE; PR 17 remains
unmerged and requires the G1 reviewer decision plus the remaining V-case
execution before it can be considered `READY FOR HUMAN REVIEW`.
