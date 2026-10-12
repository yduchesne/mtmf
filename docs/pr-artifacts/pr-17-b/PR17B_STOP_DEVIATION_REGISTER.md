# PR 17-B Stop / Deviation Register

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Implementation commit:** `362aae664c4f76a88c69ae25421249346b5591c7` (core) + `9e074fb09e92b1db37f96496f3f256ef49196e1a` (brokered-account hardening); final tip `9e074fb09e92b1db37f96496f3f256ef49196e1a`

## Blocking STOP conditions

**None triggered.** The implementation proceeded within the approved plan scope. The most relevant
potential STOP conditions and their resolution follow.

| Plan STOP condition | Assessment |
| --- | --- |
| (1) current `main` materially differs | Not triggered — `HEAD == origin/main == b60c50b`; no drift. |
| (2) Admin REST cannot safely expose a stable user ID | Not triggered — `GET .../users?username=...&exact=true` returns a stable `id`; validated and used. |
| (3) approved realm disallows the specified login/credential behavior | Not triggered — created users authenticate through the already-approved browser/OIDC flow; no direct-access grants enabled. |
| (4) user creation requires weakening client/realm policy | Not triggered — no policy change; generic profile names satisfy the existing required profile. |
| (5) existing bootstrap locks hold **DB transactions** across external I/O | Not triggered — the connection is `autocommit`; only a session advisory lock is held. New user I/O is placed outside the lock. See `PR17B_LOCK_AND_TRANSACTION_DECISION.md`. |
| (6) production credential exposed to runtime/ATI | Not triggered — the new variables exist only in the initializer service. |
| (7) pre-existing fabricated-subject binding needs migration/deletion | Not triggered — fresh acceptance used a clean schema; the fabricated default is removed. |
| (8) safe concurrent create/reconciliation cannot be guaranteed | Not triggered — bounded exact re-read + advisory lock. |
| (9) Keycloak/MTMF state conflict | Not triggered — conflict paths fail closed. |
| (10) extra migration/stored function/grant needed | Not triggered — none added. |
| (11) Podman port/resource ownership conflict | Not triggered — prefix-2 loopback ports and MTMF-owned projects only. |
| (12) required live topology cannot be established | Not triggered — real Keycloak + PostgreSQL live topology was established. |
| (13) mandatory acceptance gate fails/cannot execute | Not triggered — all canonical gates and the live PR 14/17 suites passed. |
| (14) approved security manifest would need rewriting | Not triggered — the realm-security projection does not include users and was not changed. |

## Deviations and decisions

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| D-1 | Decision | Generic `firstName`/`lastName` are set on created users so the approved OIDC browser flow does not route through `VERIFY_PROFILE`. | Accepted; no policy weakened; documented in `PR17B_IMPLEMENTATION_REPORT.md` D1. |
| D-2 | Defect fix | Wrong admin credential initially raised a raw `HTTPError`. `preflight_issuer` now emits a redacted `BootstrapError`. | Fixed in the implementation commit; unit + live tested. |
| D-3 | Decision | All Admin REST/token responses are bounded to 1 MiB. | Accepted; strengthens fail-closed behavior. |
| D-4 | Decision | Compose mounts `$MTMF_DEV_SECRET_DIR` read-only at `/run/mtmf-secrets`. | Accepted; no plaintext password in Compose/`.env`. |
| D-5 | Hardening | Brokered accounts (`origin`) are rejected in addition to `federationLink`/service accounts. | Added in `9e074fb`; unit tested. |
| SD-1 | Pre-existing behavior | The existing PR 17 advisory lock is held across `ensure_client`/`verify_issuer` remote calls. | Retained as the existing bounded lock contract; **no DB transaction** is held; new user I/O is outside the lock. Not a blocking STOP. |
| SD-2 | Coverage gap | Live I12 (simultaneous initializers), I13 (kill after create), I15 (injected timeout after POST), I16 (live container inspection), I10 (injected incompatible binding), I18 (multi-Application), I20 (live Compose launch) were not all independently reproduced against the live stack. | Design- and unit-covered; recorded in `PR17B_ACCEPTANCE_REPORT.md` §4. Not a hard blocker, but part of why the PR is not DONE. |
| SD-3 | Harness environment | The PR 14 live suite requires the fixture CA to be trusted (`SSL_CERT_FILE`); without it, 20 cases fail with `attestation credential request failed`. | Environment/harness failure, not a PR 17-B regression; re-run with the CA trusted passed 51/51. |

## Open items before DONE

- Complete or explicitly waive the unexercised live I-cases (SD-2).
- Human security/architecture review and approval. **No merge without human approval.**
