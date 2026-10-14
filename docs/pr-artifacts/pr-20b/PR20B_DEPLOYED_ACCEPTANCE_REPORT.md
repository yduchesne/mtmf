# PR20B_DEPLOYED_ACCEPTANCE_REPORT

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**Implementation SHA (validated):** `61649b4969eb882501920a506584f2bba581d125`
**Status:** deployed acceptance executed and green for L20B/S/B/N/G; F01–F07
and the P0 mixed-batch proof are explicit STOP/deviations (PR 20B not DONE).

## 1. Authoritative topology and command

The PR20B launcher reuses the canonical PR20A topology creator and owns only
the isolated `mtmf-pr20a-acceptance` project:

```text
uv run python scripts/pr20b-reference-acceptance.py acceptance
```

Topology: PostgreSQL 18.6, Keycloak 26.8.0-1, restricted MTMF service,
development-only internal TLS terminator, independent reference-app container;
PostgreSQL `127.0.0.1:29532`, Keycloak HTTPS `127.0.0.1:29543`, MTMF TLS
`127.0.0.1:29501`, reference app `127.0.0.1:29511`. Genuine Keycloak
Authorization Code + PKCE end-user tokens are issued through the approved
fixture; the tests are black-box HTTP only and never import the ASGI app.

The default `mtmf` stack inventory was captured before and after and was
**unchanged**.

## 2. Executed cycles (0 skips)

```text
COLD-01 PASS
REPEAT-01 PASS
RECREATE-01 PASS
default stack inventory unchanged
```

Each cycle ran PR 20A L01–L05 and the 18 PR20B conformance cases:

| Cycle | PR 20A | PR 20B | Skips/retries |
| --- | --- | --- | --- |
| COLD-01 | 5 passed | 18 passed | 0 |
| REPEAT-01 | 5 passed | 18 passed | 0 |
| RECREATE-01 | 5 passed | 18 passed | 0 |

The launcher fails the cycle on any `skipped`/`xfailed`/`xpassed`/`failed`/
`error` marker, so a required case cannot silently become a PASS.

## 3. Part C — lifecycle and subscription matrix (executed)

| ID | Case | Observed |
| --- | --- | --- |
| L20B-01 | T1 active, A1 subscribed, Alice permitted, D1 present | `200` exact D1; real `event=mtmf_evaluate` |
| L20B-02 | A1 unsubscribed from T1 | no body; authoritative rejection (`403`); no D1 content |
| L20B-03 | subscription restored | `200` exact D1; no residual deny |
| L20B-04 | T1 suspended | no `200`; no body |
| L20B-05 | T1 reactivated | `200` exact D1 |
| L20B-06 | verified Bob in T1, no Role | `403`; real MTMF DENY |
| L20B-07 | Alice requests another-Tenant D2 | `404`; **no** MTMF evaluation |
| L20B-08 | absent token | `401`; **no** MTMF evaluation |

State transitions were performed exclusively through
`scripts/pr20b_fixture_transitions.py` (sanctioned stored functions as
`mtmf_migrator`), and the autouse fixture restored `activate-tenant`,
`subscribe`, and `grant-role` before and after every case.

## 4. Part D — spoofing / identity binding matrix (executed subset)

| ID | Case | Observed |
| --- | --- | --- |
| S01 | spoofed `X-MTMF-User-Authorization`, no `Authorization` | `401`; no evaluation |
| S03 | arbitrary `X-Tenant-ID`/`X-Application-ID`/`X-Actor-ID`/`X-Session-ID` | ignored; `200` exact D1 for Alice |
| S04 | body `tenant_id` spoof on batch | `400`; no evaluation |
| S06 | T1 actor reads another-Tenant document | `404`; no evaluation (= L20B-07) |

**Not executed (deviation):**

- **S02** (Bob Bearer + Alice token in a spoofed forwarding header): the app
  only accepts the standard `Authorization` header and the official client is
  the sole constructor of the outbound assertion; the spoofed-header-without-
  `Authorization` case S01 already proves the forwarding header is ignored.
  A combined Bob+Alice-header case was not added because it would not exercise
  a distinct code path (the app never reads the forwarding header inbound).
- **S05** (wrong audience/issuer/typ or bad signature): the cryptographic
  verifier rejects these; the case is covered by existing lower-level tests
  (`examples/mtmf-reference-app/tests/test_auth.py`, PR20A U04) rather than
  deployed. Minting an isolated wrong-claims issuer is possible but was not
  wired in this run.
- **S07** (service credentials presented as end-user Bearer): not executed;
  requires a dedicated service-token mint step.
- **S08** (unknown cryptographically verified subject): not executed; requires
  an additional non-fixture Keycloak user.

## 5. Part B — deployed batch route (executed)

| ID | Case | Observed |
| --- | --- | --- |
| B01 | Alice batch `[D1, D3]` | `200`; ordered bodies, one evaluation |
| B02 | Bob batch `[D1, D3]` | `403`; **zero** bodies (no D1/D3 content) |
| B03 | batch including another-Tenant D2 | `404`; no evaluation |
| B04 | duplicate ids | `400`; no evaluation |

`D3` is the PR20B fixture document
`d0c0a1e0-0004-4000-8000-000000000004`, seeded through the existing fixture
loader. The **mixed ALLOW/DENY in one verified-user batch** case is not
executed: see the P0 STOP below.

## 6. Part E — revocation (executed) and snapshot semantics

| ID | Case | Observed |
| --- | --- | --- |
| N09 | revoke Alice's fixture Role, next deployed GET | `403`; no content; real evaluation |
| N10 | restore the exact assignment, next deployed GET | `200` exact D1 |

Because the PR20A PEP re-evaluates every request, no cross-request stale window
is claimed. Deterministic snapshot exactness/expiry (N01–N08) is covered by the
existing `tests/unit/client/test_client_snapshot.py` (CL-U27..U45) and
`test_client_transport.py`; no missing exact case required a new client test.

## 7. Part F — deterministic remote faults

The acceptance-only fault fronting component `scripts/pr20b-fault-proxy.py` was
implemented and unit-tested (`tests/unit/service/test_pr20b_harness.py`:
control-file selection, pass-through default, response tamper). The deployed
F01–F07 matrix was **not executed**. Reason (precise constraint): the component
must front `/v1/authorization/evaluate`, but the canonical PR20A TLS leaf is
pinned to SAN `DNS:mtmf.mtmf.test`, and that network alias is owned by the
existing `service-tls-proxy` container. Inserting the fault proxy without a
second SAN on the pinned leaf or a network-alias reassignment would change the
canonical project topology. No fault was injected into production MTMF, the
client, or the default stack.

## 8. Part G — concurrency (executed)

| ID | Case | Observed |
| --- | --- | --- |
| G01 | 32 concurrent GETs (16 Alice / 16 Bob), barrier start | all Alice `200` with exact body; all Bob `403` with no body; no 5xx; no cross-actor mixing |

## 9. P0 — mixed-batch STOP

The same-actor, same-Action, same-Tenant mixed ALLOW/DENY batch cannot be
produced: policy matching is on the exact Action URN only
(`CompiledPolicy`), and `ResourceTarget` is used solely for the Tenant/
management boundary (`target_is_permitted`). See
[`PR20B_STOP_REPORT.md`](PR20B_STOP_REPORT.md). No fabricated decision or
invented Action was substituted.

## 10. Evidence / log locations

- Launcher stdout: captured during execution (COLD/REPEAT/RECREATE markers,
  per-suite pytest summaries, reference-app container ids).
- Unit gate and example coverage: `PR20B_FINAL_ACCEPTANCE_REPORT.md`.
- Artifacts committed under `docs/pr-artifacts/pr-20b/`.
