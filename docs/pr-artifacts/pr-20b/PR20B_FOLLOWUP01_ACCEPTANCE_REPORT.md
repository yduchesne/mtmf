# PR20B_FOLLOWUP01_ACCEPTANCE_REPORT

**PR:** roadmap PR 20B — Follow-up 01: genuine mixed-action conformance,
deployed faults, and spoofing closure.
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Branch:** `dev/pr20b-conformance`
**Baseline reconciliation (follow-up start):** `a13ededd8aa04ea210d1aca0e5e8454a99492ff1`
**Validated implementation SHA:** `7f9092ddebb7913059a03c6996e5394180247bc2`
**Status:** **DONE** — all mandatory gates and deployed cases executed green,
including the P0 real ordered mixed ALLOW/DENY proof.

## 1. Environment and restricted DB role

| Item | Value |
| --- | --- |
| Python (uv environment) | 3.14.7 |
| PostgreSQL (acceptance) | 18.6 (`docker.io/library/postgres@18`) |
| Keycloak | `quay.io/keycloak/keycloak:26.8.0-1` |
| Acceptance project | `mtmf-pr20a-acceptance` (isolated; default `mtmf` untouched) |
| Privileged fixture identity | `mtmf_migrator` (DB identity verified before mutation) |
| Runtime identity | `mtmf_runtime` (restricted) |
| Alembic head | `0013_security_mutation_audit_partitioning` (unchanged) |

## 2. Canonical gates (executed on the validated SHA)

| Gate | Command | Observed |
| --- | --- | --- |
| Quality | `./build.sh --qa` | Ruff format/lint clean, strict Mypy clean, **2462 passed**, coverage **90.36%** |
| Security | `./build.sh --sec` | Bandit 0 medium/high, Semgrep **0 findings** |
| Examples scan | `uv run semgrep scan --config=auto examples` | **0 findings** (11 files) |
| Rust/native | `./build.sh --rust` | cargo fmt/clippy/test, `maturin develop`, native probe, parity/differential suites, clean wheel, benchmark smoke — **PASS** |
| Integration | `set -a; source .env; set +a; ./build.sh --integration` | **593 passed, 90 skipped** (pre-existing opt-in live suites only) |
| Example package | `uv run pytest examples/mtmf-reference-app/tests --cov=mtmf_reference_app --cov-fail-under=85` | **89.48%** |
| Deployed acceptance | `uv run python scripts/pr20b-reference-acceptance.py acceptance` | **3 cycles**; each **5 PR20A + 45 PR20B**, **0 skips**; default stack inventory unchanged |

The 90 integration skips are the documented pre-existing opt-in live suites
(PR 17/18/19C), **not** PR20B acceptance skips. The dedicated PR20B launcher
reported zero skips in every cycle.

## 3. COLD / REPEAT / RECREATE

```text
COLD-01 PASS
REPEAT-01 PASS
RECREATE-01 PASS
default stack inventory unchanged
```

| Cycle | PR 20A | PR 20B | Skips |
| --- | --- | --- | --- |
| COLD-01 | 5 passed | 45 passed | 0 |
| REPEAT-01 | 5 passed | 45 passed | 0 |
| RECREATE-01 | 5 passed | 45 passed | 0 |

Each cycle re-provisioned the metadata Action/Role/assignments and the fault
overlay. REPEAT proved no duplicate Role/Permission/assignment and no drift;
RECREATE destroyed only acceptance-owned volumes/secrets and re-created the
topology.

## 4. P0 — real ordered mixed ALLOW/DENY (executed)

The isolated fault proxy records a non-secret evidence record for every
successful real upstream evaluation (monotonic counter + `request_id`, exact
`action`, `effect`, non-secret `resource_id`). The deployed acceptance captured:

```text
n=50  actions=[read-metadata, read-object]  effects=[ALLOW, DENY]   resource=D1
n=51  actions=[read-object, read-metadata]  effects=[DENY, ALLOW]   resource=D1
```

These are **genuine MTMF decisions for one verified actor (Bob), one Tenant, one
Application and one loaded T1 document in a single batch**, in both response
orders. The PEP returned HTTP 403 with zero results and zero title/body in both
cases. The reversed-order case and a separate metadata-only success for Bob were
also proven. No decision was fabricated, and no MTMF authorization engine code
was changed.

## 5. Part C — metadata and mixed batch (M01–M13)

| ID | Scenario | Result |
| --- | --- | --- |
| M01 | Bob metadata GET D1 | `200` `{id,title}` only, no `body` |
| M02 | Bob content GET D1 | `403`, no title/body |
| M03 | Alice metadata GET D1 | `200` `{id,title}` only, no `body` |
| M04 | Alice content GET D1 | `200` `{id,title,body}` |
| M05 | Bob batch-access `[metadata D1, content D1]` | real one-batch `ALLOW,DENY`; `403`, zero results |
| M06 | Bob batch-access `[content D1, metadata D1]` | real one-batch `DENY,ALLOW`; `403`, zero results |
| M07 | Alice batch-access `[metadata, content]` | `200` ordered; metadata no `body`, content exact body |
| M08 | Bob metadata-only batch | `200` metadata result, no `body` |
| M09 | Bob existing `batch-read [D1,D3]` | `403`, no bodies (contract unchanged) |
| M10 | cross-Tenant/absent row in batch-access | `404`, zero PDP calls |
| M11 | invalid batch-access shape | `400`, zero PDP calls |
| M12 | restored-state stability | Alice content `200`, Bob content `403`, Bob metadata `200` |
| M13 | mixed-operation concurrency (8/8/8/8) | exact counts, no 5xx, no cross-actor or body mixing |

## 6. Part B — deterministic remote faults (F01–F07)

Faults ran against the **deployed reference app** over real HTTPS with genuine
Keycloak tokens; only the remote `/v1/authorization/evaluate` response was
substituted. Evidence recorded every activated mode:

```text
fault activations: refuse, delay, http_502, http_503, non_json, malformed_json, mismatch
```

| ID | Mode | Observed |
| --- | --- | --- |
| F01 | `refuse` | `503`, no disclosure |
| F02 | `delay` (past client timeout) | `503`, no disclosure; worker lifetime bounded |
| F03a | `http_502` | `503`, no disclosure |
| F03b | `http_503` | `503`, no disclosure |
| F04 | `non_json` (200) | `503`, no disclosure |
| F05 | `malformed_json` (200 JSON type) | `503`, no disclosure |
| F06 | `mismatch` (tamper real correlation) | `503`, no snapshot accepted |
| F07 | `none` after each fault / at end | Alice content `200`, Bob content `403`, Bob metadata `200` |

Each test asserted the intended mode was observed (non-secret activation record)
and restored `none` in `finally`. The service was proven healthy after every
fault (F07), so a `503` cannot be attributed to an unrelated broken service.

## 7. Part C — spoofing closure (S02/S05/S07/S08)

| ID | Test | Result |
| --- | --- | --- |
| S02 | Bob Bearer + Alice in `X-MTMF-User-Authorization` | Bob stays Bob: content `403`, metadata `200`, no content disclosure |
| S05a | real Alice token, tampered signature | `401`, zero PDP calls |
| S05b | real signed wrong-audience user token (`mtmf-evidence-user` client, aud `mtmf-user-api`) | `401`, zero PDP calls |
| S05c | real signed refresh token presented as Bearer (wrong type) | `401`, zero PDP calls |
| S07 | real OAuth client-credentials service token as inbound Bearer | `401`; provenance confirmed via `service_class_ok`; zero PDP calls |
| S08 | genuine `mtmf-user-carol` token, subject excluded from mapping | `403`, zero PDP calls |

## 8. Regression evidence preserved

- `examples/mtmf-reference-app/tests/test_worker.py` W01–W08 (permit retained
  after timeout/cancellation) — passed in `--qa`.
- Content GET and `batch-read` contracts, snapshot provenance/context/TTL,
  ordered-response binding, v1 API contract, Rust/Python parity — passed in
  `--qa`/`--rust`.
- Real-PostgreSQL migration/privilege checks — passed in `--integration`.
- Existing deployed PR20A L01–L05 and PR20B lifecycle/subscription L20B-01–08,
  revocation N09–N10, spoofing S01/S03/S04/S06, and content concurrency G01 —
  passed in all three cycles.

## 9. Fault proxy TLS and routing verification

- Dedicated leaf `mtmf-fault.crt`/`mtmf-fault.key` signed by the **existing**
  acceptance CA, `subjectAltName=DNS:mtmf-fault.mtmf.test`, serverAuth EKU,
  key mode `0600`; SAN reconciled on REPEAT.
- Distinct network alias `mtmf-fault.mtmf.test`; the canonical
  `service-tls-proxy` and its `mtmf.mtmf.test` alias are untouched.
- No new host port published; the overlay container has the acceptance project
  label and is removed on `down()`/`recreate()`.
- TLS verification was never disabled; the reference app verified the fault leaf
  against the existing CA bundle, and the pre/post default-stack inventory was
  identical.

## 10. Defect found and resolved during follow-up

The long deployed suite initially produced intermittent `401`s on
`/v1/authorization/evaluate` at ~300s intervals (the Keycloak access-token
lifespan). Root cause: the official client's default proactive service-token
renewal leeway (`5s`) was smaller than the token-endpoint round-trip in the
acceptance topology, so the reference app briefly presented a service token the
restarted MTMF service considered expired; the service correctly returned
`UNAUTHENTICATED`. Resolution (no MTMF/core/client change): the example app now
configures `ClientConfig.renewal_leeway_seconds` (default `30`, env
`MTMF_REFERENCE_APP_RENEWAL_LEEWAY_SECONDS`). A 400-second time-based probe
crossing the refresh boundary then issued **606 requests with 0 failures**. The
fix and the deployed-acceptance rerun are on the validated SHA.

## 11. Deviations / STOPs

None. All previously deferred spoofing subcases were executed with genuine
tokens; no fabricated tokens, no TLS bypass, no skipped case, and no production
policy change. The S05 wrong-audience subcase used a real Keycloak client
(`mtmf-evidence-user`) with a different audience, signed by the same trusted
issuer; no issuer/audience configuration was weakened.

## 12. Evidence locations

- Deployed launcher stdout: captured during execution (COLD/REPEAT/RECREATE
  markers and per-suite pytest summaries).
- Non-secret decision/fault evidence: acceptance-only
  `/tmp/mtmf-pr20b-acceptance-faults/evidence/evidence.jsonl` (not committed;
  contains no credentials, tokens, or document bodies).
- Reports: this file, `PR20B_FOLLOWUP01_SECURITY_REVIEW.md`, and the dated
  addenda to the prior reports, under `docs/pr-artifacts/pr-20b/`.
