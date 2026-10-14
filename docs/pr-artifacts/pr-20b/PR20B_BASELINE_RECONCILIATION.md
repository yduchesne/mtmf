# PR20B_BASELINE_RECONCILIATION

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Required artifact directory:** `docs/pr-artifacts/pr-20b/`
**Execution branch:** `dev/pr20b-conformance`
**Baseline:** merged `main` after PR 20A
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**Reconciliation status:** **PHASE 0 COMPLETE — architecture unchanged; one intentional early STOP gate opened (P0 mixed batch). See `PR20B_STOP_REPORT.md`.**

## 1. Fresh-main reconciliation

| Item | Value |
| --- | --- |
| `git rev-parse HEAD` at branch creation | `c7c992a372bb83bae3837efb04b1f19742bb83e2` |
| `git rev-parse origin/main` | `c7c992a372bb83bae3837efb04b1f19742bb83e2` (identical; no divergence) |
| Working tree at start | clean |
| Branch | `dev/pr20b-conformance` (created from `origin/main`, tracking `origin/main`) |
| Alembic migration head | `0013_security_mutation_audit_partitioning` |
| Python (uv environment) | 3.14.7 |
| Container Python | `python:3.14-slim` |
| PostgreSQL | 18.6 (acceptance uses `docker.io/library/postgres:18`) |
| Keycloak | `quay.io/keycloak/keycloak:26.8.0-1` |
| Podman | 4.9.3, `podman-compose` present |
| Roadmap section | `docs/ROADMAP_V01.md` §"PR 20B — End-to-End Conformance and Resilience [PLANNED; depends on PR 20A]" |

No divergence from the inspected architecture was found. The verified anchors in
the execution plan (`examples/mtmf-reference-app/**`, `packages/mtmf-client/**`,
`scripts/pr20a-*`, `tests/e2e/reference_app/test_pr20a_live_reference_app.py`)
match merged `main` exactly.

## 2. Authoritative documents read

- `AGENTS.md`
- `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`
- `docs/ROADMAP_V01.md` (PR 20 / 20A / 20B sections)
- `docs/SECURITY_MODEL.md`, `docs/AUTHORIZATION.md`, `docs/ARCHITECTURE.md`,
  `docs/DATABASE.md`, `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`
- `docs/pr-artifacts/pr-20a/*` (baseline, boundary review, deployed, final,
  fixup acceptance reports)

## 3. Verified repository anchors (as inspected on baseline SHA)

| Anchor | File | State |
| --- | --- | --- |
| Reference PEP read ordering | `examples/mtmf-reference-app/src/mtmf_reference_app/app.py` | JWT verify → server mapping → Tenant-scoped `DocumentStore.load` → `ResourceTarget(APPLICATION_OWNED, "document", loaded_id)` → single-action `AuthorizationBatchRequest` → `HttpMtmfClient.evaluate` in `BoundedWorker` → exact `require` |
| Independent auth | `auth.py`, `config.py` | pinned issuer/audience/JWKS, RS256, token-type/temporal checks; no MTMF trust import |
| App-owned store | `store.py` | parameterized Tenant+document equality SQLite query |
| Official client | `packages/mtmf-client/src/mtmf_client/client.py` | strict request/response conformance, no POST retry, context-bound monotonic snapshot, exact `require` |
| Snapshot semantics | `packages/mtmf-client/src/mtmf_client/snapshot.py` | `TrustedActorContext`, `_context_matches`, `_snapshot_is_live`, `_find_decision`; unknown/ambiguous → deny |
| Acceptance orchestrator | `scripts/pr20a-reference-acceptance.py` | project `mtmf-pr20a-acceptance`; `preflight/up/test/down/recreate/acceptance`; real PostgreSQL 18 + Keycloak + MTMF + TLS terminator + reference app |
| Fixture provisioning | `scripts/pr20a_reference_fixture.py`, `scripts/pr20a-initialize.py` | sanctioned `action_add` / `role_add` / `identity_role_assignment_add`; exact document-read Action/Permission; TENANT Role for the fixture Tenant |
| Live black-box suite | `tests/e2e/reference_app/test_pr20a_live_reference_app.py` | L01–L05, real Keycloak Authorization Code + PKCE tokens |
| Worker capacity fixup | `app.py` `BoundedWorker.run` + `tests/test_worker.py` | slot held until executor future completes |

## 4. Preflight evidence (fresh, on baseline SHA)

Command:

```text
uv run python scripts/pr20a-reference-acceptance.py preflight
```

Observed:

```text
PR 20A acceptance preflight passed
```

This executes `_verify_issuer_constants`, `_validate_compose_isolation`,
`_require_tools`, `_dns_ok`, `_ports_free`, and `_assert_owned`. At the time of
this reconciliation the isolated acceptance project had no containers, the
host ports `29532/29543/29501/29511` were free, and `keycloak.mtmf.test`
resolved to loopback.

## 5. Existing-vs-missing inventory (summary)

The full, per-contract inventory and mapping to the PR20B matrices is in
[`PR20B_MATRIX_AND_FIXTURE_CONTRACT.md`](PR20B_MATRIX_AND_FIXTURE_CONTRACT.md).

**Previously verified by PR 20A (deployed):** single-document deployed
ALLOW/DENY for the same seeded document, invalid/missing auth, missing and
cross-Tenant document, local exact enforcement, worker lifetime, fixture Role
aggregate idempotency, COLD/REPEAT/RECREATE.

**Not started before PR20B:** deployed lifecycle/subscription matrix, spoofing
breadth, mixed batch, snapshot expiry/revocation consumer contract,
deterministic outage/protocol injection, concurrent black-box stress, and
consolidated parity/contract regression evidence.

**Lower-level existing tests identified for reuse (not rewritten):**

- `tests/unit/client/test_client_snapshot.py` — CL-U27..U45 snapshot context,
  expiry, ambiguity, provenance, monotonic anomaly (N01–N07).
- `tests/unit/client/test_client_resource_binding.py`,
  `test_client_transport.py`, `test_client_observability.py` — response
  conformance / no-retry / telemetry (N08 support).
- `tests/integration/postgres/test_pr17_live_http.py`,
  `test_pr17b_live_acceptance.py`, `test_pr17b_compose_isolation.py`,
  `test_pr18_live_client.py`, `test_pr19c_live_management.py` — live
  endpoint/client/management contracts (opt-in).
- `tests/integration/postgres/pr17b_fault_proxy.py` — existing deterministic
  Admin-REST fault-proxy pattern supporting the Part F approach.
- `tests/unit/service/test_pr19c_live_orchestrator.py` — orchestrator
  unit-test pattern.

## 6. Conclusion

No contract below requires new production MTMF architecture. The one
architectural gate encountered is the **P0 mixed-batch** gate in Part B, which
is a genuine STOP under the approved policy model (Permissions match exact
Actions, never resource instances). It is documented in
[`PR20B_MATRIX_AND_FIXTURE_CONTRACT.md`](PR20B_MATRIX_AND_FIXTURE_CONTRACT.md)
§5 and [`PR20B_STOP_REPORT.md`](PR20B_STOP_REPORT.md).
