# PR20B_SECURITY_BOUNDARY_REVIEW

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**Implementation SHA (validated working tree):** `61649b4969eb882501920a506584f2bba581d125`
**Status:** implemented and deployed-acceptance verified **except** the P0
mixed-batch gate (explicit STOP).

## 1. Non-negotiable invariant

> No reference-app resource content is disclosed unless the independently
> authenticated user, the app-owned Tenant-scoped resource, the MTMF-issued
> exact Action/resource decision, and a locally enforced unexpired
> context-bound ALLOW all agree. Every mismatch, missing grant, malformed
> response, timeout and outage fails closed.

This invariant is unchanged from PR 20A. PR 20B adds a **multi-document** route
that preserves it with an all-or-nothing disclosure rule.

## 2. Trust boundaries preserved

| Boundary | Owner | PR20B effect |
| --- | --- | --- |
| End-user authentication | reference app (`auth.py`) | unchanged; every batch request re-verifies the Bearer token at the app boundary |
| Subject → Tenant mapping | reference app (server-owned fixture mapping) | unchanged; never caller input |
| Document ownership/isolation | reference app (`store.py`) | batch resolves every row with a Tenant equality predicate before authorization |
| Policy decision | MTMF service (PDP) | one ordered batch per request; never reconstructed by the app or the client |
| PDP transport/conformance | official `mtmf-client` | unchanged; no reimplementation, no POST retry |
| Local enforcement | official `require` helper | called once per occurrence in input order before any body is serialized |
| Acceptance policy fixture | privileged one-shot initializer | unchanged; PR20B adds no Action/Role/Permission |
| Lifecycle/subscription/Role mutation | privileged one-shot transitions helper | sanctioned stored functions only, as `mtmf_migrator`, DB identity verified |

## 3. Batch route security ordering (`POST /v1/documents/batch-read`)

1. extract the `Authorization: Bearer` token; absent → `401`, no MTMF call;
2. parse the body as exactly `{"document_ids": [...]}`; wrong shape/unknown
   field/duplicate/non-canonical UUID/fewer than 1 or more than 16 entries →
   `400`, no MTMF call, no store read;
3. cryptographically verify the token; failure → `401`;
4. resolve the server-owned subject binding; unknown subject → `403`, no MTMF
   call;
5. load **every** requested row with the trusted Tenant + id equality
   predicate; any absent/cross-Tenant row → generic `404`, no MTMF call, no body;
6. derive one `ResourceTarget` per loaded row and build **one** ordered
   `AuthorizationBatchRequest` with one occurrence per row and
   `request_id="document-read-<index>"`;
7. evaluate once through the bounded worker using the official client;
8. call `require` for **every** occurrence in input order;
9. only if every `require` succeeds, serialize the ordered success body.

The route accepts **no** Action, Tenant, Application, actor, session, or target
parameter from the caller. Caller-supplied `tenant_id`/`application_id` in the
body is an unknown field and is rejected with `400`.

## 4. Atomic disclosure

A single non-ALLOW occurrence raises before the response is built, so the app
returns `403` with **zero** document bodies — it never partially returns the
authorized subset. This was verified by a unit test with a per-occurrence
decision client (`test_batch_deny_is_atomic_with_zero_bodies`) and by the
deployed all-deny batch case.

## 5. Error mapping (unchanged)

| Condition | Status | Body disclosed |
| --- | --- | --- |
| Missing/malformed/unverifiable token | 401 | no |
| Unknown verified subject | 403 | no |
| MTMF policy or eligibility DENY | 403 | no |
| Missing/cross-Tenant/malformed resource | 404 | no |
| Invalid batch input | 400 | no |
| Dependency/timeout/protocol failure | 503 | no |

Every response sets `Cache-Control: no-store`.

## 6. Fixture-transition safety

`scripts/pr20b_fixture_transitions.py`:

- refuses any profile other than `Development`;
- connects only as `mtmf_migrator`;
- verifies `current_database()` equals the explicitly configured
  `MTMF_PR20B_ACCEPTANCE_DB` before any mutation;
- uses only `suspend_tenant`/`activate_tenant`/
  `tenant_application_subscription_save`/`identity_role_assignment_remove`/
  `identity_role_assignment_add`; no raw table write, `UPDATE`, or `DELETE`;
- prints only non-secret identifiers; performs no IdP I/O in a transaction;
- is never imported by the reference app.

## 7. Deliberately unchanged

- `packages/mtmf-api`, `packages/mtmf-client`, `packages/mtmf-core`,
  `packages/mtmf-service` — no production code changed.
- `packages/mtmf-core/.../sql/**` and Alembic migrations — head remains `0013`.
- Protected built-in policy manifests and `dev/keycloak/expected-*.json`.
- `compose.yaml`, `compose.dev.yaml`, `compose.pr19c-acceptance.yaml`.
- Default `mtmf` stack and all foreign (ATI/Darkula/PR 19C) resources.

## 8. Residual risk and explicit STOP

The **P0 mixed-batch** deployed proof is not representable under the approved
policy model (Permissions match exact Action URNs, never resource instances).
This is an explicit STOP recorded in
[`PR20B_STOP_REPORT.md`](PR20B_STOP_REPORT.md); it is not silently omitted and
not replaced by a fabricated test. Consequently PR 20B is **not** marked DONE.

The deterministic fault fronting component
(`scripts/pr20b-fault-proxy.py`) is implemented and unit-tested, but the
deployed F01–F07 fault matrix was **not executed** because inserting it into the
canonical PR20A topology would require either a second TLS SAN on the pinned
acceptance leaf or a network-alias reassignment of the existing terminator —
a topology change to the canonical project. This is recorded as a deviation in
[`PR20B_DEPLOYED_ACCEPTANCE_REPORT.md`](PR20B_DEPLOYED_ACCEPTANCE_REPORT.md).
