# PR 18 Fixup 1 — Final Acceptance

**Status:** **AWAITING HUMAN REVIEW.** All required fixup gates pass; the
only non-executed item is the explicitly out-of-scope shared-Keycloak
restart (NOT TESTED, reviewer decision).

Start point: PR 18 implementation tip `5291ed7a2366f6e931eec8d34f8ed2a63fbba100`.

## 1. Requirements-to-evidence traceability

| Requirement | Evidence | Status |
| --- | --- | --- |
| Exact Action and ResourceTarget mandatory in module and client helpers | `PR18_FIXUP1_API_CONTRACT_AND_TEST_MATRIX.md` §1; FX-U08–U11 | DONE VERIFIED |
| No action-only / request-id-only / implicit-resource / wildcard path | FX-U02, U03, U05, U06, U08–U11, U13 | DONE VERIFIED |
| Duplicate exact occurrences require `request_id`; wrong Action/resource deny | FX-U05, U06, U07, U22, U23 | DONE VERIFIED |
| Context, provenance, monotonic expiry, client-instance ownership preserved | FX-U16, U17, U19; existing CL-U30–U37, U44, U45 | DONE VERIFIED |
| Existing tests migrated without weakening policy semantics | `PR18_FIXUP1_API_CONTRACT_AND_TEST_MATRIX.md` §3; 148 client unit tests pass | DONE VERIFIED |
| CL-I16 owned Uvicorn restart (real TLS/Keycloak/PostgreSQL, same client, failure then recovery) | `PR18_FIXUP1_CL_I16_LIVE_ACCEPTANCE.md` | DONE VERIFIED |
| Keycloak restart | — | NOT TESTED (reviewer decision) |
| Three full live runs, zero retries | `PR18_FIXUP1_CL_I16_LIVE_ACCEPTANCE.md` §3 (16/16 × 3) | DONE VERIFIED |
| `uv sync --locked`, client unit, `--qa`, `--sec`, `--rust`, `--integration` | `PR18_FIXUP1_QUALITY_GATES.md` | DONE VERIFIED |
| Docs/examples show exact checked resource and PEP row isolation | README binding section + example; `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` snapshot section | DONE VERIFIED |
| Reports committed under `docs/pr-artifacts/pr-18/`, no secrets | This fixup report set + preserved original seven reports | DONE VERIFIED |

## 2. Reviewer checklist (plan §9)

- [x] `main` and PR 18 branch reconciled; no unapproved scope drift.
- [x] Exact Action and ResourceTarget mandatory in both helper entry points,
      including when `request_id` is supplied.
- [x] No action-only, request-id-only, wildcard-resource, or implicit
      capability grant path.
- [x] Duplicate exact occurrences require `request_id`; wrong resource and
      wrong Action deny.
- [x] Context, provenance, monotonic expiry and client-instance ownership
      remain enforced.
- [x] Existing live PR 18 tests migrated without changing policy semantics.
- [x] CL-I16 owned Uvicorn restart exercises real TLS, real Keycloak, real
      PostgreSQL, the same client, failure then recovery.
- [ ] Keycloak restart explicitly NOT TESTED unless separately approved and
      executed (open reviewer decision).
- [x] Three full live runs with zero retries; all required gates executed and
      passed.
- [x] Docs/examples show the exact checked resource and independent
      row/Tenant isolation.
- [x] All reports committed under `docs/pr-artifacts/pr-18/`; no secrets or
      unrelated resources changed.
- [x] No roadmap DONE/merge approval claimed before human review.

## 3. Deviations carried forward

- Optional service-token-expiry `401` retry: deferred by contract.
- Universal 15-second snapshot cap: preserved conservative deviation.
- Keycloak restart: NOT TESTED (see `PR18_FIXUP1_STOP_DEVIATIONS.md`).

## 4. Disposition

The fixup is **ready for human review**: the API contract hardening is
implemented and covered, all in-repository call sites are migrated, CL-I16
passes in the real live topology, the full live module passed three
consecutive runs with zero retries, and all canonical gates pass. PR 18
remains **not DONE** pending human review/merge approval, which must also
decide whether a separate isolated Keycloak restart gate is required.
