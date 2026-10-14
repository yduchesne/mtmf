# PR19A_IMPLEMENTATION_REPORT

**PR:** roadmap PR 19A — verified-provenance mutation audit.
**Status:** **PARTIAL / BLOCKED.** Contract scaffold and deterministic tests only.
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5`.

## 1. Scope actually implemented

Per Phase 0 (`PR19A_TRUST_BOUNDARY_RECONCILIATION.md`), no category-A authenticated+authorized management mutation entry point exists, so the plan's mandatory early STOP applies. The only implementation is the internal immutable provenance contract and its deterministic validation tests, exactly as the STOP permits ("Implement only the contract and deterministic tests that can be proven without a new management feature").

### 1.1 Files added

| File | Purpose |
|---|---|
| `packages/mtmf-core/src/mtmf_core/application/mutation_provenance.py` | Internal immutable `VerifiedMutationProvenance` contract, structural validation, and the fail-closed `require_registered_mutation` closed-registration guard. |
| `tests/unit/application/test_mutation_provenance.py` | Deterministic contract/validation tests (PA-U01, PA-U02, PA-U03, PA-U04, PA-U13 subset). |

### 1.2 Contract semantics

`VerifiedMutationProvenance` is a `@dataclass(frozen=True, slots=True)` with exactly the plan's fields:

```
operation_id: UUID
actor_identity_id: DomainId
actor_principal_id: DomainId
tenant_id: DomainId
application_id: DomainId
action_urn: ActionUrn
target_kind: str
target_id: DomainId
authorized_at: datetime   # timezone-aware UTC
```

- `__post_init__` rejects: non-`UUID` `operation_id`; non-`DomainId` actor/principal/tenant/application/target; non-`ActionUrn` `action_urn`; empty/whitespace-only/over-length `target_kind`; naive, non-UTC-offset, or non-`datetime` `authorized_at`.
- There is **no** public `from_actor_id`/`for_actor`/`trusted` factory and no boolean `trusted`/`verified` field; construction is direct and documented as confined to a future reviewed orchestration path.
- `authorized_at_utc` re-labels the validated offset-zero instant with `datetime.UTC` (formatting/comparison only).
- The closed registration mapping is **empty** in PR 19A (`registered_mutations()` returns a read-only empty mapping). `require_registered_mutation(provenance)` fails closed unless the `(target_kind, action_urn)` pair is explicitly registered; structural validity never implies audit coverage.
- The module is **not** re-exported from `mtmf_core` or `mtmf_core.application`, and no `mtmf-api` DTO references it (internal-only, no transport exposure).

## 2. What was deliberately **not** implemented

| Plan item | Status | Reason |
|---|---|---|
| Phase 1.6–1.8 — bind provenance to an existing management use case after verification + exact ALLOW | **NOT DONE** | No category-A use case exists. |
| Phase 2.9–2.12 — `0012_pr19a_verified_mutation_audit`, `sql/v012/`, `security_state_mutation_audit`, stored functions, grants, revocations | **NOT STARTED** | Gated on Phase 0 success. Creating them without a legitimate callsite would be speculative plumbing and would not close the audit gap. |
| Phase 3.15 — end-to-end trusted-application → PostgreSQL journey | **BLOCKED** | No eligible existing path; no synthetic "live" substitute created. |
| New migration revision | none | Head remains `0011`; no shipped `v001`–`v011` or migration was edited. |
| New management API / route / DTO / client method | none | Explicitly out of scope and a STOP trigger. |
| Partitioning / retention | none | PR 19B owns it. |

## 3. Stored functions, grants, and privilege changes

**None.** No stored function was added or modified; no `GRANT`/`REVOKE` was issued; the runtime allowlist is unchanged. The mandatory post-upgrade privilege verifier therefore requires no manifest update and still passes (`./build.sh --integration`).

## 4. Documentation changes

| Document | Change |
|---|---|
| `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md` | Records the PR 19A contract-only/BLOCKED status, the trusted-application provenance guarantee, and the explicit database non-attestation limitation. |
| `docs/DATABASE.md` | Records that PR 19A added no schema/function/grant and that the mutation-audit gap remains open. |
| `docs/ROADMAP_V01.md` | Adds PR 19A (with factual PARTIAL/BLOCKED status) between PR 19 and the planned PR 19B partitioning item. |
| `docs/pr-artifacts/pr-19/PR19_STOP_REPORT.md` | Dated cross-reference to the PR 19A disposition; historical evidence otherwise unchanged. |

## 5. Operation coverage

| Operation category | Coverage after PR 19A |
|---|---|
| Category-A authenticated management mutations | **COVERED: none exist** (so no operation is covered, and none is falsely claimed). |
| Structural repository writes (category C) | `STRUCTURAL/UNVERIFIED` — unchanged. |
| Privileged operator/bootstrap writes (category B) | `PRIVILEGED-OPERATOR` — unchanged. |
| Membership removal | `COVERED (pre-existing)` — pre-existing unverified-attribution audit, unchanged. |
| Root/stewardship | `COVERED (pre-existing)` — unchanged; root recovery's separate durable operator audit remains mandatory. |
| All other writes | `BLOCKED` — awaiting an approved verification/authorization seam. |

## 6. Verification of the change

- `./build.sh --qa`: PASS (`2105 passed, 177 skipped`, coverage 90.76%; new module 100%).
- `./build.sh --sec`: PASS (0 findings).
- `./build.sh --rust`: PASS.
- `./build.sh --integration`: PASS (`564 passed, 86 skipped`).
- No public API, batch PDP, Rust engine, telemetry, membership/stewardship audit, or root-recovery behavior changed.
