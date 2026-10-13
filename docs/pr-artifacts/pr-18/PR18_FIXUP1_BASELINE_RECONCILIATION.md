# PR 18 Fixup 1 — Baseline Reconciliation

**Fixup scope:** explicit Action/ResourceTarget binding for the PEP helpers;
CL-I16 owned-service restart acceptance.
**Branch:** `dev/mtmf-client-impl`.

## 1. Repository state

| Item | Value |
| --- | --- |
| Active branch | `dev/mtmf-client-impl` |
| PR 18 implementation tip (pre-fixup) | `5291ed7a2366f6e931eec8d34f8ed2a63fbba100` |
| `origin/main` / merge base | `ad30ff50feb84d8e2e9a15f6ca01b2ac01ec05c7` |
| `5291ed7` ancestor of HEAD | yes (`5291ed7 == HEAD` for the inspected baseline) |
| Working tree at start | clean |

The fixup is applied directly onto the existing PR 18 implementation branch,
not a new architectural PR. No unapproved scope drift was observed.

## 2. Pre-edit test baseline

```bash
uv run --no-sync pytest tests/unit/client -q --no-cov
# 122 passed
```

Prior PR 18 report numbers (`--qa` 2275 / 91.34%, `--sec`, `--rust`,
`--integration` 564/80, live 15×3) are classified as **reported prior
evidence**, not fixup acceptance, and were not re-derived from the old
reports.

## 3. Inspected components (reused, not redesigned)

| Component | Finding |
| --- | --- |
| `packages/mtmf-client/src/mtmf_client/snapshot.py` | `_find_decision` allowed `request_id`-only and `action`-without-resource lookups. `_context_matches`, `_snapshot_is_live`, `_Provenance`, `_owned_by` reused. |
| `packages/mtmf-client/src/mtmf_client/client.py` | `is_allowed`/`require` delegate to the snapshot helpers after the `_owned_by` check; `_build_snapshot` conservatively caps snapshots at 15 s (preserved). |
| `packages/mtmf-client/src/mtmf_client/config.py` | Immutable `ClientConfig`; unchanged. |
| `packages/mtmf-client/src/mtmf_client/credentials.py` | Single-flight Client Credentials cache; unchanged. |
| `packages/mtmf-client/README.md` | Taught `require(..., request_id=...)` without a resource; corrected. |
| `tests/integration/postgres/test_pr18_live_client.py` | CL-I01–I15, I17, I18 present; CL-I16 missing; CL-I15 lacked an explicit row-42 target. |
| `mtmf-api` DTOs / conformance | Unchanged; the DTO already validates `ResourceTarget` construction. |

## 4. Fixup delta

- `snapshot.py`: mandatory keyword-only `action`/`resource`; exact-match
  `_find_decision`; no action-only/request-id-only/implicit-resource path.
- `client.py`: the same required parameters on the client-bound methods.
- Migrated every repository call site (unit tests, live tests, README).
- Added `tests/unit/client/test_client_resource_binding.py` (FX-U01–FX-U26).
- Added `test_cl_i16_owned_uvicorn_restart_recovery` to the live module.

## 5. Related fixup artifacts

- `PR18_FIXUP1_API_CONTRACT_AND_TEST_MATRIX.md`
- `PR18_FIXUP1_CL_I16_LIVE_ACCEPTANCE.md`
- `PR18_FIXUP1_QUALITY_GATES.md`
- `PR18_FIXUP1_STOP_DEVIATIONS.md`
- `PR18_FIXUP1_FINAL_ACCEPTANCE.md`
