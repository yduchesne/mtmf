# PR19C_AMENDMENT05_BASELINE_RECONCILIATION

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Branch:** `dev/mgmt-mutation`. **Base (origin/main):** `0f6d3fe`. **Tip before this amendment:** `793d2f8`.

## Two review findings and resolution

| Finding | Observed | Resolution |
| --- | --- | --- |
| F1: H01–H05 used a test-owned Uvicorn (`_LiveServer` on 28012) instead of the Compose-managed `service` (29001) | `test_pr19c_live_management.py` built its own app | VERIFIED FIXED: suite is now a black-box `httpx` client of the deployed service at `http://127.0.0.1:29001`; no `uvicorn`/`create_app`/`build_dependencies` in the live path |
| F2: roadmap PR 19C heading `[DONE]` but paragraph began `PARTIAL — not DONE (live acceptance BLOCKED)` | stale contradictory text | VERIFIED FIXED after deployed-service acceptance passed |

## Reconciled state

- HTTP endpoint, DTO/codec, adapter, v012 audited mutation, privilege closure, concurrency proof: DONE (Amendments 01–02), regression only.
- Isolated acceptance topology: DONE (Amendment 04), preserved.
- Deployed-service black-box H01–H05: DONE (this amendment).

## Default-stack preservation

The acceptance orchestrator never starts/stops the default `mtmf` stack; it compares a read-only inventory before/after `acceptance-pr19c`, which matched.
