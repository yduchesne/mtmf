# PR22A_FINAL_ACCEPTANCE_REPORT

**Roadmap identifier:** PR 22A — Entitlement persistence foundation
**Status:** **DONE — ENTITLEMENT FOUNDATION ONLY.**
**Explicitly not delivered:** quota consumption, replay ledger, atomic
first-Tenant creation, Identity/Principal/stewardship composition,
operator/pre-Tenant privileged execution, onboarding HTTP.

## 1. Delivered and verified

| Area | State |
| --- | --- |
| Revision `0014` entitlement table + append-only event history | Implemented + verified |
| `ACTIVE`/`REVOKED` terminal lifecycle; immutable provenance; single ACTIVE per Application | Implemented + verified |
| Explicit positive quota (not consumption) | Implemented + verified |
| Owner-only `SECURITY INVOKER` functions, empty `search_path`, PUBLIC revoked, no `mtmf_runtime` grant | Implemented + verified |
| Detached domain contract + pure validators | Implemented + unit-verified |
| Concurrent duplicate-grant race | Verified (exactly one ACTIVE) |
| No Tenant/registration/subscription/steward side effects | Verified |
| Migration postflight + unchanged 78-signature allowlist | Verified |

## 2. Acceptance checklist

| # | Criterion | Result |
| --- | --- | --- |
| 1 | Branch/tip reconciled; Git integrity (`git fsck --full`) clean | PASS |
| 2 | No new `mtmf_runtime` grant, `SECURITY DEFINER`, or proxy | PASS |
| 3 | No `0006`/`0012` change; no new Action/Permission/Role seed | PASS |
| 4 | Real-PostgreSQL restricted-runtime denial tests | PASS |
| 5 | 13 entitlement tests executed and passed | PASS |
| 6 | `--qa` / `--sec` / `--rust` / `--integration` | PASS (606 integration passed) |
| 7 | Coverage ≥ 85% | PASS (90.32%) |
| 8 | Roadmap split (PR 22A/22B/24P), original PR 22 PARTIAL — BLOCKED preserved | PASS |
| 9 | Artifacts under `docs/pr-artifacts/pr-22a/`; historical `pr-22/` preserved | PASS |
| 10 | No push / no merge | PASS (none) |

## 3. Gates

`--qa` 2472 passed / 90.32%; `--sec` 0 findings; `--rust` pass; `--integration`
606 passed / 90 skipped; `git diff --check` clean; `git fsck --full` exit 0.
See `PR22A_INTEGRATION_ACCEPTANCE_REPORT.md`.

## 4. Dependencies / next steps

- **PR 23** — verified-subject, Identity/Principal, initial stewardship
  transaction participant.
- **PR 24P** — privileged operator + pre-Tenant admission execution boundary;
  STOP-P24P-TOPOLOGY requires a human-approved topology before implementation.
- **PR 22B** — atomic first-Tenant composite, quota, replay (blocked until both).
- **PR 24** — HTTP onboarding/management (depends on PR 22B + PR 24P).

## 5. Verdict

**PR 22A: DONE — ENTITLEMENT FOUNDATION ONLY.** Original PR 22 remains
historically PARTIAL — BLOCKED. v0.1 onboarding is NOT DONE.
