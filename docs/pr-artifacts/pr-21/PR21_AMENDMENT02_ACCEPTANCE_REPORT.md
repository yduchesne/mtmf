# PR21_AMENDMENT02_ACCEPTANCE_REPORT

**PR:** roadmap PR 21 — Amendment 02 (Final Security Policy Decisions)
**Status:** **AMENDMENT 02 DOCUMENTATION ACCEPTANCE: PASS. STOP-02/04/05/06
CLOSED; STOP-03 OPEN. PR 21: NOT DONE.**
**Explicit statement:** documentation-only; no runtime behavior implemented.

## 1. Branch and SHAs

| Item | Value |
| --- | --- |
| Branch | `dev/onboarding-foundation` |
| Base | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Pre-amendment tip | `b79d8aaa4597ca86aff97fdf0645e41ee6853b47` |
| Amendment 02 content commit under test | recorded in `PR21_AMENDMENT02_FINAL_SHA.md` |
| Migration head | `0013_security_mutation_audit_partitioning` |
| Production changes | none |

## 2. Changed files (documentation-only)

`git diff --name-only <pre-tip>...HEAD` shows only `README.md` and `docs/**/*.md`.
No `packages/**`, `tests/**`, SQL, Alembic, `Cargo*`, lockfile, Compose, seed, or
grant change.

- Normative: `docs/ONBOARDING_ARCHITECTURE.md` (§18 + banner/§15/§17
  updates), `docs/ONBOARDING_HTTP_CONTRACT.md` (§16 + banner), `docs/ROADMAP_V01.md`
  (PR 21–26), `README.md`.
- New Amendment 02 artifacts:
  `PR21_AMENDMENT02_{BASELINE_RECONCILIATION,DECISION_RECORD,ACTION_MANIFEST,AUTHORIZATION_MATRIX,STOP_REPORT,SECURITY_CASES,CONTRACT_DIFF,ACCEPTANCE_REPORT,FINAL_SHA}.md`.
- Dated in-place updates (history preserved): original `PR21_STOP_REPORT.md`,
  `PR21_ACCEPTANCE_REPORT.md`, `PR21_SECURITY_MATRIX.md`,
  `PR21_CONTRACT_REVIEW.md`, `PR21_FINAL_SHA.md`, and all relevant
  `PR21_AMENDMENT01_*.md`.

## 3. Decision / STOP state (individually)

| STOP | Decision | State |
| --- | --- | --- |
| STOP-02 | P02 — MTMF-owned per-Application onboarding entitlement, `ACTIVE`/`REVOKED`, system grant/revoke, quotas | **CLOSED** |
| STOP-03 | P03 — exact Action/Permission/Role manifest (method approved; literals unapproved) | **OPEN** |
| STOP-04 | P04 — system-authorized registration + narrow first-Tenant composite exception | **CLOSED** |
| STOP-05 | P05 — fresh-UUID terminal replacement with separate authority/audit | **CLOSED** |
| STOP-06 | P06 — separate service-credential binding management | **CLOSED** |

**STOP-03 exact manifest approval status:** the manifest is
`PR21_AMENDMENT02_ACTION_MANIFEST.md`; every new literal and grant is marked
**NEEDS HUMAN APPROVAL**, and existing seeded URNs (revision `0006`/`0012`) are
marked APPROVED and reused unchanged. No new literal/grant is approved.

## 4. Endpoint contract changes and PR owners

- `POST /v1/onboarding/resolve-or-provision` — PR 24 (+PR 23 seam): entitlement,
  ordering, quota/idempotency, no-mutation reads.
- Application `POST/GET/PATCH` management — PR 24: system authority;
  suspend/resume in place; retire terminal; no credentials.
- Registration `POST/GET/PATCH` — PR 24: **system** authority (P04); `ACTIVE`
  registration prerequisite; first-Tenant exception.
- Subscription `POST/GET/PATCH` — PR 24: Tenant-admin-managed with `ACTIVE`
  registration; resume vs fresh-UUID replacement.
- Invitations — PR 25.
- Credential binding — **not** in this contract; separate PR 24 contract only if
  the PR 14 trust model supports it (P06).

## 5. Preserved source-grounded invariants

- PR 13 lifecycle transitions, guards, restrictive-only `ends_at`, immutable
  `starts_at`, historical rows, unique current-row constraints preserved.
- PR 14 `(issuer, client_id)→Application` and `(issuer, subject)→Identity`
  verified binding preserved; credential mutations remain operator-only and not
  runtime-granted.
- `mtmf_runtime` gains no registry/credential mutation grant; no operator-only
  function exposed.

## 6. Gates and validation

| Check | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **PASS** — 2462 passed, 3 warnings, 90.36% coverage |
| Security | `./build.sh --sec` | **PASS** — Bandit no issues; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | **PASS** |
| Integration | `./build.sh --integration` | **PASS** — 593 passed, 90 skipped |
| Markdown links | repository link checker | **PASS** — 0 broken |
| Contradiction scan | plan §5.2 greps | **PASS** — no adverse contradictions |

These are **documentation/regression** checks only. All feature and E2E tests
for onboarding (matrix C01–C36, A01–A25, B01–B28) are **NOT RUN** and are owned
by PRs 22–26 and PR 26's deployed acceptance.

## 7. Unresolved questions requiring human approval

1. **STOP-03:** approve/amend every literal in
   `PR21_AMENDMENT02_ACTION_MANIFEST.md`, the system-management Role
   composition, and the additive seed migrations. Exact literal table: see
   manifest §2.
2. Entitlement table/function shape and operator quota defaults (PR 22/23;
   semantics fixed by P02).
3. Credential-binding management contract (PR 24, gated on the PR 14 trust
   model).
4. Any additive predecessor-reference schema support for replacement audit
   (PR 22/24).

## 8. Verdict

- **Amendment 02 documentation acceptance: PASS** — the policy decisions are
  normative, the unapproved literals are isolated in a review-ready manifest,
  and STOP-03 is reported unambiguously.
- **PR 21: NOT DONE** — STOP-03 requires human approval before PR 21 can be
  marked DONE.
- **Merge recommendation:** do not merge/claim DONE as a completed security
  freeze until STOP-03 is approved; the Amendment 02 documentation itself is
  safe to review and retain.

**documentation-only; no runtime behavior implemented.**
