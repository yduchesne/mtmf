# PR 23 — STOP and Deviation Report

**Final status: no active STOP. Verdict `PR23_COMPLETE_INTERNAL_ONLY`
(“DONE — INTERNAL PARTICIPANT ONLY”).**

The two issues that previously blocked acceptance were resolved without changing
authentication policy, the committed trust baseline, or any security-relevant
Keycloak setting.

## Resolved STOP-08 (live acceptance)

- **Original symptom:** PR 23 L01–L04 failed 4/4 with
  `AuthenticationFailure.ATTESTATION_DRIFT`.
- **Exact cause:** the committed `dev/keycloak/expected-realm-security.json`
  baseline names realm `mtmf-dev`; the live fixture was
  `mtmf-pr14-dev`. Field-by-field comparison showed:
  - `realm`: `mtmf-dev` vs `mtmf-pr14-dev` — **mismatch**;
  - `realmSecurity`: identical — no difference;
  - `clientScopes`: identical — no difference.
  The attestor intentionally excludes the realm client inventory and verifies
  admitted clients separately against `expected-client-policy.json`.
- **Resolution:** fixture selection only. The existing isolated Keycloak was
  configured with `dev/keycloak/setup-realm.py --realm mtmf-dev`, reproducing the
  approved realm name, realm-security projection, client scopes, and approved
  client projections. No baseline file, client policy, issuer-validation rule,
  attestation rule, or Keycloak security setting was modified.
- **Evidence:** PR 23 L01–L04 **4 passed, 0 skipped**; PR 14 live regression
  **22 passed, 0 skipped**. Diagnosis:
  [PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md](PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md).

## Resolved environment failure (Rust gate)

- **Original symptom:** `./build.sh --rust` could not start because `cargo` was
  absent.
- **Resolution:** installed the repository-supported Rust toolchain via rustup
  (stable `1.99.1`, rustfmt, clippy) at the documented `~/.cargo/bin` location.
- **Evidence:** `./build.sh --rust` passed (fmt, clippy `-D warnings`, cargo test,
  maturin develop, installed-native probe, focused boundary/differential tests,
  clean wheel build/install/use, benchmark smoke).

## QA count reconciliation (no unresolved deviation)

The earlier 2201 passed / 177 skipped QA result was caused by the missing native
`_mtmf_permission_engine` module, which skips native/Rust-conditioned tests and
suppresses their parametrized differential cases. With the toolchain installed,
the same QA gate reports:

- unmodified `main` @ `1bb46af` (clean worktree): **2472 passed, 0 skipped,
  90.32%**;
- PR 23 branch: **2490 passed, 0 skipped, 90.30%**.

The delta is exactly the 18 new PR 23 unit cases. The `main` count matches the
PR 22A reported 2472. No test was unintentionally excluded.

## Other STOPs

STOP-00, STOP-01, STOP-02, STOP-03, STOP-04, STOP-05, STOP-06, STOP-07, STOP-09,
and STOP-10 did not fire. See
[PR23_SECURITY_AND_PRIVILEGE_REPORT.md](PR23_SECURITY_AND_PRIVILEGE_REPORT.md)
for the privilege/root/audit evidence and
[PR23_FINAL_ACCEPTANCE_REPORT.md](PR23_FINAL_ACCEPTANCE_REPORT.md) for the final
gate checklist.

## Push status

No push and no pull request. Explicit maintainer authorization is required.
