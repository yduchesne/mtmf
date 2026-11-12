# PR 23 — STOP and Deviation Report

## Triggered STOPs

| STOP | Trigger | Status and evidence |
| --- | --- | --- |
| STOP-08 TEST | Required genuine-token live acceptance could not pass | **FIRED — BLOCKED-LIVE.** The isolated PR 14 Keycloak fixture (`realm mtmf-pr14-dev`) drifts from the committed `dev/keycloak/expected-realm-security.json`: the live realm contains `mtmf-attestation-reader` and `mtmf-evidence-same-client-b`, absent from the baseline. `test_pr23_live_pre_tenant_subject.py` fails 4/4 with `AuthenticationFailure.ATTESTATION_DRIFT` before token-class checks. `test_pr14_live_actor_context.py::test_dc07_v01_positive_real_tokens_and_postgres` fails identically on unmodified baseline `1bb46af`, classified **deterministic pre-existing fixture failure**, not a PR 23 regression. |
| STOP-08 TEST | Rust canonical gate unavailable | **FIRED — BLOCKED-ENV.** `cargo` is not installed on PATH and no Rust toolchain exists in the environment; `./build.sh --rust` cannot execute. This is an environment/harness limitation; no Rust source or semantics were changed. |

No other STOP fired. In particular:

- STOP-00 did not fire: baseline SHA, `git fsck --full`, and migration head
  matched the plan.
- STOP-01 did not fire: no owner/migrator credential was added to
  `PostgresMtmfSpi`, no runtime grant or `SECURITY DEFINER` proxy was added.
- STOP-02 did not fire: the PR 14 verification policy was reused unchanged.
- STOP-03 did not fire: conflicting/revoked/inactive/root subjects fail closed.
- STOP-04 did not fire: `MT047`/`MT048` were unused.
- STOP-05 did not fire: the v008 constraint name and guards matched.
- STOP-06 did not fire: both participants are non-committing functions in one
  caller-owned PostgreSQL transaction.
- STOP-07 did not fire: concurrency and rollback tests passed; no deadlock,
  orphan, partial commit, or duplicate ACTIVE binding was observed.
- STOP-09/10 did not fire: scope remained PR 23.

## What was completed

All code, SQL, migration, unit tests, real-PostgreSQL feature tests, docs, and
security/privilege evidence described in
[PR23_BASELINE_AND_SCOPE_RECONCILIATION.md](PR23_BASELINE_AND_SCOPE_RECONCILIATION.md).
QA, security, integration, and role-verification gates passed.

## Exactly what remains blocked

1. Genuine Keycloak signed-token acceptance for L01–L04. The harness runs and
   genuinely obtains tokens, but the independent attestation baseline for the
   fixture is stale; no alternative baseline or IdP setup was invented.
2. The Rust gate in this environment, unrelated to PR 23 source changes.

## Decision required from the human

**D1 — Live fixture baseline reconciliation.** Confirm whether the PR 14
Keycloak evidence fixture and its committed attestation baseline should be
reconciled (including whether `mtmf-attestation-reader` and
`mtmf-evidence-same-client-b` are approved baseline clients), or provide a
separately approved live fixture/baseline for PR 23 genuine-token acceptance.
Until that decision, PR 23 must not be reported DONE.

## Safe rollback

No uncommitted privileged work remains. The local PostgreSQL container and the
isolated PR 14 Keycloak evidence container are development-only and can be
stopped with their project-scoped tooling; no repository history or protected
seed was modified.
