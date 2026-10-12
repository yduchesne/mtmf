# PR 14 — Final Security Review and Conditional Sign-off

**Review date:** 2026-10-11  
**Branch reviewed:** `dev/service-auth`; Amendment #4 reported commit `6738d26283c07d863f9563e0a08975d5dd250adc`.  
**Decision:** **CONDITIONAL SECURITY ACCEPTANCE** for the development-only, non-root D1 authentication scope. **NO MERGE AUTHORIZATION** is implied by this document. Review based on committed acceptance evidence and source inspection; the reviewer did not independently execute the test suite.

## Evidence considered

- `docs/PR14_AMENDMENT4_ACCEPTANCE_REPORT.md` and `docs/PR14_AMENDMENT4_ACCEPTANCE_MATRIX.md`: report 22 real Keycloak/real PostgreSQL live tests passing without live skips; clean pinned-issuer recreate and full manifest hash match; 61 auth unit, 11 binding integration, 556 default integration, 1418 QA at 88.28% coverage, zero security findings, pre-commit, migration 0011 and 77-signature/runtime-privilege gate PASS. These are **agent-reported executed results**, not independently reproduced in this review.
- `tests/unit/authentication/test_service_verifier.py::test_wrong_issuer_is_rejected` explicitly asserts `UNTRUSTED_ISSUER`; `::test_jwks_transport_outage_fails_closed` uses failing transport and asserts `INFRASTRUCTURE`.
- `tests/unit/authentication/test_actor_context.py::test_root_identity_is_rejected` seeds the root registry with root identity/principal/tenant and asserts `ROOT_FORBIDDEN`; the live `test_dc07_root_tenant_scope_rejected` asserts rejection of root Tenant scope. These are **different layers** and not interchangeable evidence.
- §14J security architecture: shared `aud` is recipient restriction, not grant-class proof; class predicate must be signed and independently attested on each operation.

## Explicit reviewer dispositions

| Item | Disposition | Rationale / required follow-up |
| --- | --- | --- |
| AUTH-05 / D1-09 caller UUID/assertion substitution | **ACCEPT DEFERRED TO PR 17** | PR 14 exposes no public HTTP route; PR 17 must test that caller-controlled actor UUIDs/assertions never authenticate or replace independently verified actor context. Do not mark PR 14 test PASS. |
| AUTH-06 live wrong-issuer token | **ACCEPT UNIT-LEVEL EVIDENCE** | The isolated test-key verifier exercises exact wrong-issuer rejection; no second approved live issuer was available. Do not claim live PASS. |
| AUTH-13 JWKS outage | **ACCEPT UNIT-LEVEL EVIDENCE** | Dedicated failing JWKS transport test asserts typed `INFRASTRUCTURE`. Live JWKS fault injection was not executed; keep layer explicit. |
| AUTH-25 / AUTH-26 / AUTH-27 root | **ACCEPT NON-ROOT FAIL-CLOSED EVIDENCE ONLY** | Real root-Tenant rejection and unit root-registry identity rejection are complementary. Root authentication and mutation remain DEFERRED ROOT; neither is approved by this review. |
| DC05-ISSUER | **ACKNOWLEDGE NOT EXECUTED** | Pinned Keycloak unconditionally emits typed `azp`; local-key signed negative proves shipped verifier behavior but is not issuer evidence. |
| V01–V16 historical numbering | **ACCEPT DESCRIPTIVE BEHAVIORAL COVERAGE WITH TRACEABILITY EXCEPTION** | Prior plan definitions conflict. Do not claim a one-to-one V01–V16 mapping or rewrite historical case statuses; carry the discrepancy as an explicit documentation limitation. |
| Residual issuer trust | **ACKNOWLEDGE** | Privileged issuer-admin drift, per-operation attestation TOCTOU, bearer replay/separate-session acquisition, bounded JWKS cache and configuration-backed class semantics remain. |

## Conditions before any merge

1. Confirm PR 14's target is **development-only non-root D1**; no implication of production IdP readiness, root login/recovery, HTTP transport, token exchange or cross-client delegation.
2. Confirm current remote branch HEAD and target main; review actual PR diff, CI status and unresolved review comments. If branch changed after `6738d262`, rerun impacted acceptance and revisit sign-off.
3. Human maintainer must explicitly accept the above deferrals, traceability exception and residual risks in the PR review. **No agent self-approval.**
4. Confirm secrets are absent and no unexpected migrations, grants, runtime table access or foreign Podman resource modifications were introduced.
5. Preserve the test suite and live acceptance instructions for future CI/manual reruns. PR 17 must include AUTH-05/D1-09 as mandatory HTTP boundary acceptance.

**Review outcome:** Security evidence is sufficient to **recommend merge after the conditions above are checked and the human maintainer explicitly authorizes it**. This document is not that authorization. Do not merge automatically.
