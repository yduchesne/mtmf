# PR 14 — Development-first non-root implementation gate and execution plan

**Status: PLAN ONLY — SECURITY APPROVAL GATE OPEN; PRODUCTION CODE STOP.**
**Target branch:** `dev/service-auth`. **Approved scope:** pinned Keycloak 26.8.0 development issuer, constrained D1, root excluded. **Production issuer:** deferred.
**Planning reference:** `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`.

## Purpose

Provide a deterministic path from PR 14 Phase 0 evidence to a reviewable, testable service/user authentication implementation. This document is **not** permission to begin production coding. Do not conflate approved scope with approved security implementation.

## 0. Mandatory baseline reconciliation

Before any work, fetch fresh `origin/main` and `dev/service-auth`; record exact SHAs and changes. Inspect existing packages, tests, `MtmfSpi`, `UnitOfWork`, `PostgresMtmfSpi`, Identity/Principal/Tenant membership contracts, PR 13 Application registry and subscription service, runtime EXECUTE allowlist, Alembic head, JWT dependencies and test harnesses. Inspect the actual PR 14 plan if present; do not invent file paths or assume stale 0010/75-signature baseline. Classify every capability DONE+VERIFIED, DONE+UNVERIFIED, PARTIAL, NOT STARTED, or BLOCKED. Preserve existing work.

## 1. Gate G0 — complete non-root decisions (documentation/evidence only)

1. **A14-01/03/04/06/09/10:** obtain explicit reviewer approval for each normative contract, including `(issuer,client_id)` → exactly one Application, `(issuer,sub)` → exactly one ordinary `FEDERATED` Identity, protected operator-only binding, and default-deny tenant isolation.
2. **A14-02 / §7:** demonstrate *issuer-backed token-class discrimination*. In the pinned Keycloak fixture, service and user access tokens both carry payload `typ=Bearer`; distinct audiences configured by mappers provide separation but do **not by themselves prove grant type**. Identify a documented/observed, non-spoofable issuer-side predicate distinguishing client-credentials service-account subjects from interactive users; test the adversarial case where a token of the wrong grant is issued with the expected audience. If no reliable predicate can be established, **STOP** and propose an issuer configuration change for review. Do not rely on user-controlled claims or token parsing without signature validation.
3. **A14-05/07 / §8:** explicitly approve constrained D1 under the amended PR 12 T1; no cross-client delegation, `act` chain, service-signed identity assertion or user-consent claim. Development Keycloak `azp` semantics are pinned to source and config; check against protocol-mapper overrides.
4. **§10 dependency:** explicit `pyjwt[crypto]>=2.13,<3`, locked. Fixed profile-approved asymmetric algorithm (RS256 for this fixture), no header-derived algorithm selection, no `none`/HS*; `exp` required and no positive expiry leeway; `iat` required; `nbf` optional but checked when present; reject future `iat`. Prefer zero clock tolerance across all claims for v0.1.
5. **§10 ownership:** reviewer approves `mtmf-service` as HTTP/trust assembly, configuration and bounded JWKS transport owner; `mtmf-core` as provider-neutral immutable validation contracts, cryptographic validation policy, identity/Application resolution and actor composition owner. No duplicate trust authorities.
6. **A14-08:** root scope split already approved; root must fail closed. Document which original AUTH-01–AUTH-36 scenarios are root-only deferred and which remain mandatory.
7. **Development issuer scope:** exact allowlisted local issuer URL, audiences, clients, keys, and fixture digest; no default production trust and no auto-discovery from token claims. No production issuer invented.

**G0 exit:** the decision register lists every required non-root decision with reviewer/date/reference and a precise implementation authorization. Until then **no production authentication code, schema, migration, API, dependency change or root implementation**.

## 2. Implementation sequence — conditional on G0

### Part 1 — immutable contracts

Define immutable, typed service credential, user subject, issuer profile, verified client/user token, authentication failure and actor-context contracts in the existing ownership seams. Do not create a competing authorization engine or allow a caller-provided Identity UUID to authenticate.

### Part 2 — bounded token/JWKS verifier

Use only operator-configured trust anchors. Validate independent signatures, issuer, audience, token class, subject/client identity, allowed algorithm/key type, `exp`, `iat`, and optional `nbf`; reject duplicate JSON keys/ambiguous claims, malformed tokens, wrong class, unknown `kid`, duplicate JWKS `kid`, and unsupported header key URLs. Explicit token and JWKS response bounds, short transport timeout, no unsafe redirects, bounded cache TTL, unknown-kid refresh throttling and fail-closed key-rotation/outage behavior. Never let a library default silently relax expiry or fetch arbitrary URLs.

### Part 3 — additive binding persistence

Only after verifying current migration head, add the next additive migration and versioned PostgreSQL stored functions for immutable service-client/Application and issuer-subject/Identity bindings. All application DB access through existing SPI/UoW/repository seams and stored functions; runtime role has minimum EXECUTE and no direct table access or operator mutation privilege. Enforce semantic uniqueness and fail-closed ambiguity, inactive/terminal states, and tenant isolation. Preserve PR 10 root registry protections.

### Part 4 — verified D1 actor composition

Validate two tokens independently; map service token to exactly one Application, verify issuer-specific same-client user `azp`, map signed user `(issuer,sub)` to one eligible `FEDERATED` Identity, exclude root before actor composition, and apply existing Principal/Tenant memberships and Application–Tenant registration/subscription gates. Do not turn authentication into an ALLOW; the later PDP evaluates Actions. No direct request-body actor override.

### Part 5 — configuration and composition

Use development-only Keycloak fixture as explicit profile; no public HTTP endpoint (later PR), no token minting/exchange, no client SDK or production issuer assumptions. Keep the existing Podman project and loopback isolation; do not mutate ATI, Digr, Darkula or other Podman resources.

### Part 6 — documentation and regression

Update source-of-truth docs only after acceptance; preserve explicit production issuer and root gates.

## 3. Mandatory feature acceptance

- D1-01–D1-10 from PR14 decision register, including missing `azp` DC05 and real PostgreSQL Identity/Tenant/Application/subscription DC07.
- AUTH-01–AUTH-36: classify each as non-root mandatory, deferred root-only, or requiring explicit review; **do not silently omit**.
- Adversarial service/user token-class crossover even when wrong token receives an expected audience.
- Independent valid tokens from different clients; ambiguous `azp`; duplicate claims; forged signature; unknown/duplicate `kid`; key rotation, timeout, redirect, oversize and outage; expired/future-issued token.
- Root user token or mapped root Identity cannot authenticate via D1, regardless of signed claims.
- Inactive Identity, Principal, Tenant, membership, credential, Application registration/subscription all fail closed.
- Real PostgreSQL 18, `mtmf_runtime` privilege checks, real `PostgresMtmfSpi`/UnitOfWork and stored functions; fake SPI unit tests do not substitute.
- Run repository-authoritative QA/security/pre-commit and integration harnesses; record exact commands, environment, results and coverage. Classify any failure as introduced regression, feature defect, baseline failure (reproduced), flaky (demonstrated), or environment/harness failure.

## 4. Explicit non-goals

No production issuer support, root authentication, recovery changes, RFC 8693 actor delegation, cross-client identity propagation, new public endpoints, PR 15 DTOs, PR 17 HTTP transport, token issuance, client SDK, unrelated authorization semantics, or migration edits to existing revisions.

## 5. STOP conditions

STOP on incomplete human security approval; unreliable service/user class predicate; unresolved PR 12 T1 compatibility; root access exposure; issuer profile drift; ambiguous identity/application mapping; direct runtime SQL; missing PostgreSQL privilege proof; arbitrary JWKS discovery; inability to execute required feature acceptance; conflicting fresh-main architecture; or changes outside the explicit PR scope. Report precise blocker and smallest reviewer decision; never guess.

## 6. Completion report contract

Report branch/base/final SHA; exact changed files; each G0 decision and reference; class-predicate evidence; all D1/AUTH tests with PASS/FAIL/NOT EXECUTED; real PostgreSQL and runtime-role proof; security/QA/pre-commit results; residual risks; clean worktree; explicit **development-only** deployment status; production issuer/root gates still closed. Never mark PR DONE based solely on implementation or regression tests.

## 7. Immediate next action

**Do only G0 documentation and issuer evidence** until the human reviewer explicitly approves the remaining non-root decisions and authorizes implementation. This plan is not that approval.

## 8. Post-approval execution amendment (2026-10-11)

**Security design decisions approved; implementation authorization remains separate.** See `PR14_AUTHENTICATION_SECURITY_DECISIONS.md` sections 14G–14H and `PR14_NONROOT_APPROVAL_RECONCILIATION.md` sections 10–11. Earlier G0 approval-pending language is historical. This amendment supersedes it only for architectural approval, not authorization to code.

Before production authentication changes, the agent must reconcile fresh main/branch SHAs, actual Alembic head and runtime EXECUTE grants, and the PR 12 package-ownership clarification. The development profile is Keycloak 26.8.0 only; no production issuer or root trust.

**Implementation order after separate authorization:** (1) typed core/service contracts; (2) independent expected-manifest trust and fresh live attestation on *every* authentication operation, with zero positive cache and fail-closed error handling; (3) bounded independent service/user JWT verification and conditional class checks; (4) additive stored-function-only binding persistence and runtime-role privilege proof; (5) same-client D1 actor composition and independent Tenant/Application/subscription checks; (6) feature, security and integration acceptance. Service owns HTTP/JWKS transport, attestation and assembly; core owns provider-neutral verification policy and domain resolution. No public HTTP routes in PR 14.

**Security constraints:** Attestation success must precede acceptance of either token; previous startup/preflight records cannot authorize a later operation. Retain G0-T09 as a demonstrated claim-only failure and R06 as drift detection. Explicitly document the remaining configuration-change TOCTOU race and privileged issuer administrator threat. Reconcile R12's separately executed clean-recreate evidence with the matrix status before claiming full matrix completion.

**Mandatory gates:** DC05 signed missing-azp and DC07 real PostgreSQL domain binding; non-root AUTH-01–25 and AUTH-28–36; adverse mapper drift and unavailable Admin REST; cross-client and wrong-class token swaps; JWT/JWKS edge cases; root fail-closed; actual mtmf_runtime SQL EXECUTE privileges; QA, security and pre-commit. Report each PASS/FAIL/NOT EXECUTED with command and artifact. Do not infer PASS from unit tests or documentation.

**STOP:** No production authentication implementation, schema/migration, dependency or runtime grant changes until explicit implementation authorization. No production deployment or root authentication under this amendment.

## 9. Human implementation authorization (2026-10-11)

**AUTHORIZED:** The human reviewer explicitly authorized execution of this PR 14 development-only, non-root implementation plan. This supersedes earlier implementation STOP language only for the bounded development implementation described here. The coding agent must follow the sequence, security constraints, mandatory tests and STOP conditions in section 8, with fresh-main reconciliation before edits.

**Excluded:** production issuer configuration/deployment, root authentication and recovery, RFC 8693 delegation, cross-client propagation, public HTTP routes, and unrelated feature work. No implicit authorization to relax security checks, runtime database privileges, or acceptance gates. If a blocking contradiction or unmet security prerequisite is discovered, STOP and report it for human review. Implementation authorization does not imply implementation acceptance or permission to merge.

## 10. Implementation status — development-only, non-root (2026-10-11)

**Delivered (not DONE; production issuer and root remain deferred and blocked).**

- `mtmf-core` provider-neutral contracts: immutable `IssuerProfile`,
  `VerifiedAccessToken` (service/user class properties), `ServiceCredentialKey`,
  `ExternalSubjectKey`, `VerifiedActorContext`, typed `AuthenticationError`
  categories; `TokenVerifier`/`ConfigurationAttestor` ports; and
  `AuthenticatedActorContextService` (attest → verify both tokens → class and
  same-client checks → bindings → active FEDERATED Identity/Principal/ordinary
  ACTIVE Tenant → memberships → ACTIVE registration → PR 13 subscription
  eligibility; canonical root always fails closed).
- `mtmf-service` transport: fixed-RS256 verifier with bounded JWKS
  retrieval/cache, duplicate-claim and duplicate-`kid` rejection, zero positive
  expiry leeway, required `exp`/`iat`, validated optional `nbf`, no
  header-selected URL/algorithm; a fresh, zero-positive-cache canonical-manifest
  attestation against the reviewed `dev/keycloak/expected-config-manifest.json`;
  and a development composition seam. No HTTP route.
- Additive `0011` persistence: immutable `service_credential_application` and
  `external_subject_identity` tables with partial-unique ACTIVE rows and
  immutability/terminal guards, operator-only mutation functions, two narrowly
  reviewed runtime `SECURITY DEFINER` reads, updated 77-signature runtime
  allowlist, and real-PostgreSQL binding/privilege tests.
- Repository/SPI additions (`create_service_credential_application_repository`,
  `create_external_subject_binding_repository`, `create_root_registry_repository`)
  with in-memory and PostgreSQL implementations.

**Acceptance evidence.**

| Gate | Result |
| --- | --- |
| `tests/unit/authentication` (24 tests) | PASS |
| `./build.sh --integration` | PASS — 552 passed plus 7 new binding tests |
| migration `0011` + runtime privilege verifier | PASS on real PostgreSQL |
| `./build.sh --qa` | PASS — 1381 unit tests, 86.61% coverage |
| `./build.sh --sec` | PASS — Bandit 0 medium/high; Semgrep 0 findings |
| `pre-commit run --all-files` | PASS |

**Explicitly not executed / deferred (must not be reported as PASS).**

- DC05 signed missing `azp`: still NOT EXECUTED (harness predicate only).
- DC07 full real-token + real-PostgreSQL actor vertical slice: NOT EXECUTED;
  bindings and privileges are validated on real PostgreSQL, and actor
  composition is unit-tested with the in-memory SPI, but no end-to-end run
  issues live Keycloak tokens through the real `PostgresMtmfSpi`.
- AUTH-01–25 and AUTH-28–36 are covered in part by unit/integration tests; a
  complete named acceptance mapping is not yet recorded.
- G0/R12 matrix `NOT EXECUTED` entry remains as such; the separate clean
  recreate was verified but not merged into the matrix artifact.

**Residual risks.** Attestation is per-operation and fail-closed, but the
configuration-change TOCTOU window and a privileged issuer administrator remain
unmitigated; the class predicate is configuration-backed, not a JWT guarantee;
bearer replay and separate-session acquisition remain; the JWKS cache is bounded
but not instant on rotation.

**Still closed.** Production issuer trust, root authentication/recovery,
RFC 8693 actor delegation, cross-client propagation, and public HTTP routes.
PR 14 must not be marked DONE.
