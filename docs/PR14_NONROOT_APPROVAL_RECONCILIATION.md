# PR 14 — Non-root approval reconciliation and implementation gate

**Status: PROPOSED FOR HUMAN REVIEW — NO IMPLEMENTATION APPROVAL.**
**Branch:** `dev/service-auth`
**Context:** D1 v0.1 selected; Keycloak 26.8.0 development D1 profile conditionally approved; root authentication deferred and fail-closed.

## 1. Blocking conflict: approved PR 12 T1 versus D1

`docs/PR12_INTEGRATION_SECURITY_DECISIONS.md` §2 T1 requires verification of the authenticated Application's authority to act for the user and Tenant. Its consequences additionally state that PR 14 must implement external-issuer validation **and** a standards-based delegation/token-exchange mechanism. The chosen D1 flow validates two independently issued, same-client access tokens; it does **not** prove consent, per-request delegation, or an `act` actor chain.

**Required human decision:** either (A) explicitly amend T1 to permit same-client issuer-bound user context as the narrow v0.1 interpretation of authority (with tenant/application eligibility and residual risks), while retaining distinct-client delegation for a later PR; or (B) keep T1 unchanged and **block D1 production implementation** until a compliant exchange/delegation mechanism is available. Do not silently change PR 12 or infer that observed `azp` equality satisfies delegation.

**Recommendation:** A, provided the product accepts the trusted same-client application as the PEP and the limits of bearer token possession. Explicitly reject cross-client delegation and user impersonation; require separate MTMF domain checks. Human approval must update both the PR 12 T1 register and PR 14 A14-05/A14-07 contract.

## 2. Production issuer profile decision

The only evidence-backed profile is the pinned Keycloak **26.8.0 development fixture**. Before a production profile is approved, identify: exact production issuer URL, deployed Keycloak version and upgrade policy, client registration and grant configuration, audience mapper configuration, signed `azp` behavior, prohibited mappers/exchange capabilities, JWKS URI and transport trust, key rotation strategy, and distinct service/user audiences.

**Proposed non-root validation profile:** RS256 only for the pinned Keycloak profile; exact `iss`; required signed `aud` (distinct service and user audiences), `exp`, `iat`, payload `typ=Bearer`, unique nonempty string `azp`, user `sub`, and approved service-account token-class predicate. `nbf` optional but validated if present. Reject ID/refresh tokens, ambiguous duplicate JSON claims, unsupported token exchange, wrong audience/class, and service/user swaps. Audience checks alone do not prove grant type: establish a fail-closed service-account-versus-human subject predicate using issuer-backed evidence.

**Critical gap:** A signed `azp` identifies the obtaining client under the pinned source behavior, not the caller's possession of the user session or user consent.

## 3. JWT verification and JWKS policy for reviewer approval

- Explicit dependency `pyjwt[crypto]>=2.13,<3` with locked reproducible version.
- Allowed asymmetric algorithm fixed by trusted issuer profile, never derived from JWT header; no `none` or symmetric algorithms for these profiles.
- Require `exp` and `iat`; reject at/after `exp`, with **zero positive expiry leeway**. Prefer zero skew tolerance for all temporal checks in v0.1, avoiding PyJWT's shared-leeway pitfall. Validate `nbf` if present; reject future `iat`.
- Bound raw token size, JSON structure/depth, claim count, and JWKS size; reject duplicate JSON members and duplicate JWKS `kid`. No header-supplied URLs (`jku`, `x5u`, `jwk`) may select trust.
- Fetch keys only from operator-configured HTTPS JWKS endpoint with explicit timeout, response-size limit, no cross-origin redirects, bounded TTL, rate-limited unknown-`kid` refresh, and fail-closed outages/rotation. No indefinitely cached signing keys.
- Reject tokens if the issuer profile cannot distinguish service-account and interactive-user access tokens reliably.

These are **proposals**, not a substitute for acceptance tests.

## 4. Dependency ownership

**Proposed reconciliation:** `mtmf-service` owns the deployed HTTP trust boundary, request credential extraction, issuer/JWKS transport, configuration, and assembly. `mtmf-core` owns framework-neutral immutable verified-token contracts, cryptographic validation rules, Identity/Application mapping and actor composition. No duplicate policy authority, embedded consumer-side auth logic, or direct database reads; PostgreSQL remains accessed through existing SPI/UoW and stored functions.

Reviewer must approve this reading against `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §2 and `ARCHITECTURE.md` before coding.

## 5. Root exclusion

A14-08 is a **scope split**, not root authentication approval. PR 14 ordinary D1 resolution must explicitly reject canonical root Identity/Principal and root-only operations even if signed tokens pass. Root phishing-resistant assurance and external root binding remain a subsequent PR. Existing separately governed recovery is unchanged.

## 6. Minimum outstanding approvals

| Item | Required reviewer action | Current status |
| --- | --- | --- |
| PR12 T1 compatibility | Approve explicit narrow amendment or retain original and block D1 | BLOCKED |
| A14-01/03/04/06/09/10 | Record explicit final approval or amendments | PENDING |
| A14-02 and §7 | Approve issuer-specific service/user class predicates and production configuration | PENDING |
| A14-05/A14-07 and §8 | Approve D1 as satisfying amended T1 within narrow scope | PENDING |
| A14-08 | Scope split already approved; retain fail-closed root exclusion | RESOLVED FOR SCOPE |
| §10 | Approve dependency, JWT/JWKS constraints, core/service ownership | PENDING |
| DC05/DC07 | Execute missing fail-closed and real-domain integration acceptance | NOT EXECUTED |
| AUTH-01–AUTH-36 | Partition root-only tests into deferred PR; preserve non-root gates | PENDING |

## 7. Execution instructions and STOP

1. This document is **decision preparation only**. Do not change production auth, database schema, APIs, or root/recovery behavior.
2. Do not alter PR 12 T1 as an approved decision without explicit human approval.
3. If reviewer approves the T1 amendment, update the normative PR 12 register and PR 14 register together, preserving the limitation that D1 is not RFC 8693 delegation.
4. If production issuer configuration is not supplied, do not invent it or silently promote loopback fixture values to production.
5. Only after the non-root approval register is complete may a separate implementation plan authorize coding; retain integration and privilege gates.

## 8. Post-T1-amendment decision-ready recommendation (2026-10-11)

**PR 12 T1 conflict resolved:** The reviewer approved the narrow D1 amendment, recorded in PR12 and PR14 registers. The first row of §6 is no longer blocked. The implementation STOP remains because the other rows are not all approved.

**Recommended non-root technical disposition for explicit reviewer approval:**

1. **A14-01, A14-03, A14-04, A14-06, A14-09, A14-10:** approve the existing fail-closed normative requirements without broadening runtime privileges. Ordinary external identities are `FEDERATED`, and root is excluded.
2. **A14-02 / §7:** approve the pinned Keycloak 26.8.0 **development** service/user issuer profile only. A service-account token and a human-user token must be distinguishable by issuer-backed claims/configuration, not merely by `typ=Bearer` or a shared audience. Require explicit token-class negative tests. Production issuer is a separately named profile, not inferred from the fixture.
3. **A14-05 / A14-07 / §8:** accept D1 same-client issuer-bound user context as amended T1; reject cross-client pairings and unsupported exchanges. No claim of consent or RFC 8693 actor delegation.
4. **§10:** approve explicit `pyjwt[crypto]>=2.13,<3` with a reproducible lock, fixed RS256 dev allowlist, `exp` leeway zero, mandatory `iat`, optional validated `nbf`, bounded and fail-closed JWKS transport, and the split of service HTTP/trust assembly versus core provider-neutral verification policy.
5. **A14-08:** approved scope split; no root authentication in PR 14, with explicit fail-closed root exclusion and deferred test obligations.

**Do not record these recommendations as approvals until the human reviewer explicitly confirms them.** Even after approval, coding must remain blocked pending an implementation-scope decision, production profile definition if production support is intended, and a testable service/user class predicate.

**Outstanding product configuration choice:** Is the first implementation intended to support only the pinned local development Keycloak profile, or a separately configured production issuer from the outset? A production issuer cannot be safely specified from existing evidence alone.

## 9. G0 decision checklist (2026-10-11)

Evidence: [PR14_G0_NONROOT_EVIDENCE_REPORT.md](PR14_G0_NONROOT_EVIDENCE_REPORT.md).
Gate G0-A found that the candidate service/user class predicate works in the
default fixture but is **mapper-spoofable** (G0-T09), so `typ=Bearer` +
audience is insufficient. The reviewer is asked to choose a disposition.

| # | Decision | Recommended choice | Alternative |
| --- | --- | --- | --- |
| 1 | Service/user class predicate (G0-A) | **Lock + attest the issuer mapper profile and use the `client_id == azp` service predicate** (realm prohibits client-managed mappers and pins the mapper set) | Distinct clients per class, or issuer token introspection |
| 2 | A14-01, A14-03, A14-04, A14-06, A14-09, A14-10 | Approve existing fail-closed contracts as written | Amend with specific constraints |
| 3 | A14-05 / A14-07 / §8 (D1 under amended T1) | Approve constrained D1; reject cross-client, `act`, and consent claims | Revert to requiring RFC 8693 delegation |
| 4 | A14-02 / §7 profiles | Approve the pinned Keycloak 26.8.0 **development** profile only | Require a named production profile first |
| 5 | A14-08 | Confirm scope split; root fail-closed; AUTH-26/27 deferred | Reintroduce root into PR 14 (not recommended) |
| 6 | §10 dependency | `pyjwt[crypto]>=2.13,<3`; RS256 only; `exp` zero leeway; `iat` required; `nbf` optional validated; bounded JWKS | Adjust constraints |
| 7 | §10 ownership | `mtmf-service` transport/composition; `mtmf-core` provider-neutral verification (reconcile PR 12 §2 text) | Keep verification in `mtmf-service` |
| 8 | Implementation scope | Development-first pinned Keycloak profile; production issuer a separate later profile | Production-first (cannot be specified from current evidence) |

**No row is approved.** This checklist prepares the human decision; it does not
record one. Until the reviewer records the decisions above, PR 14 production
implementation remains stopped.


## 10. Post-G0-A consolidated final approval package (2026-10-11)

**Decision preparation, not self-approval.** This section supersedes stale status summaries in §§1–9 only where subsequent recorded human decisions explicitly changed them. The original evidence and negative tests remain intact.

### 10.1 Already approved (do not re-ask)

- PR 12 T1 narrowly amended for constrained same-client D1 (PR 14 §14D). D1 is not consent, actor delegation, or RFC 8693 token exchange.
- Pinned Keycloak 26.8.0 **development-first** scope (§14B/§14E); production issuer approval deferred.
- Root authentication split (§14C), root-only AUTH-26/27 deferred, all ordinary D1 root access fail-closed.
- G0-A option 1: independently trusted mapper baseline and attestation (§14F).
- **Conditional A14-02/§7 development design contract** (§14G): fresh, zero-positive-cache attestation **for every authentication operation**, then signed service token `typ=Bearer`, expected service audience, `client_id == azp`; signed user token `typ=Bearer`, expected user audience, nonempty `azp` and `sub`, **no `client_id`**. Independently verify both JWTs and same-client pairing. Failure to attest, drift, ambiguity or wrong token class rejects. Not yet implemented or accepted.

### 10.2 Remaining approvals requested as one coherent non-root package

| Decision | Proposed approval contract | Status |
| --- | --- | --- |
| A14-01 | Explicit trusted issuer/JWKS, asymmetric signed access tokens, exact `iss`, class-specific `aud`, strict temporal and algorithm validation, fail-closed | **PENDING** |
| A14-03 | Immutable `(issuer,client_id)` credential key maps to exactly one Application; no ambiguous or historical reassignment | **PENDING** |
| A14-04 | Immutable `(issuer,sub)` maps to exactly one ordinary `FEDERATED` Identity; operator-only binding; no JIT/email matching | **PENDING** |
| A14-05 / A14-07 / §8 | Constrained D1 independently verified same-client tokens under amended T1; no cross-client delegation or service-minted assertions | **PENDING final register approval** |
| A14-06 | Active Identity/Principal/ordinary Tenant, explicit memberships, active Application registration and independent subscription eligibility; never an implicit ALLOW | **PENDING** |
| A14-09 | Typed internal authentication interface only; no public route, token issuance, token leakage or account enumeration | **PENDING** |
| A14-10 | Additive migration `0011` only if needed after fresh-main reconciliation; operator-only mutations, narrow reviewed runtime stored-function read grants, real PostgreSQL privilege tests | **PENDING** |
| §10 JWT/JWKS | Locked `pyjwt[crypto]>=2.13,<3`, pinned dev RS256, `exp` zero leeway, required `iat`, validated optional `nbf`, strict duplicate/size/URL/redirect/timeout/TTL/key-rotation checks | **PENDING** |
| §10 ownership | `mtmf-service` owns HTTP credential extraction, issuer/JWKS transport, attestation/configuration and deployment composition; `mtmf-core` owns provider-neutral immutable verified claims, validation policy, Identity/Application resolution and actor-context composition through existing SPI/UoW; no duplicate authority | **PENDING explicit PR12 §2 reconciliation** |

**Ownership reconciliation:** PR 12's HTTP integration §2 describes the end-to-end service-authentication boundary, not a mandatory Python package location for every verification operation. The split above keeps external trust transport/configuration in `mtmf-service` and reusable domain verification/composition in `mtmf-core`. If source text prescribes a conflicting concrete package, amend that source after human approval; do not silently reinterpret it during coding.

### 10.3 Attestation implementation obligations

- Zero **positive** cache lifetime for the development issuer: fresh live Admin REST attestation per authentication operation, before any acceptance; negative cache may fail closed.
- Independent, reviewed baseline; no dynamic trust-on-first-use, no automatic baseline update from Keycloak. A committed baseline alone does not prevent a compromised deployment from replacing both code and manifest; deployment integrity is an explicit assumption.
- Define an atomic operation boundary for checking attestation and both JWTs. Record the remaining time-of-check/time-of-use race, potential Admin REST latency/availability and privileged configuration mutation; never describe the solution as unconditional grant-type proof.
- No production issuer or production attestation TTL is approved. No root authentication.
- G0-T09 remains **FAIL (vulnerability demonstrated)**; R06 is the positive detection control. R12 separate-run evidence must be reconciled against its matrix `NOT EXECUTED` record before claiming matrix PASS.
- DC05 (signed missing `azp`) and DC07 (real PostgreSQL binding) remain **NOT EXECUTED**; both are mandatory later acceptance, as are non-root AUTH-01–25 and AUTH-28–36.

### 10.4 Approval boundary

The reviewer must explicitly approve or amend **all rows in §10.2**, including the §10 ownership reconciliation, before authorizing implementation. A general instruction to prepare this package is not an approval of those rows. After approval, update the normative PR14 decision register and any conflicting PR12 integration text, then issue a separate explicit implementation authorization. Until then, **production authentication code, schema, migration, API and runtime grant changes remain STOPPED**.
