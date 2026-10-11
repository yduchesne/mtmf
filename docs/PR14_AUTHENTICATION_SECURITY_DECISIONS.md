# PR 14 — Service Authentication and Verified Acting-User Security Decisions

> **STATUS: PROPOSED — NOT APPROVED.**
>
> This register records the PR 14 security decisions proposed in the
> detailed implementation plan. It is **not** an approval. Per the PR 14
> execution contract and `AGENTS.md`, no security-sensitive
> implementation (token verifier, trust contracts, `0011` persistence,
> actor-context composition) may begin until a human reviewer records
> explicit approval of `A14-01`–`A14-10` and of the issuer claim profiles
> in §5. Phase 0 inspection and this proposition are permitted while
> approval is pending.
>
> Do not infer approval from the existence of this document, the
> implementation plan, `PR12_INTEGRATION_SECURITY_DECISIONS.md`,
> `PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md`, an implementation request,
> or a coding-agent report. Where a proposed value below is unresolved,
> treat it as unresolved and STOP rather than assuming.

Owner documentation: [SECURITY_MODEL.md](SECURITY_MODEL.md),
[DOMAIN_MODEL.md](DOMAIN_MODEL.md), [AUTHORIZATION.md](AUTHORIZATION.md),
[ARCHITECTURE.md](ARCHITECTURE.md), [DATABASE.md](DATABASE.md).
Companion contracts: [PR12_INTEGRATION_SECURITY_DECISIONS.md](PR12_INTEGRATION_SECURITY_DECISIONS.md)
(T1/T6), [HTTP_INTEGRATION_BATCH_AUTHORIZATION.md](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
(§2, §3, §3A, §3B, §12A), [PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md](PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md).

## 1. Purpose and boundary

PR 12 approved an HTTP-only MTMF PDP integration and decisions `T1`/`T6`.
PR 13 added the Application registry, Application–Tenant registration,
Tenant subscription state, and the read-only
`ApplicationTenantEligibilityService`. Neither authenticates a remote
caller nor proves who the acting human is. PR 14 closes the trusted
identity seam consumed by PR 15 DTOs and PR 17 HTTP transport:

```text
External authorization server (OIDC/OAuth2; local development issuer: Keycloak)
   ├── signed client_credentials ACCESS TOKEN ──> service-token verifier
   │       issuer + audience + signature + time + token class + credential identity
   │       → one persisted credential-to-Application mapping
   │       → authenticated Application (not Tenant, Principal or end user)
   └── signed USER ACCESS TOKEN (or approved exchanged user token)
           issuer + audience + signature + time + user token class + subject
           → protected external-subject-to-MTMF-Identity binding
           → existing Identity/Principal/Tenant memberships and lifecycle
```

**No authorization `ALLOW` is returned by PR 14.** A verification failure
is a typed authentication/trust failure, not a policy `DENY`, and must
never produce a reusable decision snapshot.

## 2. Phase 0 baseline recorded before this register

Observed on the working tree at the planning time of this register:

- Branch `dev/service-auth` at `HEAD == origin/main ==
  1924143ea504a9c291d695d154e9537cdb61969e`, clean working tree, no
  delta against `main`.
- Alembic migration head: `0010_pr13_application_registry`.
- Reviewed runtime `EXECUTE` allowlist through `0010`: exactly **75**
  signatures — 6 membership-removal entry points, 44 repository
  functions (v004), 8 typed Role-assignment functions (v005), 9
  TenantManagementGroup/root-registry reads (v009), and 8
  Application-registry reads (v010). Source:
  `mtmf_core.persistence.postgres.roles._*_FUNCTION_ARGUMENTS` /
  `expected_runtime_signatures()`.
- `mtmf-api`, `mtmf-client`, and `mtmf-service` are empty `__version__`
  stubs. There is no FastAPI app, no HTTP route, no public DTO, and no
  existing authentication, token, JWKS, or external-subject binding code.
- Installed/locked crypto dependencies: `cryptography==50.0.1` and
  `pyjwt==2.13.0` (both currently transitive, not declared by any MTMF
  package). `PyJWT` exposes `PyJWKClient`/`PyJWKSet` and asymmetric
  algorithms and uses stdlib HTTP for JWKS retrieval.
- Existing reuse seams (do not duplicate): one provider-neutral
  `MtmfSpi`, `UnitOfWork`, typed repositories, `PostgresMtmfSpi`
  (runtime-only), `ApplicationTenantEligibilityService`, versioned
  `sql/v0NN` + additive Alembic migrations, `Identity`/`Principal`/
  `Tenant`/typed memberships, `IdentityOrigin` (`LOCAL`/`FEDERATED`),
  `TenantLifecycle`, `SecurityScope`, and the `root_registry` protected
  canonical root binding.
- The root `LOCAL` Identity vs external OIDC binding semantic gate is
  **unresolved** in the authoritative docs; see `A14-08`.

## 3. Approval gate

Implementation may not begin until a reviewer approves each of `A14-01`–`A14-10`
in §4 and the issuer claim profiles in §5, or an explicitly narrower scope.
The approval log in §9 must be completed with reviewer identity, date, and
reference. If any proposed decision is rejected or changed, update this
register, re-obtain approval, and only then implement.

## 4. Proposed decisions

Each decision below is **PROPOSED**. Approval fields are intentionally
blank until a human reviewer acts.

### A14-01 — Token trust model (resource server)

**Proposed contract.** MTMF is an OAuth 2.0 **resource server**. Accept
only asymmetric, signed JWT **access tokens** from explicitly allowlisted
`(issuer, audience)` pairs. Reject `alg=none`, symmetric shared-secret
JWTs (HS\*), unconfigured algorithms/key types, ID tokens, refresh
tokens, and discovery of arbitrary issuer/JWKS URLs. Fixed accepted
algorithms per profile (asymmetric only: `RS256`, `ES256`, `PS256`, or a
reviewer-approved subset). No token is accepted solely because it parses.

- Reason: bounded trust surface; PR 12 `T1`; PR 14 security invariants.
- Owner: PR 14.
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-02 — Distinct service and user validation profiles

**Proposed contract.** Two distinct, immutable trust profiles with
**different expected audiences** and explicit token-class predicates.
The service profile requires configured client-credentials evidence
(`azp`/`client_id` or an approved issuer-specific equivalent). The user
profile requires `sub` and approved user-token predicates. Ambiguous,
missing, or contradictory class evidence is rejected. A service `sub`
must never be consumed as a human subject.

- Reason: prevent token confusion / cross-token swap.
- Owner: PR 14.
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-03 — Service credential → exactly one Application

**Proposed contract.** Persist service credential identity as the
immutable semantic key `(issuer, client_id)` (or a specifically approved
issuer credential identifier) mapped to exactly one Application UUID.
Multiple credentials may map to one Application; one credential may
never map to two Applications, in place or historically. Deactivation
blocks subsequent verification. The credential identifier is never the
Application UUID and is never inferred from a mutable name or Tenant.

- Reason: PR 12 `T6`; no spoofing.
- Owner: PR 14 (state/persistence), PR 13 registry (Application).
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-04 — External subject → exactly one MTMF Identity

**Proposed contract.** Persist user binding as `(issuer, sub) → exactly
one MTMF Identity`. No email/name matching, no implicit/JIT
provisioning, no self-service mapping. Binding mutations are
operator/installation-only and never granted to `mtmf_runtime`.
Identity-origin compatibility is explicitly verified. Zero, multiple,
inactive, or inconsistent mappings fail closed.

- Reason: PR 12 `T1`; account-takeover resistance.
- Owner: PR 14.
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-05 — Acting-user propagation mode (SCOPE GATE)

**Proposed contract.** For v0.1 the mandatory supported propagation path
is a **signed external-issuer end-user access token**. A standards-based
token-exchange (RFC 8693) integration contract may be documented, but a
full token-exchange HTTP client is **not** silently added, and no
unverified exchanged assertion is ever accepted.

- Open question requiring explicit reviewer disposition: PR 12 `T1`
  approved "signed end-user access tokens **or** standards-based token
  exchange". If the reviewer interprets `T1` as requiring **both modes
  to be executable in PR 14**, implementation must STOP and obtain an
  explicit scope approval before continuing.
- Owner: PR 14.
- Status: **PROPOSED / SCOPE PARTIALLY UNRESOLVED**.
- Reviewer / date / reference: _pending_.

### A14-06 — Verified actor eligibility

**Proposed contract.** The acting user must be an **ACTIVE** Identity
with an eligible/ACTIVE Principal and an explicit membership in the
selected **ACTIVE ordinary** Tenant, using existing authoritative
membership semantics (explicit `PrincipalTenantMembership` and
`IdentityTenantMembership`). The Application must be **ACTIVE** and
separately **ACTIVE-registered** for that Tenant. Tenant subscription is
checked by the existing PR 13 `ApplicationTenantEligibilityService` and
is **not** used as authentication. The SYSTEM/root Tenant and any
non-ordinary Tenant scope are rejected as consumer context even if
fabricated registration/subscription rows exist.

- Reason: verified context / Tenant isolation; PR 12 `T5` precedence.
- Owner: PR 14 (actor boundary), PR 13 (eligibility).
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-07 — Delegation / confused-deputy prevention

**Proposed contract.** The acting-user token alone does not grant the
Application delegation rights. Require an approved delegation binding:
the user token's authorized party (`azp`) or an exchanged-token actor
(`act`) must match the verified calling OAuth client, under a documented
issuer-specific claim profile. Two independently valid tokens with no
verifiable relationship must fail. The reviewer must approve either
(a) a deployment convention that the same OAuth client is used for the
service and user flows, or (b) an explicit configured delegation
relation. If the issuer cannot provide a verifiable binding, STOP.

- Reason: confused-deputy prevention; PR 12 `T1`/`T6`.
- Owner: PR 14.
- Status: **PROPOSED / CLAIM CONTRACT UNRESOLVED**.
- Reviewer / date / reference: _pending_.

### A14-08 — Protected root binding (`LOCAL` origin gate)

**Proposed contract (option A, recommended).** The canonical root
Identity remains origin `LOCAL`. Normal interactive root authentication
uses a dedicated privileged external OIDC account with phishing-resistant
MFA, and a **separate, protected, installation-only** binding row maps
the verified `(issuer, sub)` to the designated root Identity. The mapping
model does not reclassify the root Identity as `FEDERATED` and does not
weaken PR 10 invariants. It is unique, auditable, immutable except under
a separately approved protected operator procedure, and never runtime
editable.

**Alternate disposition (option B).** Split root authentication/binding
out of PR 14; PR 14 is reported `BLOCKED` on root and does not claim
completion. This register must record which option the reviewer approves.

- Also required: the approval of the root MFA/assurance claim contract
  (for example configured `acr`/`amf` values) and the exact canonical
  root structural invariant checks.
- Reason: PR 10 root design gate; `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`
  §12A.
- Owner: PR 14.
- Status: **PROPOSED / ROOT SEMANTICS UNRESOLVED**.
- Reviewer / date / reference: _pending_.

### A14-09 — No public trust route; typed internal API

**Proposed contract.** PR 14 exposes a typed **internal** verifier and
actor-context composition interface consumed by PR 17. It adds no public
HTTP endpoint, public DTO, route, or token issuance, and returns only
sanitized error categories. Raw tokens, client secrets, and token bytes
never appear in returned objects, `repr`, exceptions, or logs.

- Reason: PR 15/17 boundary.
- Owner: PR 14.
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

### A14-10 — Privilege posture for mapping persistence

**Proposed contract.** Credential/binding administration is
installation/operator-only through owner-owned `SECURITY INVOKER` stored
functions with `PUBLIC EXECUTE` revoked. `mtmf_runtime` receives only
narrowly scoped reviewed `SECURITY DEFINER` **read** functions (fixed
empty `search_path`, schema-qualified identifiers). No runtime table
`SELECT`/DML, no mapping mutation `EXECUTE`, no elevated membership, and
no unreviewed `SECURITY DEFINER` function. Additive migration `0011`
only; never edit `0001`–`0010` or `sql/v001`–`v010`.

- Reason: preserve the PR 10/13 privilege model.
- Owner: PR 14.
- Status: **PROPOSED**.
- Reviewer / date / reference: _pending_.

## 5. Proposed issuer claim profiles (require approval)

These profiles are **proposed** and must be confirmed against current
official issuer/JWT-library contracts before implementation. Local
Keycloak is a development **profile**, not the mandatory production
provider. Do not invent a universal `grant_type` JWT claim; token-class
evidence is issuer-specific.

### 5.1 Common checks (all profiles)

| Check | Proposed contract |
| --- | --- |
| `iss` | Exact string match against one configured canonical issuer; no path/case/alias normalization. |
| `aud` | Must contain the profile's configured expected audience. |
| `exp` | Required; token not accepted at/after `exp` (bounded skew). |
| `nbf` / `iat` | Validated with configured bounded skew; future values outside skew rejected. Missing `iat`/`nbf` handling per approved profile. |
| `alg` | Fixed asymmetric allowlist; `none`/HS\* rejected; key type must match algorithm. |
| `kid` | Selects only among trusted issuer keys; never a network URL. `jku`/`x5u` never fetched. |
| `typ` / token class | Profile-specific predicate; reject ID tokens and refresh tokens. |
| Size | Bounded raw-JWT bytes and bounded JSON nesting/claim count before unbounded parsing. |
| JWKS | Only the configured `jwks_uri`; bounded size, cache TTL, timeout, no redirects; unknown `kid` refresh throttled; stale/failed refresh cannot authorize. |

### 5.2 Service profile (client_credentials)

| Claim | Proposed requirement |
| --- | --- |
| `aud` | Configured **service** audience. |
| Credential identity | `azp` (or approved `client_id` equivalent) — maps to one Application. |
| Class predicate | Must prove a client-credentials access token; must NOT be accepted as a human subject. |
| `sub` | Not treated as a human Identity. |

### 5.3 User profile

| Claim | Proposed requirement |
| --- | --- |
| `aud` | Configured **user** audience (distinct from service). |
| `sub` | Required; maps to exactly one Identity binding. |
| Delegation | `azp` or `act` bind to the verified calling OAuth client (A14-07). |
| Class predicate | Must prove a user access token; not an ID token or refresh token. |

### 5.4 Root profile (only if A14-08 option A is approved)

| Claim | Proposed requirement |
| --- | --- |
| Account | Dedicated privileged external account; not an ordinary member. |
| Assurance | Configured MFA/assurance claim (`acr`/`amr` or approved equivalent) present and sufficient. |
| Binding | `(issuer, sub)` resolves to the one protected root binding. |
| Isolation | Root token is never accepted as an ordinary Application/SYSTEM-Tenant consumer authorization. |

## 6. Proposed dependency and module ownership (require approval)

- **JWT library (proposed):** `pyjwt[crypto]` pinned to the already-locked
  `2.13.x`, using explicit asymmetric algorithm allowlists and a
  controlled JWKS client (`PyJWKClient` with bounded cache lifespan,
  timeout, and no untrusted URL following) or a reviewed equivalent.
  `python-jose` is not proposed (maintenance posture). Final library and
  version require reviewer approval and lockfile evidence.
- **Value types / ports / orchestration (proposed):**
  `mtmf_core.application` — immutable verified value types,
  `ExternalTokenVerifier` / mapping resolver protocols, and
  `AuthenticatedActorContextService` (no JWT dependency).
- **Verifier adapter + auth configuration (proposed):**
  `mtmf-service` — PyJWT-based adapter, trusted issuer/audience/JWKS
  configuration, strict startup validation, secret redaction. This
  matches the PR 12 ownership matrix ("`mtmf-service` owns token/user
  verification") and avoids adding a JWT dependency to core.
- The reviewer must confirm this split; the implementation plan leaves
  the exact package boundary to the coding agent.

## 7. Unresolved items and mandatory STOP conditions

The following must be resolved by the reviewer or STOP must be reported:

1. Approval of `A14-01`–`A14-10` and the §5 claim profiles.
2. `A14-05`: whether PR 14 must implement both signed-token and
   token-exchange executable modes.
3. `A14-07`: the approved delegation claim contract and whether the same
   OAuth client may be used for service and user flows.
4. `A14-08`: root model option A vs option B, plus the root assurance
   claim contract and `LOCAL`-origin reconciliation.
5. Exact issuer token-class predicates and supported audiences for the
   chosen issuer (Keycloak development profile), confirmed against
   current issuer/JWT-library contracts.
6. JWT library and version choice (§6).
7. Package ownership split (§6).

Any STOP from the implementation plan §10 applies unchanged.

## 8. Explicit non-goals (PR 14 boundary)

No public HTTP endpoint, public batch DTO, token issuance, token
exchange server, client-side token acquisition/renewal, root recovery
CLI, refresh-token handling, or privilege expansion. These belong to
PR 15–20 and the separate recovery PR.

## 9. Approval log

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| A14-01 | PROPOSED | — | — | — |
| A14-02 | PROPOSED | — | — | — |
| A14-03 | PROPOSED | — | — | — |
| A14-04 | PROPOSED | — | — | — |
| A14-05 | PROPOSED / SCOPE UNRESOLVED | — | — | — |
| A14-06 | PROPOSED | — | — | — |
| A14-07 | PROPOSED / CLAIM CONTRACT UNRESOLVED | — | — | — |
| A14-08 | PROPOSED / ROOT SEMANTICS UNRESOLVED | — | — | — |
| A14-09 | PROPOSED | — | — | — |
| A14-10 | PROPOSED | — | — | — |
| §5 claim profiles | PROPOSED | — | — | — |
| §6 library/ownership | PROPOSED | — | — | — |

## 10. Post-approval implementation outline (not started)

Only after §9 is approved: immutable trust contracts (Part 1); trusted
token verifier with bounded JWKS (Part 2); additive `0011` mapping
persistence, stored functions, and restricted runtime reads (Part 3);
verified actor composition reusing PR 13 (Part 4); configuration and
composition seam (Part 5); documentation and final gates (Part 6). The
mandatory deterministic acceptance matrix `AUTH-01`–`AUTH-36` and the
real-PostgreSQL privilege gates in the implementation plan apply.
