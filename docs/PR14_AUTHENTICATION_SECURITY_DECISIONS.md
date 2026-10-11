# PR 14 — Service Authentication and Verified Acting-User Security Decisions

> **STATUS: PROPOSED — PENDING HUMAN REVIEW. NOT APPROVED.**
>
> This register records the PR 14 security decisions proposed in the
> detailed implementation plan and the Phase 0 review. It is **not** an
> approval. Per the PR 14 execution contract and `AGENTS.md`, no
> security-sensitive implementation (token verifier, trust contracts,
> `0011` persistence, actor-context composition) may begin until a human
> reviewer records explicit approval of `A14-01`–`A14-10`, the issuer
> claim profiles in §5, the delegation contract in §6, the root model in
> §7, and the dependency/ownership split in §8 — or an explicitly narrower
> scope.
>
> Do not infer approval from the existence of this document, the
> implementation plan, `PR12_INTEGRATION_SECURITY_DECISIONS.md`,
> `PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md`, an implementation request,
> a coding-agent report, or successful documentation checks. Every
> unresolved value is marked unresolved and must STOP rather than be
> assumed. Review recommendations in §9 are **recommendations only**, not
> approvals.

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

**Explicit non-goals.** No public HTTP endpoint, public batch DTO, token
issuance, token-exchange server, client-side token acquisition/renewal,
root recovery CLI, refresh-token handling, or privilege expansion. Those
belong to PR 15–20 and a separate recovery PR.

## 2. Phase 0 baseline recorded before this register

Observed on the working tree when this register was drafted:

- Branch `dev/service-auth` at `HEAD == origin/main ==
  1924143ea504a9c291d695d154e9537cdb61969e`, clean, no delta against
  `main`.
- Alembic migration head: `0010_pr13_application_registry`.
- Reviewed runtime `EXECUTE` allowlist through `0010`: exactly **75**
  signatures — 6 membership-removal entry points, 44 repository
  functions (v004), 8 typed Role-assignment functions (v005), 9
  TenantManagementGroup/root-registry reads (v009), and 8
  Application-registry reads (v010). Source:
  `mtmf_core.persistence.postgres.roles._*_FUNCTION_ARGUMENTS` /
  `expected_runtime_signatures()`.
- `mtmf-api`, `mtmf-client`, and `mtmf-service` are empty `__version__`
  stubs. There is no FastAPI app, HTTP route, public DTO, or existing
  authentication, token, JWKS, or external-subject binding code.
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
  **unresolved** in the authoritative docs; see `A14-08` and §7.

## 3. Approval gate and conventions

Implementation may not begin until a reviewer approves each of
`A14-01`–`A14-10` in §4 and the profiles/contracts in §5–§8, or an
explicitly narrower scope. The approval log in §11 must be completed with
reviewer identity, date, and reference.

Status vocabulary:

- **PROPOSED** — the stated contract; pending review.
- **RECOMMENDED FOR APPROVAL** — the Phase 0 recommendation; still not
  approved.
- **UNRESOLVED** — a required value not yet settled; STOP if it blocks
  implementation.

## 4. Proposed decisions

### A14-01 — Token trust model (resource server)

**Normative requirement (proposed).**

1. MTMF acts only as an OAuth 2.0 **resource server**. It validates
   access tokens; it does not issue them.
2. Accept only asymmetric, signed JWT **access tokens** from explicitly
   allowlisted `(issuer, audience)` pairs.
3. Reject: `alg=none`; symmetric shared-secret JWTs (`HS256`/`HS384`/
   `HS512`); any algorithm or key type not in the profile's fixed
   allowlist; ID tokens (`token_use`/`typ` indicating ID); refresh
   tokens; and opaque tokens with no verifiable signature.
4. Never perform implicit discovery of an arbitrary issuer, `jwks_uri`,
   `jku`, or `x5u`. Only configured trust anchors are used.
5. A token that merely parses is not accepted; signature, issuer,
   audience, token class, and time must all verify.

**Rationale.** Bounded trust surface; PR 12 `T1`; PR 14 security
invariants 1, 5, 6.

**Alternatives considered.** Symmetric HMAC (rejected: shared secret
between issuer and MTMF broadens trust and enables key confusion);
opaque introspection (rejected for v0.1: adds a live network dependency
and an `introspection_endpoint`, and is not required by T1); OIDC
discovery (rejected: unbounded trust surface).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-02 — Distinct service and user validation profiles

**Normative requirement (proposed).**

1. Two distinct, immutable trust profiles exist: **service** and
   **end-user**.
2. They MUST have **different expected audiences** (no shared audience
   alias).
3. Each profile defines explicit, non-empty token-class predicates.
4. Service profile requires configured client-credentials evidence
   (`azp`/`client_id` or an approved issuer-specific equivalent) and
   MUST NOT accept a human subject.
5. User profile requires `sub` and approved user-token predicates.
6. Missing, ambiguous, or contradictory class evidence is rejected.
7. A service token is never accepted where a user token is required,
   and vice versa.

**Rationale.** Token-confusion / cross-token-swap prevention; PR 14
invariants 1, 5.

**Alternatives considered.** A single profile with a `token_use` switch
(rejected: one predicate bug collapses both classes); audience-only
separation (insufficient alone; retained as a necessary condition, not
sufficient).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-03 — Service credential → exactly one Application

**Normative requirement (proposed).**

1. The persisted service-credential semantic key is the immutable tuple
   `(issuer, client_id)` (or a specifically approved issuer credential
   identifier).
2. Each current credential maps to exactly one Application UUID.
3. Multiple active credentials MAY map to one Application.
4. One credential MUST NOT map to two Applications — not in place and
   not historically.
5. Deactivation/revocation blocks subsequent verification; terminal
   rows are retained as history and must not block a *new distinct*
   credential.
6. The credential identifier is never the Application UUID and is never
   inferred from a mutable name or Tenant.
7. Duplicate/ambiguous active rows fail closed as an integrity failure;
   never select an arbitrary `LIMIT 1`.

**Rationale.** PR 12 `T6`; no spoofing; PR 14 invariants 2, 4.

**Alternatives considered.** Mutable name/keyed mapping (rejected);
credential-as-Application-ID (rejected); many-to-many (rejected: violates
T6).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-04 — External subject → exactly one MTMF Identity

**Normative requirement (proposed).**

1. User binding semantic key is the immutable tuple `(issuer, sub)`.
2. Each current binding maps to exactly one MTMF Identity.
3. No email/name/`preferred_username` matching; no implicit or JIT
   Identity creation; no self-service mapping.
4. Binding mutations are operator/installation-only and never granted
   to `mtmf_runtime`.
5. Identity-origin compatibility is explicitly verified (see §7 for
   root; ordinary users are expected `FEDERATED`, and a reviewer must
   confirm the exact rule for each issuer).
6. Zero, multiple, inactive, inconsistent, or cross-Tenant mappings
   fail closed.
7. One `(issuer, sub)` never maps to two Identities, and one Identity
   never claims two current `(issuer, sub)` bindings, unless the
   reviewer explicitly approves a multiple-binding model.

**Rationale.** PR 12 `T1`; account-takeover resistance.

**Alternatives considered.** Email matching (rejected:
reassignment/ takeover); JIT provisioning (rejected: unmanaged
principals); runtime self-service linking (rejected).

**Recommendation.** Adopt as written, with the ordinary-user origin rule
recorded at approval. Status: **PROPOSED**. Approval: reviewer
`_pending_`, date `_pending_`, reference `_pending_`.

### A14-05 — Acting-user propagation mode (SCOPE GATE)

**Normative requirement (proposed).**

1. The mandatory supported v0.1 path is a **signed, externally issued
   end-user access token** verified per §5.3.
2. RFC 8693 token exchange is **deferred** unless required to establish
   verifiable delegation (see A14-07 / §6).
3. If token exchange is implemented, the exchanged access token is
   validated exactly like any other user token, including actor/delegation
   chain; the exchange request/response is never trusted unverified, and
   no ad-hoc assertion format is invented.
4. A full token-exchange HTTP client is not added silently.

**Rationale.** Narrow implementation; PR 12 `T1`; plan §5.2.

**Alternatives considered.** (a) Signed tokens only (recommended).
(b) Signed tokens plus executable RFC 8693 exchange in PR 14 (larger
scope; requires explicit approval). (c) Exchange-only (rejected: depends
on an exchange endpoint that may not exist).

**Recommendation (not an approval).** Signed externally issued end-user
access tokens are the mandatory v0.1 path; token exchange is deferred
unless required to establish verifiable delegation.

**Open scope question.** PR 12 `T1` approved "signed end-user access
tokens **or** standards-based token exchange". If the reviewer interprets
`T1` as requiring **both modes to be executable in PR 14**, implementation
must STOP and obtain explicit scope approval first.

**Status: PROPOSED / SCOPE PARTIALLY UNRESOLVED.** Approval: reviewer
`_pending_`, date `_pending_`, reference `_pending_`.

### A14-06 — Verified actor eligibility

**Normative requirement (proposed).**

1. The acting user MUST be an **ACTIVE** Identity (not soft-deleted)
   with an eligible/ACTIVE Principal (not soft-deleted).
2. There must be an explicit `PrincipalTenantMembership` and
   `IdentityTenantMembership` for the Identity/Principal and the
   **selected** Tenant.
3. The selected Tenant MUST be `ACTIVE` (not `PROVISIONING`/
   `SUSPENDED`, not soft-deleted) and MUST be an **ordinary** Tenant
   (`SecurityScope.TENANT`). The SYSTEM/root Tenant and `SecurityScope.ROOT`
   are rejected as consumer context, even if fabricated registration or
   subscription rows exist.
4. The Application MUST be `ACTIVE` and separately, currently registered
   (`ACTIVE` registration) for that exact Tenant.
5. Tenant subscription eligibility is checked by the existing PR 13
   `ApplicationTenantEligibilityService` **separately** and is not used
   as authentication.
6. The selected Tenant is a request context, never proof of membership.
7. Missing/inconsistent context fails closed.

**Rationale.** Verified context / Tenant isolation; PR 12 `T5`
precedence.

**Alternatives considered.** Using the subscription as the auth gate
(rejected: conflates commercial fact with authentication); allowing
SYSTEM/root consumer context (rejected: PR 12 §3B).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-07 — Delegation / confused-deputy prevention

**Normative requirement (proposed).** The full delegation contract is
§6. In summary:

1. The acting-user token alone does not grant the Application delegation
   rights.
2. A user token MUST present issuer-validated evidence that the verified
   calling OAuth client is authorized to act for the subject.
3. Two independently valid tokens with no verifiable relationship MUST
   fail.
4. Absent/ambiguous delegation evidence fails closed.

**Original proposal (preserved, differs from the §9 recommendation).**
The first draft accepted either `azp == verified client_id` under a
deployment convention that the same client is used for service and user
flows, **or** an `act` claim under token exchange.

**Reviewer-recommended refinement (recorded, NOT approved).** An `azp`
claim **alone does not automatically establish delegation authority**;
`azp` typically identifies the client that obtained the token and may be
a different or shared client. An `act` claim is accepted **only** under
an explicitly defined trusted token-exchange profile. Delegation must be
issuer-validated, not inferred.

**Discrepancy to resolve.** The two positions differ on whether
`azp == client_id` can ever be sufficient. §6 records the stricter
recommended contract as the working proposal and preserves the original
as an explicitly flagged alternative. Do not implement either until the
reviewer chooses.

**Rationale.** Confused-deputy prevention; PR 12 `T1`/`T6`.

**Status: PROPOSED / CLAIM CONTRACT UNRESOLVED.** Approval: reviewer
`_pending_`, date `_pending_`, reference `_pending_`.

### A14-08 — Protected root binding (`LOCAL` origin gate)

**Normative requirement (proposed).** The root model is §7. In summary:

1. The canonical root Identity remains origin `LOCAL`; it is never
   reclassified as `FEDERATED`.
2. A **separate**, protected, installation-only authentication binding
   maps the verified external `(issuer, sub)` to the designated root
   Identity.
3. The binding is unique among active rows, auditable, immutable except
   under a separately approved protected operator procedure, and never
   runtime-editable.
4. Root assurance (MFA/`acr`/`amr`) is required and must be sufficient.
5. Root authentication is never accepted as ordinary Application/
   SYSTEM-Tenant consumer authorization, and no root recovery is
   implemented here.

**Alternate disposition (option B).** Split root authentication/binding
out of PR 14; PR 14 is reported `BLOCKED` on root and does not claim
completion. The reviewer must choose option A or option B and record it
in §11.

**Rationale.** PR 10 root design gate;
`HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §12A.

**Recommendation (not an approval).** Prefer option A: retain the
canonical root Identity as `LOCAL` with a separate protected
`(issuer, subject)` binding; do not reclassify as `FEDERATED`.

**Status: PROPOSED / ROOT SEMANTICS UNRESOLVED.** Approval: reviewer
`_pending_`, date `_pending_`, reference `_pending_`.

### A14-09 — No public trust route; typed internal API

**Normative requirement (proposed).**

1. PR 14 exposes a typed **internal** verifier and actor-context
   composition interface consumed by PR 17.
2. It adds no public HTTP endpoint, route, public DTO, or token issuance.
3. It returns only sanitized error categories; PR 15 owns external HTTP
   error mapping.
4. Raw tokens, client secrets, and token bytes never appear in returned
   objects, `repr`, exceptions, or logs.
5. Errors must not reveal account existence to untrusted callers.

**Rationale.** PR 15/17 boundary; sanitized failure surface.

**Alternatives considered.** A public `/authenticate` route (rejected:
belongs to PR 17); returning provider exceptions (rejected: leak/reveal
risk).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-10 — Privilege posture for mapping persistence

**Normative requirement (proposed).**

1. Credential/binding administration is installation/operator-only
   through owner-owned `SECURITY INVOKER` stored functions with `PUBLIC
   EXECUTE` revoked.
2. `mtmf_runtime` receives only narrowly scoped reviewed `SECURITY
   DEFINER` **read** functions with fixed empty `search_path` and
   schema-qualified identifiers.
3. No runtime table `SELECT`/DML, no mapping-mutation `EXECUTE`, no
   elevated membership, and no unreviewed `SECURITY DEFINER` function.
4. Persistence changes are **additive** migration `0011`; never edit
   `0001`–`0010` or `sql/v001`–`v010`.
5. The runtime `EXECUTE` manifest is updated with only the exact new
   reviewed read signatures, and the post-upgrade verifier must pass
   against the actual `mtmf_runtime` login.
6. Root-binding mutation must be denied to the runtime credential.

**Rationale.** Preserve the PR 10/13 privilege model; `DATABASE.md`.

**Alternatives considered.** Runtime mutation grants (rejected: recreates
the shared-runtime trust problem); granting direct table reads (rejected:
bypasses reviewed reads).

**Recommendation.** Adopt as written. Status: **PROPOSED**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

## 5. Proposed JWT claim-validation profiles

Profiles are **proposed** and must be confirmed against current official
issuer/JWT-library contracts before implementation. Local Keycloak is a
development **profile**, not the mandatory production provider. Do not
invent a universal `grant_type` JWT claim; token-class evidence is
issuer-specific.

### 5.1 Common checks (all profiles)

| Check | Proposed contract |
| --- | --- |
| `iss` | Exact string match against one configured canonical issuer. No path stripping, case folding, or alias acceptance. |
| `aud` | Must contain the profile's configured expected audience (string or array membership). |
| `exp` | Required. Reject at/after `exp` plus configured skew. |
| `nbf` | Validated with configured bounded skew; a future value beyond skew is rejected. Missing `nbf` handling is profile-defined. |
| `iat` | Validated with configured bounded skew; a future `iat` beyond skew is rejected. Required for the service and user profiles (exact requirement pending). |
| `alg` | Fixed asymmetric allowlist (`RS256`/`ES256`/`PS256`, or an approved subset). `none` and `HS*` rejected. Key type must match algorithm. |
| `kid` | Selects only among trusted keys already loaded for that issuer. Never causes a network fetch of an attacker-supplied URL. |
| `jku`/`x5u`/`jwk` | Never fetched or trusted; if a key cannot be resolved from the configured JWKS set, reject. |
| `typ` / token class | Profile-specific predicate (below). Reject ID tokens and refresh tokens. |
| Size/parse bounds | Bound raw-JWT bytes, claim count, and JSON nesting before unbounded parsing. |
| JWKS | Only the configured `jwks_uri`; bound response size, cache TTL, timeout, and redirects; unknown-`kid` refresh throttled; stale/failed refresh cannot authorize a new key. |
| Clock | One captured UTC time per resolution; skew reduces, never extends, validity. |

### 5.2 Service profile (OAuth 2.0 client credentials)

| Claim | Proposed requirement |
| --- | --- |
| `aud` | Configured **service** audience. |
| Credential identity | `azp` (or approved `client_id`-equivalent claim) — the credential key `(issuer, client_id)` that maps to exactly one Application. |
| `sub` | MAY exist but is **not** a human Identity and is never used for user resolution. |
| Class predicate | Must prove a client-credentials access token and must be disjoint from the user profile's predicate. Must not be accepted where a user token is required. |
| Delegation | None at service level; delegation is established by the user profile (A14-07/§6). |

### 5.3 End-user profile

| Claim | Proposed requirement |
| --- | --- |
| `aud` | Configured **user** audience, distinct from the service audience. |
| `sub` | Required. Maps to exactly one Identity via `(issuer, sub)`. |
| `azp` | The authorized party; recorded, but **not sufficient alone** as delegation (A14-07/§6). |
| `act` | Accepted **only** under an explicitly approved trusted token-exchange profile; validated as part of the trusted issuer's signed token. |
| Class predicate | Must prove a user access token (not ID, not refresh, not client credentials). |
| Delegation | Must satisfy §6 against the verified calling `client_id`. |

### 5.4 Root profile (only if A14-08 option A is approved)

| Claim | Proposed requirement |
| --- | --- |
| Account | Dedicated privileged external account; not an ordinary member/identity. |
| `aud` | Configured **root** audience. |
| `sub` | Maps to the single protected root binding. |
| Assurance | Configured MFA/assurance claim (`acr` and/or `amr`) present and sufficient (exact values require approval). |
| Class predicate | Root interactive access token; not service, ID, or refresh. |
| Isolation | Never accepted as an ordinary Application/SYSTEM-Tenant consumer authorization. |

## 6. Proposed delegation contract

This is the working proposal for A14-07. It records the stricter
recommended position; the original `azp`-sufficiency alternative is
preserved in A14-07 and must be resolved by the reviewer.

1. **Calling client.** The verified service token establishes the calling
   credential identity `(issuer, client_id)`, which maps to exactly one
   Application. This `client_id` is the delegation principal.
2. **Trusted issuer.** The user token (or exchanged token) must be
   issued/attested by the same trusted issuer as the service token, or by
   an explicitly configured trusted issuer pair for an approved token
   exchange. Cross-issuer delegation without an approved profile is
   rejected.
3. **Delegation evidence (must be issuer-validated, not inferred):**
   - **Preferred — RFC 8693 exchanged token `act` claim.** The user
     token is an exchanged access token from the trusted exchange
     endpoint, containing an `act` claim whose acting subject/client
     equals the verified `client_id` (nested `act` chains handled per the
     approved profile). The `act` claim is inside the issuer-signed token
     and is validated as part of the token.
   - **Alternative — explicitly approved issuer authorized-party
     contract.** A specific claim that the issuer itself uses to attest
     the client→user delegation, equal to the verified `client_id`. The
     exact claim name/shape is per-issuer and requires approval.
   - **`azp`.** Recorded but **not sufficient alone**. `azp == client_id`
     is never treated as automatic delegation authority; it may be
     accepted only as an additional condition within an explicitly
     approved issuer profile.
4. **Audience.** The user/exchanged token must contain the configured
   MTMF **user** audience; a service-audience or unknown-audience token
   is rejected.
5. **Issuer.** Exact configured issuer match; no alias/URL
   normalization.
6. **Bidirectionality.** The delegation binds one exact Application
   (from the service token), one exact acting subject Identity (from the
   user token), and one exact Tenant context. No cross-Application or
   cross-Tenant substitution.
7. **Fail closed.** Missing, ambiguous, unsupported, or contradictory
   delegation evidence → `delegation_denied`; never inferred from the
   mere possession of two independently valid tokens.

**Unresolved:** the exact claim name(s) and whether the same OAuth client
is used for both service and user flows, or an explicit delegation
relation must be configured. STOP if no verifiable binding exists.

## 7. Proposed root authentication model and `LOCAL` reconciliation

Working proposal for A14-08 option A. Not approved.

1. **Origin preserved.** The canonical root Identity created by PR 10
   remains origin `LOCAL`. MTMF does not reclassify it, does not store a
   password for it, and does not create a second root.
2. **Separate protected binding.** A dedicated protected
   authentication-binding record maps the verified external
   `(issuer, sub)` to the designated root Identity. Proposed storage
   options:
   - **(i) Dedicated table (recommended):** e.g.
     `root_authentication_binding`, separate from the ordinary
     external-subject binding table, with installation-only mutation and
     runtime read-only access (or no runtime access at all).
   - **(ii) Protected flag on the ordinary binding table:** simpler but
     risks accidental treatment as a generic editable binding.
   The reviewer must choose; (i) is recommended.
3. **Structural reconciliation with PR 10.** The binding target must
   equal `root_registry.root_identity_id`; the root Identity must remain
   `LOCAL`, not soft-deleted, and its Principal/Tenant membership and
   protected root chain must remain intact. The binding cannot target a
   non-root Identity, and adding it cannot create, move, or demote root.
4. **Assurance.** Normal root login requires a dedicated privileged
   external OIDC account with phishing-resistant MFA. The approved
   assurance claim (`acr`/`amr` or equivalent) must be present and
   sufficient; absent/insufficient assurance → reject.
5. **Uniqueness/immutability.** At most one active root binding;
   installation-only provisioning; immutable except under a separately
   approved protected operator procedure; auditable.
6. **Isolation.** A root token is never accepted as an ordinary
   Application/SYSTEM-Tenant consumer authorization. Root management and
   emergency recovery remain separate (no recovery CLI, no runtime
   recovery grant, no fabricated root session).
7. **Option B.** If the reviewer does not approve this reconciliation,
   split root work out of PR 14 and report `BLOCKED` for the root gate
   rather than claiming completion.

**Unresolved:** option A vs option B; storage option (i) vs (ii); the
exact assurance claim values; and the ordinary/root Identity-origin rule
for each issuer.

## 8. Proposed dependency and module ownership

**Working proposal.** Provider-neutral trust and identity-resolution
logic belongs in `mtmf-core`; only HTTP-specific integration belongs in
`mtmf-service`.

- **JWT dependency:** make `pyjwt[crypto]` an explicit,
  version-constrained dependency (proposed constraint `>=2.13,<3`,
  matching the locked `2.13.x`), using explicit asymmetric algorithm
  allowlists and a controlled JWKS client (bounded cache lifespan,
  timeout, no untrusted-URL following) or a reviewed equivalent.
  `python-jose` is not proposed (maintenance posture). No dependency is
  added until approved.
- **`mtmf-core` (provider-neutral trust/identity logic):**
  immutable trusted value types (verified service credential, verified
  acting user, verified actor context); the claim-validation profiles
  and delegated-verification logic; the `ExternalTokenVerifier` and
  `ExternalSubjectIdentityResolver` / `CredentialApplicationResolver`
  ports and implementations that do not perform HTTP; and
  `AuthenticatedActorContextService` orchestration over the existing
  SPI/UnitOfWork and PR 13 eligibility seam. Core stays free of
  transport frameworks.
- **`mtmf-service` (HTTP/transport-specific integration only):** the
  HTTP JWKS retrieval transport/adapter wiring and any future FastAPI
  request-binding (PR 17). No business or authorization logic.
- **Configuration:** trusted issuer allowlist, service/user/root
  audiences, `jwks_uri`, algorithm allowlists, bounded skew, JWKS TTL/
  timeouts, and an optional development issuer profile; strict startup
  validation and secret redaction.

**Discrepancy to resolve.** The initial Phase 0 draft placed the
PyJWT-based verifier adapter in `mtmf-service`. The recommended position
places provider-neutral trust/identity-resolution logic in `mtmf-core`
and reserves `mtmf-service` for HTTP-specific integration. The two
differ on where the cryptographic verifier and claim profiles live;
preserve both, and resolve at approval. The PR 12 ownership matrix
("`mtmf-service` owns token/user verification") must be reconciled with
this placement in the same approval.

## 9. Recommendations and open questions (not approvals)

**Recommendations recorded for review:**

1. **A14-05:** Signed, externally issued end-user access tokens are the
   mandatory v0.1 path; RFC 8693 token exchange is deferred unless
   required to establish verifiable delegation.
2. **A14-07:** Explicit, issuer-validated delegation to the authenticated
   Application is mandatory. `azp` alone does not establish delegation
   authority; `act` is accepted only under an explicitly defined trusted
   token-exchange profile.
3. **A14-08:** Retain the canonical root Identity as `LOCAL` with a
   separate protected `(issuer, subject)` authentication binding; do not
   reclassify as `FEDERATED`.
4. **Dependencies/ownership:** Explicit, version-constrained
   `pyjwt[crypto]`; provider-neutral trust/identity-resolution logic in
   `mtmf-core`; HTTP-specific integration in `mtmf-service`.

**Open questions requiring reviewer disposition:**

| # | Question | Blocks |
| --- | --- | --- |
| Q1 | Does PR 12 `T1` require both signed-token and executable RFC 8693 modes in PR 14? | A14-05 scope |
| Q2 | Exact delegation claim contract; is `azp == client_id` ever sufficient? Is the same OAuth client used for both flows? | A14-07/§6 |
| Q3 | Root option A vs option B; dedicated root-binding table vs protected flag; assurance claim values. | A14-08/§7 |
| Q4 | Exact issuer class predicates and supported audiences (Keycloak dev profile), confirmed against current issuer contracts. | A14-02/§5 |
| Q5 | Ordinary-user `IdentityOrigin` rule per issuer (`FEDERATED` expected). | A14-04/A14-06 |
| Q6 | JWT library/version confirmation. | §8 |
| Q7 | Module-ownership split (`mtmf-core` vs `mtmf-service`) and reconciliation with the PR 12 ownership matrix. | §8 |
| Q8 | Approval of `A14-01`–`A14-10` overall. | all |

## 10. STOP conditions

STOP and report before further coding if any of the following holds (from
the implementation plan §10, unchanged):

1. `A14-01`–`A14-10` lack explicit human approval, or approved issuer
   claim profiles are unavailable.
2. Root `LOCAL` origin and external OIDC binding cannot be reconciled
   without changing PR 10 security invariants, or root MFA/assurance
   requirements are unspecified.
3. Secure client-to-user delegation proof cannot be derived from
   verified issuer claims.
4. The chosen JWT library cannot enforce algorithm/key-type/issuer/
   audience/time and safe JWKS behavior with verified current APIs.
5. Required membership/Principal/Identity lifecycle semantics are
   ambiguous or incompatible with the proposed mapping.
6. A design requires giving `mtmf_runtime` mapping writes, root/recovery
   mutation, raw table access, or unreviewed `SECURITY DEFINER`
   privileges.
7. A design requires editing shipped migrations `0001`–`0010`,
   implementing an HTTP endpoint, minting tokens, building a
   token-exchange server, or adding Keycloak runtime orchestration.
8. A security-critical case cannot be tested against the prescribed real
   PostgreSQL topology.
9. `main` has advanced with conflicting identity/authentication work;
   reconcile before implementation.
10. Any mandatory gate fails without proven resolution.

## 11. Approval log

All rows are **PENDING HUMAN REVIEW**. No decision is approved.

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| A14-01 | PENDING HUMAN REVIEW | — | — | — |
| A14-02 | PENDING HUMAN REVIEW | — | — | — |
| A14-03 | PENDING HUMAN REVIEW | — | — | — |
| A14-04 | PENDING HUMAN REVIEW | — | — | — |
| A14-05 | PENDING HUMAN REVIEW / SCOPE OPEN | — | — | — |
| A14-06 | PENDING HUMAN REVIEW | — | — | — |
| A14-07 | PENDING HUMAN REVIEW / CLAIM CONTRACT OPEN | — | — | — |
| A14-08 | PENDING HUMAN REVIEW / ROOT SEMANTICS OPEN | — | — | — |
| A14-09 | PENDING HUMAN REVIEW | — | — | — |
| A14-10 | PENDING HUMAN REVIEW | — | — | — |
| §5 claim profiles | PENDING HUMAN REVIEW | — | — | — |
| §6 delegation contract | PENDING HUMAN REVIEW | — | — | — |
| §7 root model | PENDING HUMAN REVIEW | — | — | — |
| §8 dependency/ownership | PENDING HUMAN REVIEW | — | — | — |

## 12. Post-approval implementation outline (not started)

Only after §11 is approved: immutable trust contracts (Part 1); trusted
token verifier with bounded JWKS (Part 2); additive `0011` mapping
persistence, stored functions, and restricted runtime reads (Part 3);
verified actor composition reusing PR 13 (Part 4); configuration and
composition seam (Part 5); documentation and final gates (Part 6). The
mandatory deterministic acceptance matrix `AUTH-01`–`AUTH-36` and the
real-PostgreSQL privilege gates in the implementation plan apply.
