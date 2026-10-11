# PR 14 — Service Authentication and Verified Acting-User Security Decisions

> **STATUS: D1 ARCHITECTURE SELECTED; KEYCLOAK DEVELOPMENT PROFILE CONDITIONALLY APPROVED; FULL PR 14 APPROVAL PENDING. IMPLEMENTATION STOP.**
>
> This register records the PR 14 security decisions proposed in the
> detailed implementation plan and the Phase 0/Phase 0-refinement
> evidence review. It is **not** an approval. Per the PR 14 execution
> contract and `AGENTS.md`, no security-sensitive implementation (token
> verifier, trust contracts, `0011` persistence, actor-context
> composition) may begin until a human reviewer records explicit
> approval of `A14-01`–`A14-10`, the issuer claim profiles in §7, the
> delegation contract in §8, the root model in §9, and the dependency/
> ownership split in §10 — or an explicitly narrower scope.
>
> Do not infer approval from the existence of this document, the
> implementation plan, `PR12_INTEGRATION_SECURITY_DECISIONS.md`,
> `PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md`, an implementation
> request, a coding-agent report, successful documentation checks, or
> the fact that some requirements below are marked “supportable for
> approval”. Every unresolved value is marked **UNRESOLVED** or
> **BLOCKED**, and implementation must STOP rather than assume it.
> Recommendations in §11 are **recommendations only**, not approvals.
> The approval log in §14 is untouched and remains PENDING.

Owner documentation: [SECURITY_MODEL.md](SECURITY_MODEL.md),
[DOMAIN_MODEL.md](DOMAIN_MODEL.md), [AUTHORIZATION.md](AUTHORIZATION.md),
[ARCHITECTURE.md](ARCHITECTURE.md), [DATABASE.md](DATABASE.md).
Companion contracts: [PR12_INTEGRATION_SECURITY_DECISIONS.md](PR12_INTEGRATION_SECURITY_DECISIONS.md)
(T1/T6), [HTTP_INTEGRATION_BATCH_AUTHORIZATION.md](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
(§2, §3, §3A, §3B, §12A), [PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md](PR13_APPLICATION_SUBSCRIPTION_DECISIONS.md).
Track 2 issuer evidence: [PR14_KEYCLOAK_EVIDENCE.md](PR14_KEYCLOAK_EVIDENCE.md) —
reproducible observations from the isolated Keycloak 26.8.0 dev fixture. The
evidence does **not** grant approval; see §17.

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

## 2. Reconciled baseline and inspected sources

This section separates **repository facts** (inspected locally) from
**externally documented issuer behavior** (verified against official
documentation) from **MTMF configuration/observed evidence** (absent).

### 2.1 Repository facts (inspected)

| Fact | Value |
| --- | --- |
| Branch | `dev/service-auth` |
| `origin/main` base | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Initial Phase 0 register commit | `2ed39bb` (“PR 1 phase 0”) |
| Published finalized register | `cea99d144b8df164defae99ef6f32d2bca1377c0` |
| Refinement base | `cea99d1` (clean working tree at start) |
| Alembic migration head | `0010_pr13_application_registry` |
| Runtime EXECUTE allowlist | exactly **75** signatures (6 removal + 44 repository + 8 role-assignment + 9 TenantManagementGroup/root + 8 Application-registry), from `expected_runtime_signatures()` |
| `mtmf-api`/`mtmf-client`/`mtmf-service` | empty `__version__` stubs |
| Existing auth/JWT/JWKS code | none |
| `compose.yaml` services | PostgreSQL 18 only |
| Keycloak version/config in repo | **none** (no realm, client, audience, ACR/AMR, or dev-issuer configuration) |
| PR 14 implementation plan on branch | **absent** from `.plans/` |
| Locked crypto libs | `cryptography==50.0.1`, `pyjwt==2.13.0` (both transitive, not declared by any MTMF package) |

Reuse seams confirmed: one provider-neutral `MtmfSpi`, `UnitOfWork`, typed
repositories, `PostgresMtmfSpi` (runtime-only),
`ApplicationTenantEligibilityService`, versioned `sql/v0NN` + additive
Alembic migrations, `Identity`/`Principal`/`Tenant`/typed memberships,
`IdentityOrigin` (`LOCAL`/`FEDERATED`), `TenantLifecycle`,
`SecurityScope`, and the `root_registry` protected canonical root binding.

### 2.2 Externally verified issuer/library evidence (official docs)

Accessed 2026-10-11. These are **documented capabilities**, not proof of
any MTMF-configured profile, and not observed runtime tokens.

| Source | URL | Relevance |
| --- | --- | --- |
| Keycloak Server Administration Guide (release **26.8.0**) | `https://www.keycloak.org/docs/latest/server_admin/` | client_credentials/service accounts, audience mappers, ACR→LoA, AMR mapper, `azp` presence, Standard Token Exchange client option |
| Keycloak “Configuring and using token exchange” (release **26.8.0**) | `https://www.keycloak.org/securing-apps/token-exchange` | Standard Token Exchange V2, delegation (`may_act`/`act`) preview status |
| OpenID Connect Core 1.0 | `https://openid.net/specs/openid-connect-core-1_0.html` | normative `azp` definition (ID Token) |
| RFC 8693 (OAuth 2.0 Token Exchange) | `https://www.rfc-editor.org/rfc/rfc8693.txt` | `act` (§4.1) and `may_act` (§4.4) claims |
| PyJWT 2.13.0 (installed) | local `.venv` source | `decode`, `PyJWKClient`, leeway semantics |

### 2.3 What the evidence does and does not prove

- **Proves (documented capability):** Keycloak 26.8.0 documents the
  OAuth 2.0 Client Credentials grant via a client service account;
  Audience/Audience-Resolve protocol mappers that add audiences to the
  **access token only**; a realm (and per-client) ACR→Level-of-
  Authentication mapping whose `acr` value is included in access and ID
  tokens; an AMR protocol mapper (RFC 8176); the presence of `azp` in
  access tokens; and a fully supported Standard Token Exchange V2.
- **Does not prove (MTMF-specific):** no MTMF Keycloak realm/client
  configuration exists, so no service/user/root **token-class predicate**,
  audience value, `acr`/`amr` profile, or observed claim set can be
  asserted. Those remain **UNVERIFIED / NOT EXECUTED**.
- **Does not prove (delegation):** Keycloak documents that its
  `may_act`/`act` delegation is **Preview, disabled by default**, and
  requires explicit feature enablement plus FGAP V2. Standard Token
  Exchange V2 (fully supported) only exchanges a Keycloak token for a
  token targeted at a different client in the same realm; it is not, by
  itself, a guarantee that a direct user access token proves
  client-to-user delegation.
- **Does not prove (root assurance):** Keycloak documents ACR→LoA and AMR
  mapping, but generic `mfa`/`otp`/unspecified `acr` values do not prove
  phishing resistance. No MTMF root realm policy exists.

### 2.4 Evidence taxonomy used below

Repository facts; official-doc documented capabilities; proposed MTMF
configuration; and observed runtime claim evidence are kept distinct. No
observed claim evidence exists (no live issuer test was run:
**NOT EXECUTED**). Prior 1357-test QA is baseline/regression evidence
only and does not validate issuer claim semantics.

## 3. Approval gate and conventions

Implementation may not begin until a reviewer approves each of
`A14-01`–`A14-10` in §6 and the profiles/contracts in §7–§10, or an
explicitly narrower scope. The approval log in §14 must be completed with
reviewer identity, date, and reference.

Status vocabulary:

- **PROPOSED** — stated contract; pending review.
- **RECOMMENDED FOR APPROVAL** — Phase 0/refinement recommendation; still not approved.
- **SUPPORTABLE FOR APPROVAL** — evidence exists to review it now; not approved.
- **UNRESOLVED** — required value not settled; STOP if it blocks implementation.
- **BLOCKED** — missing evidence/guarantee prevents a safe contract; STOP.

## 4. Executed scope control

This refinement changed documentation only. No production Python/Rust,
migrations (`0011` or older), SQL, grants, `pyproject.toml`, lockfiles,
container/Podman orchestration, Keycloak deployment, secrets, tokens, new
endpoints, JWT verifier code, identity-mapping implementation, root
recovery, or test code was changed. No decision is marked APPROVED.

## 5. Phase 0 refinement method

1. Reconciled branch, `origin/main`, and docs (§2.1).
2. Collected PyJWT evidence from the installed 2.13.0 source (§10.2).
3. Reviewed official Keycloak 26.8.0 and OIDC/RFC documentation (§2.2).
4. Distinguished documented capability from MTMF configuration and
   observed evidence (§2.3–§2.4).
5. Refined A14-02/05/07/08 and §7–§10; added the reviewer decision table
   (§12) and decision-ready summary (§13). Approval log remains §14.

## 6. Proposed decisions

### A14-01 — Token trust model (resource server)

**Normative requirement (proposed).**

1. MTMF acts only as an OAuth 2.0 **resource server**. It validates
   access tokens; it does not issue them.
2. Accept only asymmetric, signed JWT **access tokens** from explicitly
   allowlisted `(issuer, audience)` pairs.
3. Reject `alg=none`; symmetric shared-secret JWTs (`HS*`); any algorithm
   or key type not in the profile’s fixed allowlist; ID tokens
   (`token_use`/`typ` indicating ID); refresh tokens; and opaque tokens
   with no verifiable signature.
4. Never perform implicit discovery of an arbitrary issuer, `jwks_uri`,
   `jku`, or `x5u`. Only configured trust anchors are used.
5. A token that merely parses is not accepted; signature, issuer,
   audience, token class, and time must all verify.

**Rationale.** Bounded trust surface; PR 12 `T1`; PR 14 invariants.

**Refinement.** The expiry/time semantics are now evidence-backed in
§10.2; the recommended PyJWT constraint is §10.1.

**Recommendation.** Adopt as written. Status: **PROPOSED /
SUPPORTABLE FOR APPROVAL**. Approval: reviewer `_pending_`, date
`_pending_`, reference `_pending_`.

### A14-02 — Distinct service and user validation profiles

**Normative requirement (proposed).**

1. Two distinct, immutable trust profiles exist: **service** and
   **end-user** (plus **root**, §9).
2. They MUST have **different expected audiences** (no shared alias).
3. Each profile defines explicit, non-empty token-class predicates.
4. Service profile requires configured client-credentials evidence
   (`azp`/`client_id` or an approved issuer-specific equivalent) and MUST
   NOT accept a human subject.
5. User profile requires `sub` and approved user-token predicates.
6. Missing, ambiguous, or contradictory class evidence is rejected.
7. A service token is never accepted where a user token is required, and
   vice versa.

**Rationale.** Token-confusion prevention.

**Refinement (Phase 0).** Keycloak 26.8.0 documents that Audience mappers
add audiences to the **access token only**.

**Track 2 observed refinement (not an approval).** In the isolated
Keycloak 26.8.0 fixture, the access-token payload `typ` is `Bearer` for
**both** the client-credentials and interactive-user tokens, so `typ`
alone does not separate service from user; the profile-specific
**audience** does. ID tokens use payload `typ=ID` and refresh tokens use
payload `typ=Refresh`. Therefore the proposed predicate is:

- service profile: audience contains the configured service audience and
  the token is not a user/ID/refresh token; credential identity from
  `azp`;
- user profile: audience contains the configured user audience, payload
  `typ=Bearer`, and a stable `sub`.

This is observed for the **development** profile only; the production
issuer profile still requires approval (§17).

**Status: PROPOSED / OBSERVED FOR THE DEV PROFILE (production profile
still requires approval)**. Approval: reviewer `_pending_`, date
`_pending_`, reference `_pending_`.

### A14-03 — Service credential → exactly one Application

**Normative requirement (proposed).**

1. The persisted service-credential semantic key is the immutable tuple
   `(issuer, client_id)` (or a specifically approved issuer credential
   identifier).
2. Each current credential maps to exactly one Application UUID.
3. Multiple active credentials MAY map to one Application.
4. One credential MUST NOT map to two Applications — not in place and
   not historically.
5. Deactivation/revocation blocks subsequent verification; terminal rows
   are history and must not block a new distinct credential.
6. The credential identifier is never the Application UUID and is never
   inferred from a mutable name or Tenant.
7. Duplicate/ambiguous active rows fail closed; never select an
   arbitrary `LIMIT 1`.

**Rationale.** PR 12 `T6`; no spoofing.

**Refinement.** Keycloak documents the `client_id`/service-account
concept, but the exact claim used to carry the credential identity in an
access token is profile-specific and remains part of §7/A14-02.

**Recommendation.** Adopt as written. Status: **PROPOSED / SUPPORTABLE
FOR APPROVAL** (subject to §7 claim-name confirmation). Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-04 — External subject → exactly one MTMF Identity

**Normative requirement (proposed).**

1. User binding semantic key is the immutable tuple `(issuer, sub)`.
2. Each current binding maps to exactly one MTMF Identity.
3. No email/name/`preferred_username` matching; no implicit or JIT
   Identity creation; no self-service mapping.
4. Binding mutations are operator/installation-only and never granted to
   `mtmf_runtime`.
5. Ordinary (non-root) external users bind to a **`FEDERATED`** MTMF
   Identity; the root binding is the sole protected exception (§9).
6. Zero, multiple, inactive, inconsistent, or cross-Tenant mappings fail
   closed.
7. One `(issuer, sub)` never maps to two Identities, and one Identity
   never claims two current `(issuer, sub)` bindings unless the reviewer
   explicitly approves a multiple-binding model.

**Rationale.** PR 12 `T1`; account-takeover resistance.

**Refinement.** Re-checked `IdentityOrigin` and membership contracts in
`mtmf_core.domain.identity_entity`/`memberships`: origin is immutable
`LOCAL`/`FEDERATED`, and Tenant usability is explicit through
`IdentityTenantMembership` plus the matching `PrincipalTenantMembership`.
A `FEDERATED` ordinary binding is compatible with those contracts; this
does **not** assert an issuer rule (which remains a reviewer choice, §13/Q5).

**Recommendation.** Adopt as written. Status: **PROPOSED /
SUPPORTABLE FOR APPROVAL**. Approval: reviewer `_pending_`, date
`_pending_`, reference `_pending_`.

### A14-05 — Acting-user propagation mode (SCOPE GATE)

**Recommended interpretation of PR 12 `T1` for review.**

1. The mandatory v0.1 mechanism is an **externally issued, signed,
   validated end-user access token**, verified independently of the OAuth
   2.0 Client Credentials service token.
2. RFC 8693 exchange is **not mandatory merely because PR 12 lists it as
   an alternative**. It becomes a dependency only **if the selected
   issuer cannot establish the required client-to-user delegation binding
   through its signed direct-token profile**.
3. If direct tokens cannot demonstrate delegation under a documented
   issuer guarantee, mark A14-05/A14-07 **BLOCKED**, propose RFC 8693 as
   an alternative for human approval, and STOP.
4. Never implement an exchange endpoint, an exchange client, or an ad-hoc
   service-signed assertion in PR 14.
5. Any exchanged token that is later approved is validated exactly like
   any other user token, including its actor/delegation chain; the
   exchange request/response is never trusted unverified.

**Evidence.** Keycloak 26.8.0 documents a fully supported Standard Token
Exchange V2, but also documents that the `may_act`/`act` **delegation**
feature is **Preview, disabled by default**, requiring
`--features=preview` or `--features=token-exchange-delegation` and FGAP
V2. A preview feature is not an acceptable mandatory security dependency.

**Track 2 observed refinement (not an approval).** A live Standard Token
Exchange V2 attempt in the isolated fixture failed with HTTP 400
`Requested audience not available`, so V2 availability was **not**
demonstrated; actor delegation remains a preview feature (§17, K13/K14).
Signed external-issuer end-user access tokens were issued and verified
successfully (K02).

**Recommendation.** Signed external-issuer end-user access tokens are the
mandatory v0.1 path; RFC 8693 exchange is a contingency, not a baseline.

**Open scope question Q1.** If the reviewer interprets `T1` as requiring
**both** modes to be executable in PR 14, STOP and obtain explicit scope
approval.

**Status: PROPOSED / SCOPE PARTIALLY UNRESOLVED**. Approval: reviewer
`_pending_`, date `_pending_`, reference `_pending_`.

### A14-06 — Verified actor eligibility

**Normative requirement (proposed).**

1. The acting user MUST be an **ACTIVE** Identity (not soft-deleted) with
   an ACTIVE Principal (not soft-deleted).
2. Explicit `PrincipalTenantMembership` and `IdentityTenantMembership`
   must exist for the Identity/Principal and the **selected** Tenant.
3. The selected Tenant MUST be `ACTIVE` (not `PROVISIONING`/`SUSPENDED`,
   not soft-deleted) and **ordinary** (`SecurityScope.TENANT`). The
   SYSTEM/root Tenant (`SecurityScope.ROOT`) is rejected as consumer
   context even if fabricated registration/subscription rows exist.
4. The Application MUST be `ACTIVE` and currently `ACTIVE`-registered for
   that exact Tenant.
5. Tenant subscription eligibility is checked by the existing PR 13
   `ApplicationTenantEligibilityService` **separately**; it is never
   authentication.
6. The selected Tenant is request context, never proof of membership.
7. Missing/inconsistent context fails closed.

**Rationale.** Verified context / Tenant isolation; PR 12 `T5`.

**Refinement.** Confirmed against the in-repo `Tenant`/`SecurityScope`/
`TenantLifecycle` and typed-membership contracts.

**Recommendation.** Adopt as written. Status: **PROPOSED / SUPPORTABLE
FOR APPROVAL**. Approval: reviewer `_pending_`, date `_pending_`,
reference `_pending_`.

### A14-07 — Delegation / confused-deputy prevention

**Normative requirement (proposed).** The detailed contract is §8. In
summary:

1. The acting-user token alone does not grant the Application delegation
   rights.
2. A user token MUST present **issuer-validated** evidence that the
   verified calling OAuth client is authorized to act for the subject.
3. Two independently valid tokens with no verifiable relationship MUST
   fail.
4. `act` is accepted only under a separately approved, issuer-specific
   RFC 8693 exchanged-token profile; no generic `act` fallback.
5. Absent/ambiguous delegation evidence fails closed.

**Evidence and verdict.**

- OIDC Core defines `azp` for **ID Tokens** and states that in practice
  `azp` “only occurs when extensions beyond the scope of this
  specification are used”; validation SHOULD follow the extension.
  Keycloak does emit `azp` in access tokens, but the reviewed Keycloak
  documentation does **not** guarantee that the access-token `azp` is the
  client that obtained the user's authorization in a way that establishes
  MTMF delegation. Therefore `azp == client_id` alone is **insufficient**
  and the same-client direct-token design is **BLOCKED — UNVERIFIED**
  pending an explicit issuer guarantee and configured profile.
- RFC 8693 §4.1 defines the `act` claim. Keycloak’s `act`/`may_act`
  delegation is **Preview/disabled-by-default** (26.8.0); it is not an
  assured fallback.
- **Track 2 observation (not delegation proof):** in the isolated
  fixture, the same client obtained both a service token and a user token
  with equal `azp` (K09), and different clients produced different `azp`
  (K10). No documented issuer guarantee accompanies that equality. The
  direct-token design remains **BLOCKED** pending Q2.

**Required reviewer question Q2.** Can one confidential OAuth client
safely serve both client-credentials and interactive user flows under the
selected Keycloak profile, and does the issuer guarantee the signed user
token was issued to that exact client? If not, describe the
distinct-client + exchange alternative and mark the direct-token design
**BLOCKED**, not approved.

**Status: PROPOSED / BLOCKED (issuer guarantee missing)**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-08 — Protected root binding (`LOCAL` origin gate)

**Normative requirement (proposed).** The root model is §9. In summary:

1. The canonical root Identity remains origin `LOCAL`; never reclassified
   as `FEDERATED`.
2. A **dedicated protected root-authentication-binding** record maps the
   verified external `(issuer, sub)` exclusively to
   `root_registry.root_identity_id`; installation-only creation/repair,
   never ordinary runtime mutation, no recovery implementation here.
3. The binding is unique among active rows, auditable, immutable except
   under a separately approved protected operator procedure.
4. Phishing-resistant MFA is required, attested by an issuer **policy**
   and a validated assurance signal. Generic `mfa`/`otp`/unspecified
   `acr` is insufficient.
5. Root authentication is never accepted as ordinary Application/
   SYSTEM-Tenant consumer authorization.
6. Option B (split/block root work) remains the explicit fallback.

**Evidence and verdict.** Keycloak 26.8.0 documents ACR→LoA mapping and
the AMR protocol mapper, but no MTMF root realm policy is configured and
no ACR value mapping to a phishing-resistant (WebAuthn/passkey-only)
policy has been evidenced. **Track 2 observation:** a password-only root
login in the isolated fixture yielded only `acr=1` with no `amr`
(generic realm assurance), and no WebAuthn flow was configured or
exercised (K15–K17). Root assurance is therefore **BLOCKED —
UNRESOLVED**; the smallest decision is an issuer-admin–documented realm
flow policy for the root account and the exact `acr`/`amr` value(s) it
emits in the **access token**, with evidence.

**Recommendation.** Prefer option A (keep root Identity `LOCAL`,
dedicated protected binding); do not reclassify as `FEDERATED`.

**Alternate disposition (option B).** Split root authentication/binding
out of PR 14; report `BLOCKED` on root and do not claim completion.

**Status: PROPOSED / BLOCKED (assurance evidence missing)**. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

### A14-09 — No public trust route; typed internal API

**Normative requirement (proposed).**

1. PR 14 exposes a typed **internal** verifier and actor-context
   composition interface consumed by PR 17.
2. No public HTTP endpoint, route, public DTO, or token issuance.
3. Only sanitized error categories; PR 15 owns external HTTP error
   mapping.
4. Raw tokens, client secrets, and token bytes never appear in returned
   objects, `repr`, exceptions, or logs.
5. Errors must not reveal account existence to untrusted callers.

**Rationale.** PR 15/17 boundary.

**Recommendation.** Adopt as written. Status: **PROPOSED / SUPPORTABLE
FOR APPROVAL**. Approval: reviewer `_pending_`, date `_pending_`,
reference `_pending_`.

### A14-10 — Privilege posture for mapping persistence

**Normative requirement (proposed).**

1. Credential/binding administration is installation/operator-only
   through owner-owned `SECURITY INVOKER` stored functions with `PUBLIC
   EXECUTE` revoked.
2. `mtmf_runtime` receives only narrowly scoped reviewed `SECURITY
   DEFINER` **read** functions with fixed empty `search_path` and
   schema-qualified identifiers.
3. No runtime table `SELECT`/DML, no mapping-mutation `EXECUTE`, no
   elevated membership, no unreviewed `SECURITY DEFINER` function.
4. Persistence changes are **additive** migration `0011`; never edit
   `0001`–`0010` or `sql/v001`–`v010`.
5. The runtime `EXECUTE` manifest is updated with only the exact new
   reviewed read signatures; the post-upgrade verifier must pass against
   the actual `mtmf_runtime` login.
6. Root-binding mutation is denied to the runtime credential.

**Rationale.** Preserve the PR 10/13 privilege model; `DATABASE.md`.

**Recommendation.** Adopt as written. Status: **PROPOSED / SUPPORTABLE
FOR APPROVAL**. Approval: reviewer `_pending_`, date `_pending_`,
reference `_pending_`.

## 7. Proposed JWT claim-validation profiles (evidence-backed status)

Each field records its evidence status. `UNVERIFIED` means no MTMF
production issuer profile/config exists; `DOCUMENTED` means Keycloak
26.8.0 documents the capability but not an MTMF value. **Track 2 addendum
(§17):** the Keycloak 26.8.0 *development* profile values are now
**OBSERVED** (service/user audiences, payload `typ`, `azp`, `acr`, key
type) in
[PR14_KEYCLOAK_EVIDENCE.md](PR14_KEYCLOAK_EVIDENCE.md); those observations
supersede the per-field `UNVERIFIED` only for the dev profile and are not
approval of a production profile.

### 7.1 Common checks (all profiles)

| Check | Proposed contract | Evidence status |
| --- | --- | --- |
| `iss` | Exact match against one configured canonical issuer; no path/case/alias normalization. | Proposed; MTMF value **UNVERIFIED** |
| `aud` | Must contain the profile’s configured expected audience. | Keycloak audience mappers documented; distinct MTMF audiences **UNVERIFIED** |
| `exp` | Required. Reject at/after `exp` with **no positive leeway** (see §10.2). | PyJWT behavior verified |
| `nbf` | Validated; future value beyond an explicit cap rejected. Presence rule per profile. | PyJWT behavior verified; presence rule **UNRESOLVED** |
| `iat` | Required (service/user/root); future value beyond an explicit cap rejected. | PyJWT behavior verified; requirement proposed |
| `alg` | Fixed asymmetric allowlist (`RS256`/`ES256`/`PS256`, or approved subset). `none`/`HS*` rejected; key type must match. | PyJWT supports; allowlist proposed |
| `kid` | Selects only among trusted keys; never a network URL. Duplicate `kid` rejected. | PyJWT first-match verified; duplicate rejection proposed |
| `jku`/`x5u`/`jwk` | Never fetched/trusted. | PyJWT rejects non-http(s) JWKS schemes; URL trust policy proposed |
| `typ`/token class | Profile-specific predicate; reject ID/refresh tokens. | Keycloak documents `typ` presence but not the access-token value; predicate **UNVERIFIED** |
| Size/parse bounds | Bound raw-JWT bytes, claim count, JSON nesting. | Proposed |
| JWKS | Only configured `jwks_uri`; bounded size/TTL/timeout/redirects; unknown-`kid` refresh throttled; stale/failed refresh cannot authorize. | PyJWT `PyJWKClient` partial (see §10.2) |
| Clock | One captured UTC time per resolution; skew reduces, never extends, validity. | Proposed |

### 7.2 Service profile (OAuth 2.0 client credentials)

| Field | Required documentation | Status |
| --- | --- | --- |
| Issuer/version | Actual Keycloak version/profile examined | **UNVERIFIED** (no MTMF config) |
| Token endpoint / grant | `client_credentials` via a client service account | DOCUMENTED (Keycloak 26.8.0) |
| `iss`, `aud` | Configured issuer; **distinct service audience** | **UNVERIFIED** (placeholders only) |
| Token class | Concrete predicate distinguishing a client-credentials token | **UNVERIFIED / NOT EXECUTED** |
| `sub` | Service-account subject; never a human Identity | DOCUMENTED (service account); MTMF rule proposed |
| Client identity | Exact claim (`azp`/`client_id`) and issuer semantics | **UNVERIFIED**; OIDC Core does not normatively define `azp` for access tokens |
| `exp`,`nbf`,`iat` | Presence + bounded policy | Proposed; `exp`/`iat` required; `nbf` rule unresolved |
| `typ`/`act` | Supported meaning, if any | `typ` value **UNVERIFIED**; `act` not applicable to service tokens |
| JWKS | Trusted issuer config, key selection/rotation/failure | Proposed; MTMF config **UNVERIFIED** |
| Evidence | Official docs/redacted observed example | Docs **DOCUMENTED**; observed **NOT EXECUTED** |

### 7.3 End-user profile

| Field | Required documentation | Status |
| --- | --- | --- |
| Issuer/version | Actual Keycloak version/profile examined | **UNVERIFIED** (no MTMF config) |
| Token endpoint / grant | Interactive flow (e.g. authorization code + PKCE) obtains the user token | DOCUMENTED (Keycloak 26.8.0); MTMF binding **UNVERIFIED** |
| `iss`, `aud` | Configured issuer; **distinct user audience** | **UNVERIFIED** |
| Token class | Predicate distinguishing a user access token from service/ID/refresh | **UNVERIFIED / NOT EXECUTED** |
| `sub` | Subject mapping `(issuer, sub)` → one Identity | Proposed; **UNVERIFIED** |
| Client identity | `azp`/`act` delegation evidence | `azp` documented-present but semantics **not guaranteed**; `act` preview |
| `azp` | Authority to act for the subject | **BLOCKED — no issuer guarantee** |
| `act` | RFC 8693 actor chain | RFC 8693 defines it; Keycloak delegation **Preview/disabled** |
| `exp`,`nbf`,`iat` | Presence + bounded policy | Proposed; `exp`/`iat` required; `nbf` rule unresolved |
| `typ`/`token_use` | Supported meaning, if any | **UNVERIFIED** |
| JWKS | Trusted issuer config, rotation/failure | Proposed; **UNVERIFIED** |
| Evidence | Official docs/redacted observed example | Observed **NOT EXECUTED** |

### 7.4 Root profile (only if A14-08 option A is approved)

| Field | Required documentation | Status |
| --- | --- | --- |
| Account | Dedicated privileged external account | Proposed |
| `iss`, `aud` | Configured issuer; distinct root audience | **UNVERIFIED** |
| `sub` | Maps to the single protected root binding | Proposed |
| Assurance | Exact `acr`/`amr` mapping to a phishing-resistant policy | ACR→LoA and AMR **DOCUMENTED**; exact values/policy **BLOCKED** |
| Class predicate | Root interactive token, not service/ID/refresh | **UNVERIFIED** |
| Isolation | Never ordinary Application/SYSTEM-Tenant authorization | Proposed |

## 8. Proposed delegation contract (refined)

Working contract for A14-07. The stricter position is recorded here; the
earlier `azp`-sufficiency draft is preserved as an explicitly flagged
alternative.

1. **Calling client.** The verified service token establishes the
   credential identity `(issuer, client_id)` (via an issuer-documented
   claim), mapping to exactly one Application. This `client_id` is the
   delegation principal.
2. **Same-client model (proposed v0.1 target).** A verified user
   **access** token must identify the **same** client by a documented
   issuer claim whose semantics the configured issuer/profile
   **explicitly guarantees**. A bare `azp == client_id` comparison
   **without that guarantee** is insufficient.
3. **Independent validation.** Both JWTs must independently pass issuer,
   distinct-audience, token-class, signature, temporal, and key checks.
4. **Trust-pair compatibility.** Both tokens must be compatible with the
   selected configured issuer trust pair. Neither may authorize a
   different Application or Tenant. The user’s verified `(issuer, sub)`
   must resolve through the protected MTMF binding and memberships.
5. **Fail closed.** A user token issued to a different client; a
   missing/ambiguous client claim; coincidental text only; or a service
   token presented as a user token **fails closed**.
6. **`act` path.** `act` is accepted only under a separately approved,
   issuer-specific RFC 8693 exchanged-token profile; no generic `act`
   fallback. The exchange request/response is never trusted unverified.
7. **Evidence limitation.** Keycloak 26.8.0 documents that it emits
   `azp` and that Standard Token Exchange V2 is supported, but it does
   **not** document that access-token `azp` establishes delegation; its
   `act`/`may_act` delegation is Preview/disabled-by-default. Therefore
   the direct-token design is **BLOCKED** pending the issuer guarantee in
   Q2.

**Preserved earlier proposal (differs).** The first Phase 0 draft
accepted `azp == client_id` under a shared-client deployment convention.
That is not adopted; it is retained here for reviewer comparison.

## 9. Proposed root authentication model and `LOCAL` reconciliation (refined)

Working proposal for A14-08 option A. Not approved.

1. **Origin preserved.** The canonical root Identity remains `LOCAL`; no
   reclassification, no password, no second root.
2. **Dedicated protected binding.** A separate protected
   root-authentication-binding table (recommended) maps verified
   `(issuer, sub)` exclusively to `root_registry.root_identity_id`.
   (Alternate: protected flag on the ordinary binding table — not
   recommended.)
3. **PR 10 reconciliation.** Binding target must equal
   `root_registry.root_identity_id`; the root Identity must remain
   `LOCAL`, not soft-deleted, with its Principal/Tenant membership and
   protected root chain intact. The binding cannot target a non-root
   Identity and cannot create/move/demote root.
4. **Assurance.** Phishing-resistant MFA backed by a documented and
   configured issuer policy **and** a validated assurance signal. Generic
   `mfa`/`otp`/unspecified `acr` is insufficient. No exact assurance
   contract can be proposed until the issuer-admin policy and ACR/AMR
   value(s) are evidenced → **UNRESOLVED — STOP**.
5. **Uniqueness/immutability.** At most one active root binding;
   installation-only provisioning; immutable except under a separately
   approved protected operator procedure; auditable.
6. **Isolation.** A root token is never ordinary Application/SYSTEM-Tenant
   consumer authorization. No recovery implementation here.
7. **Option B.** If option A is not approved, split root work out of
   PR 14 and report `BLOCKED`.

**Fallback.** Option B is explicit. No root password, recovery API,
synthetic root session, or unverified assurance claim is added.

## 10. Dependency and ownership

### 10.1 JWT dependency (proposed, not added)

- Make `pyjwt[crypto]` an explicit, version-constrained dependency
  (proposed `>=2.13,<3`, matching the locked `2.13.x`; `[crypto]` pulls
  `cryptography` for asymmetric verification).
- `python-jose` is not proposed (maintenance posture).
- No dependency is added by this documentation change.

### 10.2 PyJWT 2.13.0 evidence (installed source, verified)

| API | Verified behavior |
| --- | --- |
| `jwt.decode(jwt, key, algorithms, options, verify, audience, issuer, leeway, ...)` | Supports `issuer`, `audience`, `algorithms`; docstring warns not to derive `algorithms` from the token. |
| `_validate_exp` | Rejects when `exp <= now - leeway`. **Positive `leeway` extends acceptance past `exp`** — forbidden by the proposed contract. |
| `_validate_nbf` / `_validate_iat` | Reject future values beyond `now + leeway`. The same single `leeway` also relaxes `exp`. |
| `PyJWKClient.__init__` | Defaults `cache_keys=False`, `cache_jwk_set=True`, `lifespan=300`, `timeout=30`; rejects non-http(s) schemes. |
| Tier-2 key cache | If `cache_keys=True`, per-`kid` keys are cached with **no time-based expiration** — keep disabled. |
| `get_signing_key_from_jwt` / `get_signing_key` | Reads unverified `kid`; refreshes once on unknown `kid` with **no built-in throttle**. |
| `fetch_data` | Uses stdlib `urllib`; **follows redirects and has no response-size limit** — requires a wrapper/transport policy. |
| `match_kid` | Returns the **first** matching key; duplicate `kid` is not rejected by the library. |

**Proposed expiry policy (for approval).** Reject any token at/after its
signed `exp` using the authoritative validation clock; do **not** use
positive leeway to extend acceptance past `exp`. If tolerance is needed
for `nbf`/future `iat`, cap it explicitly and apply it only in the
non-expiry-extending direction. Because PyJWT applies one `leeway` to
`exp`, `nbf`, and `iat`, the contract must set `leeway=0` for the `exp`
check and implement any `nbf`/`iat` tolerance either by disabling those
two built-in checks and re-adding capped checks, or by accepting no
tolerance. Require `exp` and `iat`; make `nbf` presence explicit per
profile. Include JWKS timeouts, response-size limits, cache bounds,
unknown-`kid` refresh throttling, and no attacker-controlled key URL.

### 10.3 Package ownership reconciliation

- **`mtmf-core` (proposed):** immutable verified-token/actor contracts;
  profile and claim validation; provider-neutral cryptographic
  verification; identity/Application binding resolution; trusted actor
  composition; SPI/UoW integration; **no HTTP framework dependency**.
- **`mtmf-service` (proposed):** JWKS network transport and future HTTP
  request/response binding only; no duplicate identity/policy semantics.
- External IdP is not part of `MtmfSpi`; database reads use existing
  repositories/UoW and versioned stored functions only.

**Reconciliation vs. approved docs.** `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`
§2 states that `mtmf-service` owns the “authenticated HTTP trust
boundary, token/user verification, DTO mapping, subscription gate, …
(PRs 14/17)”, and `ARCHITECTURE.md` calls `mtmf-service` the
“authenticated service and end-user trust boundary (PR 14)”. Proposed
reading: **`mtmf-service` owns the deployed authentication boundary and
composition; `mtmf-core` owns reusable verification policy and
cryptographic logic.** Because this could change the apparent normative
ownership, it is **flagged for reviewer approval** and is not a silent
edit of the earlier documents.

**Status: PROPOSED / RECONCILIATION REQUIRES REVIEWER APPROVAL**. Do not
implement either placement until the reviewer decides. Approval:
reviewer `_pending_`, date `_pending_`, reference `_pending_`.

## 11. Recommendations and open questions (not approvals)

**Recommendations recorded for review:**

1. **A14-05:** Signed, externally issued end-user access tokens are the
   mandatory v0.1 path; RFC 8693 exchange is deferred unless required for
   verifiable delegation.
2. **A14-07:** Explicit, issuer-validated delegation is mandatory; `azp`
   alone is never sufficient; `act` only under an approved trusted
   exchange profile.
3. **A14-08:** Retain the canonical root Identity as `LOCAL` with a
   separate protected `(issuer, subject)` binding; never reclassify as
   `FEDERATED`.
4. **Dependencies/ownership:** explicit `pyjwt[crypto]`; provider-neutral
   verification in `mtmf-core`, HTTP integration in `mtmf-service`
   (subject to §10.3 reconciliation).

**Open questions requiring reviewer disposition:**

| # | Question | Blocks |
| --- | --- | --- |
| Q1 | Does PR 12 `T1` require both signed-token and executable RFC 8693 modes in PR 14? | A14-05 scope |
| Q2 | Issuer guarantee: can one confidential client serve both flows, and does the issuer guarantee the user token was issued to that client? | A14-05/A14-07/§8 |
| Q3 | Root option A vs B; dedicated table vs protected flag; and the issuer-admin–documented phishing-resistant ACR/AMR policy and exact value(s). | A14-08/§9 |
| Q4 | Exact per-issuer token-class predicates and distinct service/user/root audiences, with configured-profile evidence. | A14-02/§7 |
| Q5 | Ordinary-user `IdentityOrigin` rule per issuer (`FEDERATED` proposed). | A14-04/A14-06 |
| Q6 | JWT library/version confirmation (`pyjwt[crypto]>=2.13,<3`). | §10.1 |
| Q7 | Module-ownership reconciliation (`mtmf-core` vs `mtmf-service`) and whether the PR 12 ownership text must be amended. | §10.3 |
| Q8 | Approval of A14-01–A14-10 and §7–§10 overall. | all |
| Q9 | Exact `nbf` presence/tolerance rule and the `exp`-leeway prohibition confirmation. | §7/§10.2 |

## 12. Reviewer decision table

Approval is required for every row. “Evidence source” distinguishes
repository facts, official docs, and unverified items.

| ID | Proposed disposition | Evidence source | Remaining uncertainty | Approval required |
| --- | --- | --- | --- | --- |
| A14-01 | Adopt asymmetric resource-server validation; `leeway=0` at `exp` | Repo + PyJWT source + Keycloak docs | Algorithm subset; parse bounds | Yes |
| A14-02 | Distinct service/user profiles with distinct audiences | Track 2 observed Keycloak 26.8.0 dev profile (K01–K06, K18) | Production issuer profile/audience names | Yes |
| A14-03 | `(issuer, client_id)` → one Application; unique, immutable | PR 12 T6; repo persistence seams | Exact client-identity claim | Yes |
| A14-04 | `(issuer, sub)` → one `FEDERATED` Identity; operator-only | Repo identity/membership contracts | Per-issuer origin rule | Yes |
| A14-05 | Signed external user token mandatory; exchange contingency | Track 2 (signed token verified K02; exchange K13 blocked) | Whether T1 demands both modes | Yes |
| A14-06 | ACTIVE actor + explicit memberships + ordinary ACTIVE Tenant + ACTIVE registration | Repo domain/lifecycle contracts | None material | Yes |
| A14-07 | Issuer-validated same-client delegation; `azp` alone insufficient | OIDC Core; Track 2 K09/K10 (equality observed, no guarantee) | **Issuer guarantee missing → BLOCKED** | Yes |
| A14-08 | Root stays `LOCAL`; dedicated protected binding; phishing-resistant assurance | PR 10 invariants; Track 2 K15–K17 (generic `acr=1`, no `amr`) | **Assurance policy/value missing → BLOCKED** | Yes |
| A14-09 | Typed internal verifier/composer; sanitized errors; no public route | Plan/architecture | None material | Yes |
| A14-10 | Operator-only mutation; runtime read-only `SECURITY DEFINER`; additive `0011` | Repo privilege model (75-signature manifest) | New read signatures | Yes |
| §7 profiles | Claim matrices with per-field evidence status | Track 2 observed dev profile + official docs + PyJWT | Production profile values; K07/K13 not executed | Yes |
| §8 delegation | Refined same-client + `act` contingency | OIDC/RFC; Track 2 K09/K10/K13/K14 | **Blocked pending issuer guarantee** | Yes |
| §9 root model | Option A dedicated binding; option B fallback | PR 10 invariants; Track 2 K15–K17 | **Assurance blocked** | Yes |
| §10 dependency | `pyjwt[crypto]>=2.13,<3`; core/service split | Installed PyJWT; PR 12 text | Ownership reconciliation | Yes |

## 13. Decision-ready summary

**(a) Supportable for approval now (evidence sufficient; still not
approved).**

- A14-01 (trust model; `exp`-leeway prohibition from verified PyJWT
  behavior).
- A14-03 (credential → one Application), A14-04 (subject → one
  `FEDERATED` Identity), A14-06 (actor eligibility), A14-09 (internal
  API only), A14-10 (privilege posture).
- A14-02/§7 **for the Keycloak 26.8.0 development profile only**
  (observed payload `typ` + profile-specific audience; §17).
- §10.1 dependency constraint; §10.2 PyJWT/JWKS/time constraints.

**(b) Blocked by missing evidence (do not implement).**

- A14-05/A14-07/§8: same-client direct-token delegation lacks an
  issuer guarantee (observed `azp` equality is not a guarantee); the
  `act`/V2 exchange was not demonstrated and delegation is a Keycloak
  preview feature.
- A14-08/§9: phishing-resistant root assurance policy/values unverified;
  a password-only root login yielded only generic `acr=1` with no `amr`.
- A14-02/§7 production profile: the observed values are the development
  profile, not an approved production issuer profile.

**(c) Exact minimal choices required from the reviewer.**

1. Q1: confirm the v0.1 propagation scope (signed-only vs both modes).
2. Q2: provide either a documented issuer guarantee for same-client
   direct tokens, or approve the distinct-client + exchange alternative
   (and accept or reject the preview-feature dependency).
3. Q3: choose root option A vs B and supply the issuer-admin–documented
   phishing-resistant policy + ACR/AMR value(s), or confirm BLOCKED.
4. Q4/Q5: approve the per-issuer class predicates/audiences and the
   ordinary-user origin rule (requires a configured dev issuer profile).
5. Q6/Q7/Q9: confirm the JWT dependency, resolve the core/service
   ownership reconciliation, and confirm the `exp`/`nbf` policy.

## 14. STOP conditions

STOP and report before further coding if any of the following holds:

1. A14-01–A14-10, §7, §8, §9, or §10 lack explicit human approval.
2. Root `LOCAL` origin and external OIDC binding cannot be reconciled
   without changing PR 10 invariants, or root assurance is unspecified
   (currently **BLOCKED**).
3. Secure client-to-user delegation cannot be derived from verified
   issuer claims (currently **BLOCKED**).
4. The JWT library cannot enforce algorithm/key-type/issuer/audience/time
   and safe JWKS behavior.
5. Membership/Principal/Identity lifecycle semantics are ambiguous or
   incompatible with the proposed mapping.
6. A design requires runtime mapping writes, root/recovery mutation, raw
   table access, or unreviewed `SECURITY DEFINER` privileges.
7. A design requires editing migrations `0001`–`0010`, an HTTP endpoint,
   token minting, a token-exchange server, or Keycloak runtime
   orchestration.
8. A security-critical case cannot be tested against the real PostgreSQL
   topology.
9. `main` advanced with conflicting identity/authentication work.
10. Any mandatory gate fails without proven resolution.

## 14A. Human architecture decision — constrained D1 for v0.1 (2026-10-11)

**Decision: D1 SELECTED FOR v0.1 ARCHITECTURE; IMPLEMENTATION STILL BLOCKED.** The human reviewer explicitly selected constrained **same-client end-user access-token propagation**, not generic OAuth delegation, as the v0.1 direction. This supersedes §8's open D1-vs-D2-vs-D3 architecture choice but **does not** turn the observed `azp` equality in K09 into proof of delegation, approve an arbitrary Keycloak claim, or waive the PR 14 implementation gate.

### Exact scope and security semantics

1. A consuming application authenticates itself with a trusted-issuer OAuth 2.0 client-credentials access token. Its immutable `(issuer, client_id)` maps to exactly one MTMF Application.
2. The same OAuth client obtains a **user access token** through an approved interactive user-authentication flow. MTMF independently verifies its signature, issuer, audience, expiration, issued-at time, token class, and subject. ID tokens, refresh tokens, service tokens masquerading as user tokens, and caller-supplied Identity IDs are rejected.
3. The trusted issuer profile must **explicitly document and demonstrate** that its configured, signed user-access-token client-identity claim identifies the OAuth client to which the token was issued, and that the verified service-token client identity identifies the same client. MTMF checks these identities for equality **only after independent token validation**. A bare comparison of unqualified `azp` strings is not accepted as evidence of authority.
4. The D1 contract is **client-bound user context**, not RFC 8693 actor delegation or authority for one independent OAuth client to impersonate a user of another client. Both tokens must be legitimately obtained for the registered client; MTMF must not infer user consent, arbitrary delegation, or cross-client authority from matching text.
5. The verified `(issuer, sub)` resolves only through an operator-provisioned immutable Identity binding; ordinary user Identity origin remains `FEDERATED`. MTMF validates the active Identity, Principal, selected Tenant, explicit memberships, Application registration/subscription eligibility, and subsequent authorization independently. The calling application remains responsible for resource isolation.
6. Missing, ambiguous, unverified, or mismatched client identities; mismatched issuers/trust profiles; wrong audience or token class; expired tokens; inactive actors; and unsupported cross-client flows **fail closed**. Neither service credentials nor user tokens alone authorize an acting-user request.
7. RFC 8693 exchanged-token `act` chains, distinct-client delegation, and Keycloak preview delegation are **outside the v0.1 D1 implementation scope**. A later separately approved profile may introduce them; no silent fallback or preview-feature dependency is permitted.

### Required issuer evidence before D1 implementation

The development Keycloak fixture in `docs/PR14_KEYCLOAK_EVIDENCE.md` observes `azp` equality (K09), but the issuer guarantee and normative client-binding interpretation remain **UNVERIFIED**. Before implementing D1, the reviewer must approve an issuer-specific, signed access-token claim contract, with authoritative issuer documentation or explicit controlled issuer configuration and positive/negative issuer-backed evidence. If that cannot be established, **STOP**; do not substitute equality alone.

### Mandatory integration acceptance scenarios (not yet executed)

| ID | Scenario | Required outcome |
| --- | --- | --- |
| D1-01 | Valid client-credentials and user access tokens issued to the same registered client, with verified issuer-specific client-binding semantics | Accepted as authenticated client-bound context; authorization evaluated separately |
| D1-02 | Independently valid service and user tokens from different OAuth clients | Rejected |
| D1-03 | Matching client text from unverified/malformed JWT or unsupported claim | Rejected |
| D1-04 | Missing, multiple, or ambiguous client-identity claims | Rejected |
| D1-05 | User token used in service slot; service token in user slot; ID/refresh token in user slot | Rejected |
| D1-06 | Wrong service/user audience, untrusted issuer, bad signature, unknown key, expired token | Rejected |
| D1-07 | Same client but user binding absent/inactive, Tenant membership absent/inactive, Application registration/subscription ineligible | Rejected independently of token validity |
| D1-08 | Two valid same-client tokens with unrelated Tenant selection or cross-Tenant actor context | Rejected |
| D1-09 | Caller-supplied Identity/Principal UUID, service-signed assertion, or cross-client token-exchange substitution | Never accepted as authentication |
| D1-10 | Keycloak dev fixture re-created from clean state; observed signed claims and negative controls reproduced | Evidence recorded, secrets redacted |

These are **future PR 14 acceptance gates**, not Track 2 PASS claims. Use the actual configured issuer and MTMF production validation path when implementation is authorized; harness-only comparisons are diagnostic, not sufficient feature acceptance.

### Related decisions and outstanding STOPs

- **A14-05:** Signed external-issuer user access tokens are the selected v0.1 mechanism; RFC 8693 actor delegation is deferred. This is a scope choice, not full implementation approval.
- **A14-07:** D1 architecture selected; issuer-specific binding guarantee and end-to-end tests remain mandatory and currently blocked.
- **A14-08:** Option A (canonical `LOCAL` root plus protected external authentication binding) remains the target, but root authentication is **BLOCKED** pending verified phishing-resistant MFA policy and exact access-token assurance semantics. Option B (separate/defer root work) remains available by explicit decision.
- **A14-02/§7:** Profile-specific class predicates and audiences require explicit production-profile approval; observed development values are not automatically production defaults.
- **§10:** Explicit PyJWT dependency and provider-neutral core/service ownership must be reconciled with approved PR 12 wording before implementation.
- **JWT time:** `exp` is mandatory with zero positive expiration leeway; `iat` is mandatory; `nbf` is optional if the issuer omits it but must be validated when present, without extending `exp`.
- **Implementation gate:** No PR 14 authentication, migration, persistence, or HTTP code may be started on the strength of this addendum alone. Other A14 decisions and required contracts remain subject to the recorded approval gate.

### D1 issuer-specific client-binding contract (follow-up evidence, proposed)

**Evidence status: SOURCE-SUPPORTED + OBSERVED (development profile); NOT APPROVED.**

A D1 follow-up established whether a specific, configured Keycloak issuer
profile provides a defensible, verifiable contract binding a
client-credentials access token and an interactive user access token to the
same OAuth client. Full detail and exact source citations are in
[PR14_KEYCLOAK_EVIDENCE.md](PR14_KEYCLOAK_EVIDENCE.md) §6A.

- **Source-supported behavior (Keycloak 26.8.0):** the access-token `azp`
  claim is `JsonWebToken.issuedFor` and is set by
  `TokenManager.initToken` from `client.getClientId()`, where `client` is
  the **authenticated** OAuth client of the token request in both the
  client-credentials and authorization-code+PKCE flows. It is not a
  normative published issuer guarantee and must be revalidated on upgrade
  or for another issuer.
- **Observed and verified (development fixture):** DC01 same-client pair
  yields equal signature-verified `azp`; DC02 distinct clients differ;
  DC03/DC04/DC06 reject wrong audience, ID/refresh/swapped tokens, wrong
  issuer, bad signature, and an expired token; DC08 clean recreate
  reproduces the results. DC05 and DC07 are **NOT EXECUTED**.
- **Proposed contract:** independently verify both tokens (issuer,
  signature, algorithm/key, distinct audience, access-token class,
  `exp`/`iat`, `nbf` when present, zero positive expiry leeway), then
  require the verified service `azp` and user `azp` to name the same
  registered client, with no `azp`-overriding mapper and no token exchange
  or preview delegation. `(issuer, sub)` Identity binding and all MTMF
  domain gates remain separate.
- **Not delegation:** D1 remains client-bound user context. It does not
  prove user consent, RFC 8693 actor delegation, or cross-client authority.
  Bearer replay, separate-session acquisition, and client-credential trust
  remain residual risks.

**Reviewer decision requested:** approve, reject, or amend this specific
Keycloak 26.8.0 development D1 profile and the production issuer
version/configuration that will replace it. This follow-up records **no
approval**; the approval log below is unchanged and every entry remains
PENDING.

## 14B. Human review disposition — Keycloak 26.8.0 D1 development profile (2026-10-11)

**CONDITIONALLY APPROVED FOR DEVELOPMENT PROFILE ONLY.** Following the D1 follow-up report at commit `aa09b219afe96b4496b1d101f7e81fe1b826b8c5`, the reviewer authorized recording conditional acceptance of the pinned **Keycloak 26.8.0 development issuer profile** described in [PR14_KEYCLOAK_EVIDENCE.md](PR14_KEYCLOAK_EVIDENCE.md) §6A. This is a narrow **issuer-profile decision**, **not** approval of the production issuer, A14-01–A14-10 collectively, root authentication, or PR 14 implementation.

**Accepted basis:** In Keycloak 26.8.0 source, access-token `azp` maps to `issuedFor`, initialized from the authenticated token-request client; both client-credentials and authorization-code+PKCE paths were traced. DC01, DC02, DC03, DC04, DC06, and DC08 support the configured/observed behavior. This is **version-specific source-supported implementation behavior**, not a standards-level delegation guarantee.

**Binding conditions:**

1. Pin the exact Keycloak issuer version and immutable image digest for the development fixture; re-review source behavior, issuance evidence, and mapper configuration on upgrades or issuer changes.
2. For the D1 profile, require one registered confidential OAuth client with both service-account and authorization-code+PKCE flows enabled, with no `azp` override, token exchange, or preview actor delegation.
3. Validate service and user JWTs **independently** for allowed asymmetric algorithm/key, trusted issuer, distinct required audiences, access-token class, `exp` (zero positive leeway), `iat`, and `nbf` if present, then compare signed, unambiguous client identities. Reject absent/malformed/ambiguous claims and token swaps.
4. Authenticate the Application from the service client and resolve the user through protected `(issuer, sub)` Identity binding. Tenant, membership, subscription, and policy authorization are independent checks. D1 is **client-bound user context**, not consent, cross-client delegation, or an RFC 8693 actor chain.
5. DC05 (signed token missing `azp`) and DC07 (real MTMF domain binding) remain **NOT EXECUTED**; require fail-closed verifier and integration tests before feature acceptance. Harness-only checks are not sufficient.
6. Document and accept residual bearer replay, separate-session token acquisition, and client-credential compromise risks; this approval does not claim proof of same request/session.

**Outstanding reviewer decisions (do not infer approval):** production issuer/version and configuration; production audience/class profile; A14-01–A14-10 and §§7–10 as a whole; ordinary-user IdentityOrigin rule; dependency/ownership reconciliation; root Option A vs explicit separation/defer, plus phishing-resistant root assurance. The root Option A architecture remains a target, **not a production authentication approval**.

**Gate:** PR 14 production code, migration `0011`, API changes, and root authentication remain **STOPPED**. An explicitly scoped, separately approved implementation gate is required.

## 14C. Human decision — defer root authentication to subsequent PR (2026-10-11)

**APPROVED SCOPE SPLIT:** PR 14 may target ordinary service authentication and constrained D1 user-context propagation **only after its remaining non-root security gates are explicitly approved**. Root authentication is deferred to a separate future PR. This is a scope decision, **not** authorization to implement PR 14.

- The canonical built-in root Identity remains `LOCAL`, with the protected external authentication binding architecture (Option A) reserved for the future root PR. This does not permit changing its origin, creating a second root, or silently substituting an ordinary `FEDERATED` Identity.
- **Fail closed:** PR 14 must not provide an external or ordinary-user authentication path to the root Identity, root Principal, root privileges, or root-only operations. Root identities must never be eligible through D1 `(issuer, sub)` ordinary-user resolution, even if a token otherwise verifies. No fallback password, MFA downgrade, impersonation, privileged bootstrap bypass, or public root endpoint.
- The separate root PR must define and verify issuer-enforced phishing-resistant authentication, exact access-token assurance claims, protected immutable root binding, and negative/downgrade tests before root authentication is enabled.
- Existing separately governed operator recovery/bootstrap mechanisms are **not** modified or implicitly authorized by this scope split. If PR 14 requires root authentication to execute its ordinary-user paths, **STOP** and report the architectural dependency.
- The original PR 14 acceptance matrix must be partitioned explicitly into ordinary service/user requirements and deferred root-only requirements, preserving all root requirements as tracked obligations rather than silently deleting them.
- This decision resolves **A14-08 scope for PR 14 only**; it does not approve the future root implementation or override other A14 approvals. The production issuer, claim profile, client-binding contract, dependency/ownership split, and non-root implementation approval remain pending.


## 14D. Approved PR 12 T1 reconciliation (2026-10-11)

The human reviewer approved the narrow v0.1 T1 amendment recorded in `PR12_INTEGRATION_SECURITY_DECISIONS.md` (commit `db470bebc4968a897bc30d10875a1611dfbf7109`). Constrained D1 may supply issuer-bound same-client user context without an RFC 8693 actor chain, subject to independent verification of both tokens, explicit issuer client-binding semantics, cross-client rejection, and independent Application, Identity, Tenant membership, subscription and policy gates. This is not consent, cross-client delegation, or a per-request actor-chain proof. The prohibition on arbitrary service-signed identity assertions remains. Distinct-client delegation requires a separately approved standards-based mechanism. Root remains excluded and fail-closed. **Production issuer, full non-root approval, and implementation remain PENDING.**

## 14E. Human decision — development-first PR 14 scope (2026-10-11)

**APPROVED SCOPE ONLY; IMPLEMENTATION AUTHORIZATION NOT YET GRANTED.** The reviewer selected a development-first PR 14 implementation targeting the pinned, conditionally approved **Keycloak 26.8.0 local development issuer profile**. A separately specified and validated production issuer profile is deferred. This does not imply that development fixture settings, loopback issuer URL, TLS material, audience values, or client secrets are suitable for production.

- Design the trust-profile configuration and verifier boundaries to accommodate a separately approved production issuer later; do not invent production issuer settings or implicitly allow arbitrary issuers.
- Only the exact configured development issuer and approved signed service/user access-token profiles are eligible. Fail closed for unknown issuer, audience, token class, algorithm, client binding, or trust configuration.
- Before production authentication code is authorized, close the outstanding **non-root** A14 security decisions, §7 token-class predicates (including reliable issuer-backed service-account vs human-user discrimination), §10 ownership/dependency rules, and any remaining approval conditions. A development-first scope decision is **not** a blanket waiver of these gates.
- Retain the amended PR 12 T1 constrained D1 model: independently verified same-client service and user tokens, plus independent MTMF Application, Identity, Tenant, subscription and policy gates; no cross-client delegation.
- Root authentication remains deferred and fail-closed. DC05/DC07 and all applicable non-root AUTH acceptance scenarios must be completed before declaring the feature accepted.
- **Deployment gate:** no production rollout or production issuer trust may be enabled until its issuer-specific profile, configuration, key-management and security evidence receive separate human approval.

### G0-A class-predicate reconciliation (evidence only, 2026-10-11)

Gate G0-A tested whether the pinned Keycloak 26.8.0 development fixture
provides a signed, issuer-backed predicate distinguishing client-credentials
service tokens from interactive user tokens. Evidence:
[PR14_G0_NONROOT_EVIDENCE_REPORT.md](PR14_G0_NONROOT_EVIDENCE_REPORT.md).

- **G0-T01–T08, T10 PASS:** a candidate predicate (service = `typ=Bearer` +
  `client_id` present and `client_id == azp`; user = `typ=Bearer` + `azp` +
  `sub` and no `client_id`) classifies genuine tokens correctly and rejects
  wrong-audience, both-audience, missing-`client_id`, ID/refresh, and
  different-client cases; a clean recreate reproduces the results.
- **G0-T09 FAIL:** a realm `oidc-hardcoded-claim-mapper` injects `client_id`
  and overrides `azp` in a signed user token, after which the user token
  passes the service predicate. The predicate is configuration-dependent,
  not non-spoofable.
- **Status:** `A14-02`/§7 class-predicate evidence is **BLOCKED for
  unconditional acceptance**; `typ=Bearer` + audience is insufficient. The
  reviewer must choose a disposition (mapper-profile lockdown + attestation,
  distinct clients, or issuer introspection) before implementation.

This note records evidence only. It does not approve any decision; the
approval log below is unchanged and every entry remains PENDING.

## 14F. Human decision — G0-A option 1 selected (2026-10-11)

**APPROVED ARCHITECTURAL DIRECTION, NOT TOKEN-CLASS ACCEPTANCE OR IMPLEMENTATION AUTHORIZATION.** Preserve D1 same-client propagation and use a locked, attested Keycloak 26.8.0 development issuer mapper configuration. The candidate service predicate (signed access-token `typ=Bearer`, `client_id` present and equal to signed `azp`) is **conditional**, not yet approved as a sufficient authentication predicate. G0-T09 demonstrated that a realm hardcoded-claim mapper can make a user token satisfy it.

A follow-up **G0-A remediation evidence gate** must:
- Define an exact canonical realm/client/client-scope/protocol-mapper configuration allowlist, including inherited/default/optional scopes and mapper precedence; prohibit any unauthorized override of security-critical claims, including `client_id`, `azp`, `sub`, `typ` and audience.
- Specify an independently controlled configuration-integrity attestation and deployment/runtime trust gate. An untrusted realm-admin assertion or a hash stored alongside mutable configuration is insufficient by itself. Identify who can mutate issuer configuration and how drift is detected **before authentication is enabled or continued**; if continuous detection cannot be established, document and obtain review of the resulting risk.
- Execute adversarial issuer tests reproducing G0-T09, demonstrating that forbidden mapper changes are rejected or detected and cause fail-closed behavior; demonstrate genuine service/user token acceptance, wrong-class rejection, and clean fixture recreation.
- Record the precise evidence and residual administrative-compromise risk; do not claim that JWT signatures alone guarantee grant type.
- Stop after documentation, fixture hardening and evidence. No production authentication verifier, migration, API, runtime grants or root behavior may be implemented until the remaining security approvals and explicit authorization.

**Unchanged:** development-first only; production issuer deferred; root authentication deferred and fail-closed; §10 ownership reconciliation and remaining non-root approvals pending.

## 15. Approval log

All rows are **PENDING HUMAN REVIEW**. No decision is approved.

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| A14-01 | PENDING HUMAN REVIEW | — | — | — |
| A14-02 | PENDING HUMAN REVIEW / PREDICATE EVIDENCE MISSING | — | — | — |
| A14-03 | PENDING HUMAN REVIEW | — | — | — |
| A14-04 | PENDING HUMAN REVIEW | — | — | — |
| A14-05 | PENDING HUMAN REVIEW / SCOPE OPEN | — | — | — |
| A14-06 | PENDING HUMAN REVIEW | — | — | — |
| A14-07 | D1 SELECTED; KEYCLOAK DEVELOPMENT CLIENT-BINDING PROFILE CONDITIONALLY APPROVED; PRODUCTION/IMPLEMENTATION BLOCKED | Human reviewer (conversation) | 2026-10-11 | §§14A–14B |
| A14-08 | ROOT AUTHENTICATION DEFERRED TO FUTURE PR; PR 14 MUST FAIL CLOSED FOR ROOT | Human reviewer (conversation) | 2026-10-11 | §14C |
| A14-09 | PENDING HUMAN REVIEW | — | — | — |
| A14-10 | PENDING HUMAN REVIEW | — | — | — |
| §7 claim profiles | KEYCLOAK 26.8.0 DEVELOPMENT D1 PROFILE CONDITIONALLY APPROVED; PRODUCTION PROFILE PENDING | Human reviewer (conversation) | 2026-10-11 | §14B; PR14_KEYCLOAK_EVIDENCE §6A |
| §8 delegation contract | D1 DEVELOPMENT PROFILE CONDITIONALLY APPROVED; PRODUCTION CONTRACT AND IMPLEMENTATION PENDING | Human reviewer (conversation) | 2026-10-11 | §§14A–14B |
| §9 root model | PENDING HUMAN REVIEW / BLOCKED ON ASSURANCE | — | — | — |
| §10 dependency/ownership | PENDING HUMAN REVIEW / RECONCILIATION OPEN | — | — | — |

## 16. Post-approval implementation outline (not started)

Only after §15 is approved: immutable trust contracts (Part 1); trusted
token verifier with bounded JWKS (Part 2); additive `0011` mapping
persistence, stored functions, and restricted runtime reads (Part 3);
verified actor composition reusing PR 13 (Part 4); configuration and
composition seam (Part 5); documentation and final gates (Part 6). The
mandatory acceptance matrix `AUTH-01`–`AUTH-36` and the real-PostgreSQL
privilege gates apply.

## 17. Track 2 observed issuer evidence (addendum, no approval)

Full detail: [PR14_KEYCLOAK_EVIDENCE.md](PR14_KEYCLOAK_EVIDENCE.md).
Isolated Keycloak `26.8.0` (`quay.io/keycloak/keycloak:26.8.0-1`, digest
`sha256:27b3230f...`), loopback-only, no MTMF database or runtime role.

**Observed and verified (development profile).** Service and interactive
user access tokens are signed RS256 with payload `typ=Bearer`, distinct
profile audiences, and `azp` naming the obtaining client. ID tokens use
`typ=ID`; refresh tokens are HS512 JWTs with payload `typ=Refresh`.
`exp`/`iat` are present and `nbf` is absent. A malformed token fails
closed. Clean `down -v` recreate reproduces the results. Only
`mtmf-pr14-keycloak` resources were touched.

**Still blocked.** Same-client `azp` equality was observed but is not a
documented delegation guarantee (D1 blocked); Standard Token Exchange V2
was not demonstrated (D3 blocked); actor delegation is a preview feature;
root phishing-resistant assurance was not established (generic `acr=1`,
no `amr`).

**Effect on this register.** Only the evidence statuses in A14-02, A14-05,
A14-07, A14-08, and §7–§9 are updated. No decision is approved; the
approval log in §15 remains **PENDING HUMAN REVIEW**, and PR 14
implementation remains stopped.
