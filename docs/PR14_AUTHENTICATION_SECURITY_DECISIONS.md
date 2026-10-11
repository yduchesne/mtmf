# PR 14 — Service Authentication and Verified Acting-User Security Decisions

> **STATUS: PROPOSED — PENDING HUMAN REVIEW. NOT APPROVED.**
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
| A14-07 | PENDING HUMAN REVIEW / BLOCKED ON ISSUER GUARANTEE | — | — | — |
| A14-08 | PENDING HUMAN REVIEW / BLOCKED ON ROOT ASSURANCE | — | — | — |
| A14-09 | PENDING HUMAN REVIEW | — | — | — |
| A14-10 | PENDING HUMAN REVIEW | — | — | — |
| §7 claim profiles | PENDING HUMAN REVIEW / PARTIALLY UNVERIFIED | — | — | — |
| §8 delegation contract | PENDING HUMAN REVIEW / BLOCKED | — | — | — |
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
