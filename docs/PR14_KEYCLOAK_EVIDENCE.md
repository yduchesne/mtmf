# PR 14 Track 2 — Keycloak issuer profile and security-contract evidence

> **STATUS: EVIDENCE ONLY. NOT AN APPROVAL. NOT PR 14 IMPLEMENTATION.**
>
> This report records reproducible, sanitized observations from an isolated
> local Keycloak development fixture. It supports — but does not grant —
> review of PR 14 decisions `A14-02`, `A14-05`, `A14-07`, and `A14-08`.
> The human approval gate in
> [`PR14_AUTHENTICATION_SECURITY_DECISIONS.md`](PR14_AUTHENTICATION_SECURITY_DECISIONS.md)
> remains fully in force, and every decision there remains
> **PENDING HUMAN REVIEW**. No MTMF authentication, persistence, HTTP,
> migration, or runtime code exists or is approved as a result of this work.

**Dominant invariant.** Every proposed authentication and delegation
contract must be supported by an observed, reproducible access-token behavior
from a configured issuer, not by guessed claim semantics. Where that evidence
is absent, the contract stays BLOCKED.

## 1. Environment and topology

| Item | Value |
| --- | --- |
| Issuer image | `quay.io/keycloak/keycloak:26.8.0-1` |
| Image digest | `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Server version | `Keycloak 26.8.0` (Quarkus 3.40.1, dev profile) |
| Runtime | rootless Podman 4.9.3 + podman-compose 1.0.6 |
| Compose project | `mtmf-pr14-keycloak` (explicit; isolated file `dev/keycloak/compose.yaml`) |
| Host ports | loopback only: `127.0.0.1:28080 -> 8080`, `127.0.0.1:28443 -> 8443` |
| TLS | operator-generated self-signed cert under `/tmp/mtmf-pr14-kc-tls` (not committed) |
| Issuer URL | `https://127.0.0.1:28443/realms/mtmf-pr14-dev` |
| Fixture commit | branch `dev/service-auth` (see §9 for exact SHAs) |
| Sanitized artifact | `dev/keycloak/evidence/pr14-keycloak-evidence.json`, SHA-256 `1ec148e41718474ffb94f0674a419efa8368622135e3ea7f09392109bc84f454` |
| Config manifest | `dev/keycloak/evidence/pr14-keycloak-config-manifest.json`, SHA-256 `476ecdf7f02f4276145fb71b96035100d26fd11e8e6c46aef30d7122d687276e` |
| G0 class-predicate artifact | `dev/keycloak/evidence/pr14-g0-token-class-evidence.json`, SHA-256 `2b0807df2fa0a104743e8e52dd6de939abc3e1c0a9737293d2b3ec393737a7f6` |

The fixture is development-only. Keycloak is not a mandated production issuer;
the PR 14 configuration remains provider-neutral. No raw token, refresh token,
client secret, password, private key, session cookie, or PII is committed.

## 2. Exact commands

```bash
git fetch origin
git status --short
git rev-parse HEAD origin/main origin/dev/service-auth

# isolated fixture (see dev/keycloak/README.md for cert + secret setup)
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml --env-file /tmp/mtmf-pr14-kc.env up -d
set -a; . /tmp/mtmf-pr14-kc.env; set +a
uv run --no-sync python scripts/pr14-keycloak-evidence.py wait
uv run --no-sync python dev/keycloak/setup-realm.py
uv run --no-sync python scripts/pr14-keycloak-evidence.py collect \
  --report dev/keycloak/evidence/pr14-keycloak-evidence.json
```

Clean recreate (K22): `podman-compose ... down -v` followed by the same
`up`/`wait`/`setup`/`collect` sequence succeeded and reproduced the same
results.

## 3. Evidence classification

- **OFFICIAL-DOC** — stated by version-matched official documentation.
- **CONFIGURED** — set at runtime in the isolated fixture.
- **OBSERVED-VERIFIED** — token issued by the issuer and its signature,
  issuer, audience, and time validated against the issuer JWKS.
- **OBSERVED-UNVERIFIED** — decoded only, signature not asserted.
- **NOT EXECUTED** — not run in this environment.
- **BLOCKED** — a required security property could not be established.

A negative assertion made by the harness itself (for example a proposed
predicate rejecting the wrong token class) is distinguished from an actual
issuer rejection.

## 4. Evidence matrix (K01–K24)

| ID | Status | Classification | Observed result / pointer |
| --- | --- | --- | --- |
| K01 | PASS | CONFIGURED, OBSERVED-VERIFIED | Service client-credentials token: RS256, `typ=Bearer`, `aud=[mtmf-service-api, account]`, `azp=mtmf-evidence-service`; signature verified |
| K02 | PASS | CONFIGURED, OBSERVED-VERIFIED | Interactive user token via Authorization Code + PKCE: RS256, `typ=Bearer`, `aud=[mtmf-user-api, mtmf-evidence-exchange, account]`, `azp=mtmf-evidence-user`, stable `sub`, `sid`, `acr=1`; signature verified |
| K03 | PASS | CONFIGURED, OBSERVED-VERIFIED | Service token lacks the user audience; proposed user profile rejects it (harness assertion) |
| K04 | PASS | CONFIGURED, OBSERVED-VERIFIED | User token lacks the service audience; proposed service profile rejects it (harness assertion) |
| K05 | PASS | CONFIGURED, OBSERVED-VERIFIED | ID token `typ=ID`, `aud="mtmf-evidence-user"` (client id, not the user API audience) |
| K06 | PASS | CONFIGURED, OBSERVED-VERIFIED | Refresh token is a JWT with payload `typ=Refresh` and JOSE `alg=HS512`; never used as evidence |
| K07 | NOT EXECUTED | CONFIGURED | No misconfigured-audience control run; the missing-audience property is covered by K03/K18 |
| K08 | PASS | CONFIGURED, OBSERVED-VERIFIED | Service client identity is carried as `azp=mtmf-evidence-service` |
| K09 | PASS | CONFIGURED, OBSERVED-VERIFIED | Same-client fixture: service `azp` == user `azp` == `mtmf-evidence-same-client` (recorded; equality is not treated as delegation proof) |
| K10 | PASS | CONFIGURED, OBSERVED-VERIFIED | Different-client control: service `azp=mtmf-evidence-service`, user `azp=mtmf-evidence-user` |
| K11 | PASS | CONFIGURED, OBSERVED-VERIFIED | Two independently valid tokens with different `azp` are not described as delegation |
| K12 | OFFICIAL-DOC / BLOCKED | OFFICIAL-DOC | Keycloak 26.8.0 does not document access-token `azp` as a client-to-user delegation guarantee; OIDC Core defines `azp` for ID tokens only. No issuer guarantee found |
| K13 | BLOCKED | CONFIGURED | Standard Token Exchange V2 attempt failed: HTTP 400 `Requested audience not available: mtmf-evidence-exchange`. The target client audience was present in the subject token; V2 preconditions were not otherwise satisfied |
| K14 | BLOCKED | OFFICIAL-DOC | Keycloak `act`/`may_act` delegation is Preview/disabled-by-default in 26.8.0; not enabled |
| K15 | BLOCKED | CONFIGURED | No issuer-enforced phishing-resistant authentication flow is configured; WebAuthn/passkey enrollment is a manual prerequisite |
| K16 | NOT EXECUTED | CONFIGURED | High-assurance WebAuthn login cannot be completed headlessly |
| K17 | PASS | CONFIGURED, OBSERVED-VERIFIED | Password-only root login yields only `acr=1`, no `amr`, `typ=Bearer` — generic assurance, not phishing resistance |
| K18 | PASS | CONFIGURED, OBSERVED-VERIFIED | Each profile's expected audience present; no cross-profile audience. Shared Keycloak default `account` present in both |
| K19 | PASS | CONFIGURED, OBSERVED-VERIFIED | `exp` present; verification uses `leeway=0` (no expiry extension) |
| K20 | PASS | CONFIGURED, OBSERVED-VERIFIED | `iat` present; `nbf` absent in issued access tokens |
| K21 | PASS | CONFIGURED, OBSERVED-VERIFIED | JWKS served at configured `jwks_uri`; token `kid` matched a served key; key rotation not performed |
| K22 | PASS | CONFIGURED, OBSERVED-VERIFIED | Clean `down -v` + recreate + setup reproduced the results |
| K23 | PASS | CONFIGURED, OBSERVED-VERIFIED | Malformed token rejected (`DecodeError`); no token contents leaked |
| K24 | PASS | CONFIGURED, OBSERVED-VERIFIED | Only `mtmf-pr14-keycloak` container/volume/network touched; ATI and MTMF PostgreSQL resources untouched |

## 5. Observed issuer claim matrix (Keycloak 26.8.0 dev profile)

These are **observations of this fixture**, not a universal Keycloak
guarantee and not approved MTMF production values.

| Claim | Service (client_credentials) | User (auth code + PKCE) | ID token | Refresh token |
| --- | --- | --- | --- | --- |
| `iss` | `https://127.0.0.1:28443/realms/mtmf-pr14-dev` | same | same | same |
| `aud` | `[mtmf-service-api, account]` | `[mtmf-user-api, mtmf-evidence-exchange, account]` | `"mtmf-evidence-user"` (string) | realm (per Keycloak docs) |
| `azp` | `mtmf-evidence-service` | `mtmf-evidence-user` | `mtmf-evidence-user` | n/a |
| payload `typ` | `Bearer` | `Bearer` | `ID` | `Refresh` |
| JOSE header `typ` | `JWT` | `JWT` | `JWT` | `JWT` |
| JOSE `alg` | `RS256` | `RS256` | `RS256` | `HS512` |
| `exp` / `iat` | present / present | present / present | present / present | present |
| `nbf` | absent | absent | absent | absent |
| `acr` | `1` | `1` | `1` | — |
| `amr` | absent | absent | absent | — |

**Service/user token-class predicate candidate (proposed, profile-specific):**
payload `typ` is `Bearer` for both access-token classes, so `typ` alone does
**not** separate service from user; the profile-specific audience does. ID and
refresh tokens are distinguishable by payload `typ` (`ID`, `Refresh`).
`azp` names the client that obtained the token. None of this is an approved
delegation guarantee.

## 6. Delegation decision table (D1/D2/D3)

| Option | Trust assumption | Issuer evidence | Application/Tenant binding | Confused-deputy risk | Disposition |
| --- | --- | --- | --- | --- | --- |
| **D1** Same-client direct token | The issuer signed the user access token for the verified calling client | Source-supported: Keycloak 26.8.0 sets access-token `azp` from the authenticated OAuth client in both flows (§6A); observed: same-client `azp` equality (K09/DC01) | `(issuer, sub)` → Identity, then explicit memberships; Application from the service token | `azp` does not bind a request or prove consent; bearer replay and same-client-session risks remain (§6A) | **SELECTED FOR v0.1; ISSUER PROFILE PROPOSED, NOT APPROVED** (reviewer decision in §10) |
| **D2** Distinct-client direct token with issuer-authorized delegation | An issuer-supported, cryptographically verified claim names the calling service client | None found | Same as D1 | Highest if unverified | **BLOCKED** |
| **D3** RFC 8693 exchanged token | A stable exchanged token carries an `act` actor chain | Standard V2 documented but the fixture exchange failed (K13); actor delegation is Preview (K14) | Exchanged-token audience + actor chain | Depends on preview feature | **BLOCKED** |

**Recommendation.** The D1 architecture was selected by the human reviewer
(see the decision register §14A). Evidence now supports a **Keycloak
26.8.0 development** client-binding contract (§6A), but it is **not an
approved issuer contract**: the source behavior is not a normative issuer
guarantee and must be revalidated on upgrade or for another issuer. D2
and D3 remain BLOCKED.

## 6A. D1 issuer-specific client-binding contract (proposed, not approved)

This section answers the D1 follow-up question: whether a specific,
configured Keycloak issuer profile provides a defensible, verifiable
contract binding a client-credentials access token and an interactive user
access token to the **same** OAuth client. It does **not** claim general
OAuth delegation, user consent, or RFC 8693 actor delegation.

### 6A.1 Provenance and classification

| Source | Exact reference | What it establishes |
| --- | --- | --- |
| Keycloak 26.8.0 source | `core/.../representations/JsonWebToken.java`: `public static final String AZP = "azp"`; `@JsonProperty(AZP) protected String issuedFor;` | The access-token `azp` claim is the token's `issuedFor` value. |
| Keycloak 26.8.0 source | `services/.../protocol/oidc/TokenManager.java`: `initToken(...)` sets `token.issuedFor(client.getClientId())`; `createClientAccessToken(...)` calls `initToken`; `AccessTokenResponseBuilder.generateAccessToken()` calls `createClientAccessToken(..., client, ...)` | `azp` is set from the response builder's client. |
| Keycloak 26.8.0 source | `services/.../protocol/oidc/grants/OAuth2GrantTypeBase.java`: `this.client = context.client`; `checkClient()` sets `client = AuthorizeClientUtil.authorizeClient(...).getClient()`; `createTokenResponseBuilder` calls `createClientAccessToken(..., client, ...)` | In both flows the client is the **authenticated** OAuth client of the token request. |
| Keycloak 26.8.0 source | `services/.../grants/ClientCredentialsGrantType.java`: rejects bearer-only/public clients, requires `isServiceAccountsEnabled()`, creates the service-account user session for that client | Client-credentials `azp` is the confidential service-account client. |
| Keycloak 26.8.0 source | `services/.../grants/AuthorizationCodeGrantType.java`: `if (!client.getClientId().equals(clientSession.getClient().getClientId()))` rejects | The authenticated client must equal the code's client, so `azp` is that client. |
| OpenID Connect Core 1.0 | `azp` is defined for ID Tokens; access-token `azp` is not normatively defined | Access-token `azp` is a Keycloak implementation behavior, not a standards guarantee. |

**Classification:** access-token `azp` = obtaining client is
**source-supported implementation behavior** for Keycloak 26.8.0, and
**configured/observed** in this fixture. It is **not** a normative
published issuer guarantee, so it must be revalidated on Keycloak
upgrade and for any non-Keycloak issuer.

### 6A.2 Proposed contract and preconditions (development profile)

1. **Issuer:** exact configured `iss` (this fixture:
   `https://127.0.0.1:28443/realms/mtmf-pr14-dev`).
2. **Token class:** both must be signed access tokens with payload
   `typ=Bearer` (not `ID`, not `Refresh`).
3. **Signing:** asymmetric (`RS256` in this fixture); verify against the
   issuer JWKS; zero positive `exp` leeway; require `exp` and `iat`;
   validate `nbf` when present.
4. **Distinct audiences:** the service token must contain the configured
   service audience; the user token the configured user audience.
5. **Client binding:** the signature-verified `azp` of the service token
   identifies the registered credential `(issuer, client_id)`; the
   signature-verified `azp` of the user token must identify the **same**
   client. Both tokens must be independently valid before comparison.
6. **Client configuration:** one confidential client with **both**
   service-account (client credentials) and standard
   authorization-code+PKCE enabled; the authenticated token-request client
   must match the code's client (issuer-enforced).
7. **No overrides:** no protocol mapper may add or override `azp`; no
   token exchange, no `act`/`may_act` delegation, and no Keycloak preview
   feature may be enabled for a client in this profile. An exchanged
   token is out of scope and must be rejected.
8. **Domain gates (separate):** `(issuer, sub)` → operator-provisioned
   Identity; active Principal/Identity/Tenant, explicit memberships,
   Application registration and subscription eligibility, and policy
   evaluation remain independent MTMF gates.

### 6A.3 Security argument (what D1 does and does not establish)

- **(a) Authenticated calling client.** The service access token is
  signature-verified and its `azp` maps to exactly one registered
  Application. It authenticates the *client*, not a user or Tenant.
- **(b) Issuer-bound user token obtained by the same client.** The user
  access token is independently signature-verified with the user
  audience and class; its `azp` is the same client. This supports a
  **client-bound user context**: the user token was issued to the same
  client that authenticated the service request. It does **not** prove
  user consent, delegation, or authority to act for the subject.
- **(c) MTMF domain authorization.** Identity binding, membership,
  Tenant/Organization, registration, subscription, and Action policy are
  separate gates. Neither token alone produces an `ALLOW`.

### 6A.4 DC evidence (this fixture)

| ID | Status | Evidence |
| --- | --- | --- |
| DC01 | PASS | One configured client obtains a client-credentials token and an auth-code+PKCE user token; both independently JWKS-verified; `azp` equal (`mtmf-evidence-same-client`) |
| DC02 | PASS | Distinct clients produce distinct verified `azp`; pairing rejected by the proposed predicate (harness) |
| DC03 | PASS | Service token against user audience and user token against service audience rejected by the verifier (audience check) |
| DC04 | PASS | ID token (`typ=ID`) and refresh token (`typ=Refresh`, HS512) rejected; swap covered by DC03 |
| DC05 | NOT EXECUTED | No issuer-backed signed access token without `azp` was produced; only a harness predicate was checked |
| DC06 | PASS | Wrong issuer (`InvalidIssuerError`), tampered signature (`InvalidSignatureError`), and an expired short-lived token (`ExpiredSignatureError`) rejected by the verifier |
| DC07 | NOT EXECUTED | The issuer fixture cannot prove Identity/Tenant/Application/subscription binding; that is future PR 14 acceptance scope |
| DC08 | PASS | Clean `down -v` recreate reproduced DC01–DC06 |

DC03/DC04/DC06 are **verifier-boundary** rejections; the issuer issued the
expired token in DC06. DC02/DC05 are **harness predicate** assertions, not
issuer-enforced checks. No synthetic unsigned JWT is counted as
issuer-backed evidence.

### 6A.5 Residual risks and revalidation requirements

- **Bearer replay:** `azp` binds the token to a client, not to a request.
  Valid stolen tokens can be replayed; TLS, short expiry, redaction, and
  future holder-of-key/DPoP (if approved) are mitigations.
- **Same-client separate sessions:** the user token may have been obtained
  in an unrelated session; D1 accepts this as the selected model.
- **No actor chain:** unlike RFC 8693 `act`, `azp` cannot show that the
  client acted *for* the user in this call.
- **Client trust:** the client credential is the trust anchor; its
  compromise permits obtaining both token classes.
- **Version/config coupling:** the behavior is source-supported, not
  contractual; revalidate on every Keycloak upgrade, and require a new
  issuer-specific review for any other issuer.
- **Mapper/exchange coupling:** custom `azp` mappers or enabled token
  exchange invalidate the contract; the profile forbids both.

### 6A.6 Reviewer decision requested

Approve, reject, or amend this **specific** Keycloak 26.8.0 development D1
profile (and the production issuer version/config that will replace it).
This document records no approval; the register approval log is unchanged.

## 6B. G0-A token-class follow-up (BLOCKED)

Gate G0-A asked whether the pinned fixture provides a signed,
issuer-backed predicate distinguishing client-credentials service tokens
from interactive user tokens. Full detail:
[PR14_G0_NONROOT_EVIDENCE_REPORT.md](PR14_G0_NONROOT_EVIDENCE_REPORT.md).

- Candidate predicate: service = `typ=Bearer` + `client_id` present and
  `client_id == azp`; user = `typ=Bearer` + `azp` + `sub` and no `client_id`.
  The `client_id` claim is produced by the built-in `service_account`
  client-scope `oidc-usersessionmodel-note-mapper` from the session note
  set only by `ClientCredentialsGrantType`.
- G0-T01–T08 and T10 PASS: genuine tokens classify correctly; wrong-audience,
  both-audience, missing-`client_id`, ID/refresh, and different-client cases
  fail closed; a clean recreate reproduces the results.
- **G0-T09 FAIL:** a realm `oidc-hardcoded-claim-mapper` injects `client_id`
  and overrides `azp` in a signed user token, after which the user token
  passes the service predicate. The predicate is therefore
  **configuration-dependent, not non-spoofable**.
- **Verdict: G0-A BLOCKED for unconditional acceptance.** `typ=Bearer` +
  audience is insufficient. Selecting a defensible predicate (issuer
  mapper-profile lockdown + attestation, distinct clients, or issuer
  introspection) is a reviewer decision in the G0 report §2.5/§7.

## 7. Root assurance disposition

- Option A (canonical `LOCAL` root Identity + dedicated protected
  `(issuer, sub)` binding) remains the recommended architecture.
- Observed: a password-only root login yields `acr=1`, no `amr`. This is
  generic realm assurance and does **not** establish phishing resistance
  (K17). No WebAuthn/passkey flow was configured or exercised (K15/K16).
- Therefore root assurance is **BLOCKED**. The smallest decision is an
  issuer-admin–documented authentication flow policy requiring a
  phishing-resistant authenticator for the root account and the exact
  `acr`/`amr` value(s) it emits in the **access token**, with evidence.
- Option B (defer/split root authentication, PR 14 incomplete on root) remains
  the explicit fallback.

## 8. Harness limitations and caveats

- `podman-compose` echoes the substituted `podman run` command, which can
  print the bootstrap admin password. Fixture startup output must be
  redirected and treated as sensitive; the collector itself prints no secrets.
- The self-signed dev key must be readable by the container user and is
  intentionally relaxed to `644` under `/tmp`; it is disposable and uncommitted.
- Key rotation was not performed (K21); only key selection was verified.
- K07's deliberate misconfiguration, K13's exchange preconditions, and
  WebAuthn enrollment are not executed and must not be counted as PASS.

## 9. Provenance

- Branch `dev/service-auth`; base `origin/main` `1924143ea504a9c291d695d154e9537cdb61969e`.
- Track 2 evidence was collected after a clean fixture recreate on the pinned
  image above; the D1 follow-up added DC01–DC08 and was also validated by a
  clean recreate.
- Keycloak source citations are pinned to the `26.8.0` tag (§6A.1).
- Sanitized artifacts and their SHA-256 hashes are recorded in §1.
- All K-experiments were executed with the `mtmf_runtime`-unrelated, isolated
  development issuer; no MTMF database or runtime role was involved.

## 10. Reviewer decision request

This evidence does not approve anything. The reviewer is asked to decide:

1. `A14-02`/§7: accept the observed Keycloak 26.8.0 token-class predicate
   (payload `typ` + profile-specific audience) as the *development* profile, or
   require a different issuer/profile.
2. `A14-05`: confirm signed external user tokens as the v0.1 mechanism, with
   token exchange as a contingency.
3. `A14-07`/§8: resolve D1/D2/D3; D1 requires an explicit issuer guarantee.
4. `A14-08`/§9: choose option A or B and supply the phishing-resistant
   assurance policy/value, or confirm the root work is blocked.
