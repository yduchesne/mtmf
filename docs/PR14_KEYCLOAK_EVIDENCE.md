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
| Sanitized artifact | `dev/keycloak/evidence/pr14-keycloak-evidence.json`, SHA-256 `51bc97f590f059a550677effde8fd767507247173a4f8311df315f05b609579c` |
| Config manifest | `dev/keycloak/evidence/pr14-keycloak-config-manifest.json`, SHA-256 `3ef835f115cef757bdb7e2b4ce15e37edaae15b5544bffa0d0afbed697ba075a` |

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
| **D1** Same-client direct token | The issuer signed the user access token for the verified calling client | Observed: same-client `azp` equality (K09); different-client mismatch (K10) | `(issuer, sub)` → Identity, then explicit memberships; Application from the service token | Requires an issuer guarantee that `azp` is the obtaining client and a rationale that this is sufficient delegation | **BLOCKED** — equality observed, but no documented issuer guarantee; reviewer decision required |
| **D2** Distinct-client direct token with issuer-authorized delegation | An issuer-supported, cryptographically verified claim names the calling service client | None found | Same as D1 | Highest if unverified | **BLOCKED** |
| **D3** RFC 8693 exchanged token | A stable exchanged token carries an `act` actor chain | Standard V2 documented but the fixture exchange failed (K13); actor delegation is Preview (K14) | Exchanged-token audience + actor chain | Depends on preview feature | **BLOCKED** |

**Recommendation.** Leave `A14-07` BLOCKED. The smallest reviewer/issuer-admin
decision is whether to obtain an explicit documented guarantee for D1's
same-client `azp` semantics, or to approve a distinct-client + token-exchange
design (which currently depends on a preview issuer feature).

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
  image above.
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
