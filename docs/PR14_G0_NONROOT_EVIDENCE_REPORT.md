# PR 14 — Gate G0 non-root evidence report

**Status: EVIDENCE AND RECONCILIATION ONLY — NO IMPLEMENTATION AUTHORIZATION.**
**Branch:** `dev/service-auth`. **Authoritative gate:** [PR14_DEVELOPMENT_FIRST_IMPLEMENTATION_GATE.md](PR14_DEVELOPMENT_FIRST_IMPLEMENTATION_GATE.md).
**Approved scope:** pinned Keycloak 26.8.0 development issuer, constrained D1, root excluded. **Production issuer:** deferred.

This report executes **G0 only**. PR 14 production authentication
implementation has not begun. No decision is approved by this document; the
approval log in [PR14_AUTHENTICATION_SECURITY_DECISIONS.md](PR14_AUTHENTICATION_SECURITY_DECISIONS.md)
is unchanged.

## 1. Phase 0 reconciliation (2026-10-11)

| Fact | Value |
| --- | --- |
| Working branch | `dev/service-auth` |
| `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Reconciled baseline (`origin/dev/service-auth`) | `fa5b19b45d18ed00f5340900d746a9c62a278bc4` |
| Local HEAD before G0 | `fa5b19b` (fast-forwarded; worktree clean) |
| Alembic head | `0010_pr13_application_registry` |
| Runtime EXECUTE allowlist | 75 signatures (`expected_runtime_signatures()`) |
| Keycloak fixture | `quay.io/keycloak/keycloak:26.8.0-1`, digest `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Fixture project | `mtmf-pr14-keycloak` (loopback-only `127.0.0.1:28080`, `127.0.0.1:28443`) |

### 1.1 Capability status matrix

| Capability | Status | Evidence / path |
| --- | --- | --- |
| PR 13 Application registry + subscription eligibility | DONE + VERIFIED | `application_eligibility.py`; `./build.sh --qa` |
| Runtime least-privilege model (75 signatures) | DONE + VERIFIED | `postgres/roles.py`; post-upgrade verifier |
| Identity/Principal/Tenant typed memberships | DONE + VERIFIED | `domain/memberships.py`; unit + integration suites |
| Isolated Keycloak 26.8.0 dev fixture | DONE + VERIFIED | `dev/keycloak/`; clean recreate |
| D1 same-client `azp` binding evidence | DONE + VERIFIED (dev profile) | `PR14_KEYCLOAK_EVIDENCE.md` §6A; DC01–DC08 |
| Service vs user token-class predicate | **BLOCKED** | §2 below (G0-T09 spoof) |
| MTMF token verifier / binding persistence / actor composition | NOT STARTED | (implementation STOP) |
| Root authentication / external root binding | BLOCKED / deferred | A14-08 scope split |
| Production issuer profile | NOT STARTED | deferred |

No PR 14 production code, schema, migration, dependency, or root behavior
exists or was added.

## 2. G0-A — service versus user token-class evidence

### 2.1 Problem

Both genuine token classes carry payload `typ=Bearer`. In `PR14_KEYCLOAK_EVIDENCE.md` §6A
the intended separation was the profile-specific audience, but **audience
alone does not establish grant type**: a token of the wrong grant can carry
the expected audience. A reliable, signed, issuer-backed class predicate is
required.

### 2.2 Source-backed facts (Keycloak 26.8.0)

| Reference | Fact |
| --- | --- |
| `common/.../constants/ServiceAccountConstants.java` | `SERVICE_ACCOUNT_SCOPE = "service_account"`; `SERVICE_ACCOUNT_USER_PREFIX = "service-account-"`; built-in mappers `Client ID`, `Client Host`, `Client IP Address`; note names `client_id`, `clientHost`, `clientAddress`. |
| Built-in `service_account` client scope (observed via Admin REST) | Three `oidc-usersessionmodel-note-mapper`s projecting the session notes `client_id`, `clientHost`, `clientAddress` into access tokens. |
| `services/.../grants/ClientCredentialsGrantType.java` | Sets user-session notes `ServiceAccountConstants.CLIENT_ID`, `CLIENT_HOST`, `CLIENT_ADDRESS`; requires a confidential service-account client. |
| `services/.../TokenManager.initToken` → `JsonWebToken.issuedFor` (`@JsonProperty("azp")`) | Access-token `azp` is the authenticated client (see §6A.1). |
| `services/.../mappers/HardcodedClaim.java` (`oidc-hardcoded-claim-mapper`) | A realm protocol mapper can set arbitrary claims, including `client_id` and `azp`. |

**Observed claim difference (same client, clean fixture):**

| Claim | Client-credentials service token | Auth-code+PKCE user token |
| --- | --- | --- |
| `typ` | `Bearer` | `Bearer` |
| `azp` | obtaining client | obtaining client |
| `client_id` | present (`== azp`) | absent |
| `clientAddress`/`clientHost` | present | absent |
| `preferred_username` | `service-account-<clientId>` | human username |
| `sid` / `auth_time` | absent | present |
| `id_token` / `refresh_token` | n/a | payload `typ=ID` / `typ=Refresh` |

### 2.3 Candidate class predicates (harness only, not approved)

- **Service class:** `typ=Bearer` AND `client_id` present AND `client_id == azp`.
- **User class:** `typ=Bearer` AND `azp` present AND `client_id` absent AND `sub` present.

These are evaluated on independently **signature-, issuer-, audience- and
time-verified** claims. They are candidate heuristics, not MTMF trust logic.

### 2.4 G0-T results (pinned fixture, clean recreate)

| ID | Status | Observation |
| --- | --- | --- |
| G0-T01 | PASS | Genuine client-credentials token satisfies the service predicate only |
| G0-T02 | PASS | Genuine auth-code+PKCE token satisfies the user predicate only |
| G0-T03 | PASS | User token deliberately carrying the service audience fails the service predicate |
| G0-T04 | PASS | Service token deliberately carrying the user audience fails the user predicate |
| G0-T05 | PASS | Both-audience tokens cannot satisfy the opposite class predicate |
| G0-T06 | PASS | Service token without the grant-derived `client_id` (scope stripped) fails the service predicate (fail closed) |
| G0-T07 | PASS | ID (`typ=ID`) and refresh (`typ=Refresh`) tokens satisfy neither predicate |
| G0-T08 | PASS | Same-client `azp` observed equal; different-client `azp` differ and pairing is rejected |
| G0-T09 | **FAIL** | A realm protocol mapper injects `client_id` and overrides `azp`; the injected user token then passes the service predicate |
| G0-T10 | PASS | Clean `down -v` recreate reproduced T01–T09 without touching other Podman resources |

Sanitized artifact: `dev/keycloak/evidence/pr14-g0-token-class-evidence.json`
(SHA-256 `2b0807df2fa0a104743e8e52dd6de939abc3e1c0a9737293d2b3ec393737a7f6`).

### 2.5 Verdict — G0-A BLOCKED for unconditional acceptance

- `typ=Bearer` + audience is **insufficient** (T03/T04/T05).
- The `client_id`-based predicate works in the **default** fixture but is
  **issuer-configuration-dependent and spoofable by a realm protocol
  mapper** (T09): `client_id` can be injected and `azp` overridden in a
  signed token. It is therefore not a non-spoofable issuer guarantee.
- Because the gate requires a reliable class predicate and T09 shows the
  trusted claims are configuration-overridable, no unconditional predicate
  can be demonstrated. Per the G0 hard STOP, do **not** accept
  `typ=Bearer` + audience as sufficient.

**Smallest issuer-configuration / architecture decisions for the reviewer:**

1. **Lock + attest the issuer mapper profile.** Keep same-client D1, but
   require the realm to prohibit client-managed protocol mappers and pin/attest
   the exact mapper set (no hardcoded `azp`/`client_id`/`typ` claims), then
   treat the `client_id` predicate as conditionally acceptable. The realm-admin
   mapper configuration becomes an explicit trust precondition.
2. **Use distinct clients** for the service credential and the interactive
   user flow (distinct signed `azp` + distinct audiences). This provides a
   stronger class boundary, at the cost of changing D1's same-client model.
3. **Issuer token introspection** (RFC 7662) to classify `sub`/client
   grant type from issuer server state instead of token claims. This adds a
   live issuer dependency and departs from the signed-token-only D1 model.

Recommendation: present decision 1 (with the mapper-lockdown precondition) as
the minimal change for development-first D1, and record decisions 2/3 as
alternatives. This report records **no approval**.

## 3. G0-B — approval-readiness matrix (no self-approval)

| ID | Normative contract (unchanged) | Evidence status | Disposition proposed |
| --- | --- | --- | --- |
| A14-01 | Asymmetric signed access tokens; fixed trust anchors; fail-closed issuer/audience/algorithm | Source + DC/G0 | Approve |
| A14-02 / §7 | Distinct service/user profiles + token-class predicates | **BLOCKED** (G0-A) | Approve only with the §2.5 predicate decision |
| A14-03 | `(issuer, client_id)` → exactly one Application | Repo + DC | Approve |
| A14-04 | `(issuer, sub)` → one ordinary `FEDERATED` Identity; operator-only | Repo + DC07 NOT EXECUTED | Approve |
| A14-05 / A14-07 / §8 | D1 same-client under amended PR 12 T1; no cross-client/consent claim | DC01–DC08 | Approve D1 scope; class predicate per §2.5 |
| A14-06 | ACTIVE actor + explicit memberships + ordinary ACTIVE Tenant + ACTIVE registration | Repo | Approve |
| A14-08 | Root scope split; fail-closed root exclusion | Approved scope split | Scope resolved; root tests deferred |
| A14-09 | Typed internal API; sanitized errors; no public route | Plan/architecture | Approve |
| A14-10 | Operator-only mutation; runtime read-only `SECURITY DEFINER`; additive migration | Repo (75 signatures) | Approve |
| §10 dependency | `pyjwt[crypto]>=2.13,<3`; RS256; `exp` zero leeway; `iat` required; `nbf` optional validated; bounded JWKS | PyJWT source + G0 | Approve |
| §10 ownership | `mtmf-service` transport/composition; `mtmf-core` provider-neutral verification | PR 12 text conflict | Reviewer reconciliation required |

## 4. AUTH-01–AUTH-36 partition

| Partition | IDs | Note |
| --- | --- | --- |
| Non-root mandatory | AUTH-01–AUTH-25, AUTH-28–AUTH-36 | Includes service/user class crossover (AUTH-07/23/24), SYSTEM-tenant rejection (AUTH-25), and privilege/DB gates (AUTH-29–AUTH-32) |
| Deferred root-only | AUTH-26, AUTH-27 | Root external binding / assurance and root binding mutation; deferred with A14-08 |
| Unresolved by G0-A | AUTH-01 (service class), AUTH-02 (user class) | Depend on the §2.5 class-predicate decision; not PASS |

DC05 (missing signed `azp`) remains **NOT EXECUTED** (only a harness predicate);
G0-T06 is the issuer-backed missing-`client_id` case. DC07 (real-domain
Identity/Tenant/Application/subscription binding) remains **NOT EXECUTED** and
belongs to future PR 14 acceptance with real PostgreSQL.

## 5. Reproducible commands and topology

```bash
# isolated fixture (explicit project; loopback; ephemeral uncommitted secrets/TLS)
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml --env-file /tmp/mtmf-pr14-kc.env up -d
uv run --no-sync python scripts/pr14-keycloak-evidence.py wait
uv run --no-sync python dev/keycloak/setup-realm.py
uv run --no-sync python scripts/pr14-keycloak-evidence.py collect \
  --report dev/keycloak/evidence/pr14-keycloak-evidence.json
uv run --no-sync python scripts/pr14-g0-token-class-evidence.py \
  --report dev/keycloak/evidence/pr14-g0-token-class-evidence.json
# clean recreate (G0-T10)
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml --env-file /tmp/mtmf-pr14-kc.env down -v
```

Mounted ephemeral self-signed TLS and generated secrets live only under `/tmp`
and are removed after collection. The fixture was torn down; no owned
container/volume/network remains, and MTMF PostgreSQL / ATI resources were
untouched.

## 6. Residual risks

- Class predicate is mapper-config-dependent (G0-T09); requires a locked,
  attested realm mapper profile or a stronger separation model.
- `azp` is mapper-overridable by a realm protocol mapper; D1 same-client
  binding assumes a trusted, pinned issuer configuration.
- Bearer tokens are not bound to a request; replay and separate-session
  acquisition remain (unchanged from §6A.5).
- Production issuer profile is unspecified and must not be inferred from the
  loopback development fixture.

## 7. Reviewer decisions requested

1. Approve, reject, or amend the §2.5 class-predicate disposition (mapper
   lockdown + `client_id` predicate, distinct clients, or introspection).
2. Approve the G0-B matrix dispositions (A14-01/03/04/06/09/10, §10), and
   resolve the §10 core/service ownership reconciliation against PR 12.
3. Confirm A14-08 root scope split and the deferred root-only AUTH-26/27.
4. Confirm whether the first implementation targets only the pinned local
   development Keycloak profile or a separately specified production issuer.

## 8. Statement

**PR 14 production authentication implementation has NOT begun; implementation
STOP remains active.** This report is decision preparation only and records no
human approval.
