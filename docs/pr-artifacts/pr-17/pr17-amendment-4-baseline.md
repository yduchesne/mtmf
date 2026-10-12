# PR 17 — Amendment #4 baseline reconciliation

**Branch:** `dev/pr17-http-service` (continued). **Verified head:** `df2b8a7`
(feature `8f2e879`). **`origin/main`:** `4eea688`. Clean working tree.

## 1. Gate status at start

**D1 (acting-user carrier), D2 (attestation architecture) and D3 (development
topology) are PENDING human approval.** Preparing this plan is not approval.
Per the gate rule, no PR 14 trust-semantics change is implemented in this
amendment while D2 is pending.

## 2. Verified source state

| Item | Value |
| --- | --- |
| Attestation seam | `packages/mtmf-service/src/mtmf_service/authentication/attestation.py` — `canonical_manifest`, strict `_diff`, `BaselineConfigurationAttestor` |
| Compared client fields | `_CLIENT_FIELDS = enabled, publicClient, serviceAccountsEnabled, standardFlowEnabled, directAccessGrantsEnabled, implicitFlowEnabled` + default/optional client scopes + normalized protocol mappers |
| Compared realm fields | **realm name only** (`canonical_manifest` returns `{"realm": realm, "clients", "clientScopes"}`) |
| Expected manifest | `dev/keycloak/expected-config-manifest.json`, sha256 `07d8f8169763c9f7b461784e3d66d768becd67329d81c4e6566e80a5174894fb` (15 clients) |
| Initializer | `scripts/mtmf-dev-initialize.py`; creates the client before `verify_issuer()` |
| Fixture | `dev/keycloak/compose.yaml`, `quay.io/keycloak/keycloak:26.8.0-1`, project `mtmf-pr14-keycloak` |
| Environment | Podman 4.9.3, `podman-compose` 1.0.6, rootless, no passwordless sudo |

## 3. Amendment #4 addition to the baseline

The realm representation returned by `/admin/realms/mtmf-pr14-dev` has **~200
fields**; the manifest projects **none** of them. Security-relevant realm
fields that are currently **not** compared include (observed values):

| Field | Observed |
| --- | --- |
| `enabled` | true |
| `sslRequired` | none |
| `defaultSignatureAlgorithm` | RS256 |
| `accessTokenLifespan` | 300 |
| `accessTokenLifespanForImplicitFlow` | 900 |
| `ssoSessionIdleTimeout` / `ssoSessionMaxLifespan` | 1800 / 3600 |
| `offlineSessionIdleTimeout` | 2592000 |
| `browserFlow`, `registrationFlow`, `directGrantFlow`, `resetCredentialsFlow`, `clientAuthenticationFlow`, `dockerAuthenticationFlow`, `firstBrokerLoginFlow` | default flows |
| `revokeRefreshToken`, `refreshTokenMaxReuse`, `notBefore` | false / 0 / 0 |

## 4. Classification (Amendment #4 scope)

| Capability | Classification |
| --- | --- |
| HTTP PDP, PR 15 contract, PR 14 verification, PR 16 Python batch | IMPLEMENTED + VERIFIED |
| Runtime DB timeouts, admission bound, permit race | IMPLEMENTED + VERIFIED |
| Whole-realm attestation vs initializer client | **BLOCKED (D2)** — reproduced (below) |
| Realm/effective-client security projection | **NOT IMPLEMENTED (D2)** |
| Host-network launcher reconciliation | **BLOCKED (D3)** |
| V12 two-client isolation | **BLOCKED (D2)** |
| V13 disposable destroy/recreate | **NOT EXECUTED** |
| V08 DB outage/recovery | EXECUTED + PASS (Amendment #3) |

## 5. Reproduced drift (fresh, this amendment)

- before initializer: 15 clients, hash `9e9bb847…fed5`, **matches** expected.
- after initializer: 16 clients, hash `2372a2bd…`, **added `mtmf-sample-app`**;
  scopes and realm-name equal → strict client-list equality is the only cause.

## 6. Required commands

```
./build.sh --qa
./build.sh --sec
./build.sh --rust
./build.sh --integration
opt-in: MTMF_PR14_LIVE / MTMF_PR17_LIVE pytest (see live matrix)
```

## 7. Prior gaps carried forward

Unapproved D1/D2/D3; V12/V13 outstanding; realm-wide settings and effective
inherited scopes not verified; duplicate client IDs not explicitly rejected;
attestation reader is the realm admin rather than a read-only reader.
