# PR 17 — Amendment #4 attestation implementation (D2 PENDING)

**Status: NOT IMPLEMENTED. No PR 14 trust-verification semantics were changed.**
S4-01 applies while D2 is PENDING.

## 1. Actual verifier coupling (verified)

```
BaselineConfigurationAttestor.attest(profile)
  -> _load_baseline()                              # committed manifest JSON
  -> canonical_manifest(reader, realm)             # fresh live Admin REST
       realm -> {"realm": <name>, "clients": [...], "clientScopes": [...]}
  -> _diff(expected, actual)                       # strict structural equality
       -> AuthenticationFailure.ATTESTATION_DRIFT  # on any difference
```

No duplicate-client guard, no realm-representation projection, and no separate
per-client expected policy exist today.

## 2. Proposed D2 schema/comparator mapping (draft for review)

### 2.1 Realm-security projection (committed)
Extend the existing `_diff` target with an explicit, normalized subset of the
realm representation (deterministic key order, no derived data):

| Realm field | Rationale |
| --- | --- |
| `enabled` | realm-wide auth enablement |
| `sslRequired` | transport expectation |
| `defaultSignatureAlgorithm` | signing trust alignment |
| `accessTokenLifespan`, `accessTokenLifespanForImplicitFlow` | token time bounds |
| `ssoSessionIdleTimeout`, `ssoSessionMaxLifespan`, `offlineSessionIdleTimeout` | session bounds |
| `browserFlow`, `registrationFlow`, `directGrantFlow`, `resetCredentialsFlow`, `clientAuthenticationFlow`, `dockerAuthenticationFlow`, `firstBrokerLoginFlow` | flow bindings that can change token issuance |
| `revokeRefreshToken`, `refreshTokenMaxReuse`, `notBefore` | revocation/rotation |

Existing `clientScopes` comparison is retained and extended to include
effective inherited/default scope mappers.

### 2.2 Expected-client policy (new, static, secret-free)
One entry per admitted client:

```
clientId, enabled, protocol, clientAuthenticatorType, publicClient,
serviceAccountsEnabled, standardFlowEnabled, directAccessGrantsEnabled,
implicitFlowEnabled, tokenExchange (if present),
redirectUris, webOrigins,
defaultClientScopes, optionalClientScopes,
effectiveProtocolMappers (aud/azp/client_id/sub-producing),
serviceAccountRoles (if relevant), token-lifetime overrides
```

Validation: reject duplicate `clientId`, missing entries, unknown fields,
malformed data, and ambiguous versions.

### 2.3 Comparator mapping
- `canonical_manifest` gains a `realmSecurity` block (new) and keeps `clients`,
  `clientScopes`; the client projection gains the new fields and **effective**
  scopes/mappers.
- `_diff` stays strict; a missing/extra/duplicate client exits through the
  existing `ATTESTATION_DRIFT` mapping.
- No new verifier is introduced; the existing Admin REST reader and
  `IssuerProfile`/JWT checks are unchanged.

## 3. Operation order (proposed, approved only after D2)

1. existing cryptographic/issuer/audience/time verification;
2. fresh Admin REST realm fetch;
3. realm-security projection comparison;
4. resolve service/user `azp` from **verified signed claims**;
5. fresh effective per-client comparison for each admitted client;
6. existing persisted bindings/eligibility/root exclusion;
7. fail closed with the existing taxonomy on any failure; no decisions.

## 4. What was executed this amendment

- Drift reproduced fresh (before `9e9bb847…`, after `2372a2bd…`, added
  `mtmf-sample-app`).
- Realm field inventory captured (baseline §3).
- No implementation, migration, grant, DTO or launcher change.

## 5. Blocked

Implementation, AT02/AT08/AT09 realm-wide cases, initializer reconciliation, and
the two-client V12 path are **BLOCKED** pending D2.
