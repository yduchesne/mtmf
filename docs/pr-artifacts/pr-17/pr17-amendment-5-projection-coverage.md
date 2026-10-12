# PR 17 — Amendment #5 projection coverage and drift threat model (SEC-04)

The projection is a **reviewed, curated allowlist** reviewed against Keycloak
26.8.0. It is not a claim that unknown future fields are detected.

## 1. Included realm-security fields (`realmSecurity`)

`enabled`, `sslRequired`, `defaultSignatureAlgorithm`, `accessTokenLifespan`,
`accessTokenLifespanForImplicitFlow`, `ssoSessionIdleTimeout`,
`ssoSessionMaxLifespan`, `offlineSessionIdleTimeout`, `browserFlow`,
`registrationFlow`, `directGrantFlow`, `resetCredentialsFlow`,
`clientAuthenticationFlow`, `dockerAuthenticationFlow`, `firstBrokerLoginFlow`,
`revokeRefreshToken`, `refreshTokenMaxReuse`, `notBefore`.

Rationale: these can change token issuance, class, audience, signing trust,
session lifetime, revocation/rotation, or flow bindings. Each has a negative
drift test (`test_realm_security_drift_is_detected`).

## 2. Included client fields (approved expected-client policy)

`clientId`, `enabled`, `protocol`, `clientAuthenticatorType`, `publicClient`,
`serviceAccountsEnabled`, `standardFlowEnabled`, `directAccessGrantsEnabled`,
`implicitFlowEnabled`, `redirectUris`, `webOrigins`, `defaultClientScopes`,
`optionalClientScopes`, `protocolMappers` (exact `name`/`protocolMapper`/`config`).

Effective scopes/mappers are covered because the client projection records its
assigned default/optional scope **names** and the realm projection records every
`clientScopes` entry with its normalized mappers; a change to either the
assignment or the scope's mapper content changes a compared projection.

## 3. Security-relevant fields deliberately excluded (with justification)

| Field family | Disposition |
| --- | --- |
| Realm presentation (`displayName`, `displayNameHtml`, localization, themes) | nonsecurity/presentation |
| Realm SMTP/email/registration UX | nonsecurity (no token issuance effect in the D1 path) |
| `attributes` free-form maps (client/realm) | not stable/semantically typed; client security behavior is compared through the typed booleans/scopes/mappers above |
| `authorizationServicesEnabled` / resource-server policy | not used: MTMF does not rely on Keycloak authorization services (MTMF is the PDP) |
| `consentRequired` | affects interactive consent UX; the D1 predicate is token class/azp, not consent |
| `webAuthnPolicy*` / `otpPolicy*` | affect interactive authentication assurance, not the service/user token D1 predicate; root assurance is a separate deferred gate |
| `browserSecurityHeaders`, `smtpServer`, `themes`, `localizationTexts` | presentation/operations |

## 4. AT16 treatment (Amendment #4)

**AT16 remains PARTIAL, not PASS.** The projection is a curated allowlist; a new
security-relevant realm field added by a future Keycloak release is not compared
until reviewed and added. This is recorded explicitly; no claim is made that
unknown future fields are detected. Version pinning: the expected artifacts are
reviewed against Keycloak 26.8.0 and must be re-reviewed on any issuer upgrade.

## 5. Added coverage this amendment

No new realm/client field was added beyond the reviewed set above; the inventory
and tests are the deliverable. Read-skew behavior is characterized in
`pr17-amendment-5-security-test-matrix.md`.
