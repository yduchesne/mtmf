# PR 17 — Amendment #4 attestation implementation (D2 APPROVED 2026-10-12)

**Status: IMPLEMENTED and VERIFIED.** D2 was explicitly approved by the human
reviewer on 2026-10-12 (see `pr17-amendment-4-decision-register.md`).

## 1. What changed (existing PR 14 seam only)

`packages/mtmf-service/src/mtmf_service/authentication/attestation.py`:

- `canonical_manifest(reader, realm)` now returns the **realm-security
  projection**: `realm` + a normalized `realmSecurity` block + the realm-level
  `clientScopes` projection. The unrelated-realm-client set is intentionally not
  part of this projection.
- `realm_security_projection(realm)` projects 18 security-relevant realm fields
  (`enabled`, `sslRequired`, `defaultSignatureAlgorithm`, token/session
  lifetimes, flow bindings, `revokeRefreshToken`, `refreshTokenMaxReuse`,
  `notBefore`).
- `canonical_client_projection(reader, realm, client)` projects one live
  client's **effective** configuration: the six original class/flow booleans plus
  `protocol`, `clientAuthenticatorType`, sorted `redirectUris`/`webOrigins`,
  default/optional client scopes (names), and normalized protocol mappers.
- `ExpectedClientPolicy` loads and strictly validates the independently approved,
  secret-free expected-client policy (version, clients, unique `clientId`,
  object entries); any malformed/duplicate/missing entry fails closed.
- `BaselineConfigurationAttestor.attest(profile)` compares the realm projection;
  `BaselineConfigurationAttestor.attest_client(profile, client_id)` resolves the
  **exactly one** live client for the verified `azp`, requires an approved policy
  entry, and compares the effective projection. Duplicate/ambiguous/missing
  client or policy entry fails closed.
- No positive cache: every call re-reads live Admin REST and re-compares.

Core seam: `ConfigurationAttestor.attest_client` added to the provider-neutral
port; `AuthenticatedActorContextService.resolve` now calls it for the service and
user `azp` after token/class/same-client verification, so only verified signed
claims select the client to attest. The realm `attest` still runs before token
acceptance (conservative ordering preserved).

## 2. Independently approved artifacts

| Artifact | Content |
| --- | --- |
| `dev/keycloak/expected-realm-security.json` | reviewed realm-security projection (realm + realmSecurity + clientScopes) |
| `dev/keycloak/expected-client-policy.json` | approved effective configuration for `mtmf-evidence-same-client`, `mtmf-evidence-same-client-b`, `mtmf-sample-app` |

Both are static, secret-free, committed files. The initializer validates a client
against the policy **before** creating it and compares an existing client to the
policy, failing closed on drift; it never regenerates or rewrites either file.

## 3. Initializer reconciliation

- `KeycloakCredentialProvisioner.ensure_client` requires an approved policy entry;
  creates a missing approved client; validates an existing client and fails on
  drift with no auto-repair/secret rotation.
- `verify_issuer` performs fresh realm attestation and attests **every** approved
  client before reporting success.

Demonstrated: fresh + idempotent initialization succeeds; mutating
`mtmf-sample-app` `webOrigins` makes the initializer fail closed
(`client 'mtmf-sample-app' drifted … no automatic repair is performed`); restore
returns to success.

## 4. Compatibility

`IssuerConfig.expected_client_policy_path` defaults to
`expected-client-policy.json` beside the manifest. The service baseline moved to
`expected-realm-security.json`; the PR 14 G0-A evidence script keeps its own
`expected-config-manifest.json`. No PR 15 DTO, PR 16 policy engine, migration,
grant, root or production file changed.

## 5. Verified

- Unit: `tests/unit/authentication/test_attestation.py` (realm projection,
  realm-security drift, client-scope drift, no-cache, policy validation,
  per-client drift, duplicate rejection, two-client independence).
- Live PR 14 actor suite 22/22; live PR 17 HTTP suite passes; containerized D3
  real ALLOW with the new code.
