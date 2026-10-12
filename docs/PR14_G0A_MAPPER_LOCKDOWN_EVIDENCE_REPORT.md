# PR 14 — G0-A mapper lockdown and attestation evidence report

**Status: G0-A REMEDIATION EVIDENCE — CONDITIONAL DIRECTION APPROVED (§14F), NOT TOKEN-CLASS ACCEPTANCE OR IMPLEMENTATION AUTHORIZATION.**
**Branch:** `dev/service-auth`. **Authorized by:** [PR14_AUTHENTICATION_SECURITY_DECISIONS.md](PR14_AUTHENTICATION_SECURITY_DECISIONS.md) §14F (2026-10-11).
**Approved scope:** pinned Keycloak 26.8.0 development issuer, constrained D1 same-client, root excluded.

This report executes the G0-A remediation gate only: fixture hardening,
independent configuration attestation, and adversarial evidence. PR 14
production authentication implementation remains stopped. The historical
G0-T09 result is **preserved as FAIL (vulnerability demonstrated)**; it is not
retroactively changed to PASS.

## 1. Baseline, tooling and topology

| Item | Value |
| --- | --- |
| `origin/main` | `1924143ea504a9c291d695d154e9537cdb61969e` |
| Reconciled base (`origin/dev/service-auth`) | `0f27ae0afefa0bf36e53f546ea421cbd475904f4` |
| Local HEAD before work | `0f27ae0` (fast-forwarded; clean tree) |
| Keycloak image | `quay.io/keycloak/keycloak:26.8.0-1` |
| Image digest | `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741` |
| Server version | Keycloak 26.8.0 (Quarkus 3.40.1, dev profile) |
| Compose project | `mtmf-pr14-keycloak` (loopback only `127.0.0.1:28080`, `127.0.0.1:28443`) |
| Python / PyJWT | 3.14.7 / `pyjwt==2.13.0` |

Sanitized artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `dev/keycloak/expected-config-manifest.json` (canonical content hash `9e9bb847e35060b2aab18c876d52c23648c137668c08fa6766c69a30dbc6fed5`) | `07d8f8169763c9f7b461784e3d66d768becd67329d81c4e6566e80a5174894fb` |
| `dev/keycloak/evidence/pr14-g0a-mapper-matrix.json` | `4ee7aaec2f26cd4da429847fb51141e17bce14d9893817b2723dd3de8b44bf58` |
| `dev/keycloak/evidence/pr14-g0-token-class-evidence.json` | `2b0807df2fa0a104743e8e52dd6de939abc3e1c0a9737293d2b3ec393737a7f6` |

## 2. Part A — mapper trust-surface inventory

The canonical manifest enumerates the security-relevant Keycloak
configuration: every client (grant flags, service-account enablement, default
and optional client scopes, directly attached protocol mappers) and every
client scope (attributes and protocol mappers). Observed provider families
that can affect signed access-token claims:

| Provider | Effect on signed claims |
| --- | --- |
| `oidc-usersessionmodel-note-mapper` | Projects server-side session notes into claims. The built-in `service_account` scope uses it for `client_id`, `clientHost`, `clientAddress`; only `ClientCredentialsGrantType` sets those notes. |
| `oidc-audience-mapper` | Adds audiences to the access token. |
| `oidc-hardcoded-claim-mapper` | Sets an arbitrary claim name/value via `otherClaims`; observed to **override** the typed `azp` and inject `client_id`. |
| `oidc-usermodel-*`/`oidc-usermodel-attribute-mapper` | Project user attributes/roles into claims. |

Trust-surface facts:

- The built-in `service_account` client scope is assigned to service-account
  clients; its `Client ID` mapper is the source of the class-discriminating
  `client_id` claim.
- Realm admins (and principals with client-management rights) can add, remove,
  or change protocol mappers and scopes. A client with `manage-clients` for
  itself could in principle alter its own mappers; the canonical manifest
  detects any such drift.
- No unknown extension point was found that can override the class claims
  without appearing in the canonical manifest.

**Effective-config manifest schema** (deterministic, sorted):

```
{
  "realm": "...",
  "clients": [ { "clientId", enabled, publicClient, serviceAccountsEnabled,
                 standardFlowEnabled, directAccessGrantsEnabled,
                 implicitFlowEnabled, defaultClientScopes[], optionalClientScopes[],
                 protocolMappers[{name, protocolMapper, config{}}] } ],
  "clientScopes": [ { "name", "protocol", "attributes{}",
                      "protocolMappers[{name, protocolMapper, config{}}] } ]
}
```

Exclusions (with reasons): instance-generated client UUIDs and mapper IDs
(regenerated on recreate, semantically irrelevant); realm signing keys and
JWKS material (regenerated; key trust is established separately by
signature verification against the configured JWKS URI); secrets and user
data (never part of the mapper trust surface). The content hash is SHA-256
over the canonical JSON.

## 3. Part B — lockdown, trust anchor and attestation

1. **Trust anchor.** `dev/keycloak/expected-config-manifest.json` is a
   reviewed repository artifact. The checker never learns the baseline from
   the live realm; it compares the live canonical manifest against this file.
2. **Observed-state retrieval.** The checker reads the live realm through the
   Keycloak Admin REST API using a privileged identity (development: the
   bootstrap admin; production: a dedicated, least-privilege, read-only
   attestation principal). The baseline (git) and the observed read
   (admin credential) are separate authorities.
3. **Enforcement point.** This task implements a **standalone preflight
   checker** (`scripts/pr14-g0a-mapper-attestation.py`). A one-time startup
   check does **not** prove continuous integrity. A future PR 14 runtime or
   deployment gate must re-attest before authentication is enabled and
   periodically thereafter, and must fail closed on drift, unreadable Admin
   REST, a missing baseline, or a stale attestation record.
4. **Freshness.** The checker can write and verify an attestation record
   (`--record` / `--check-record --max-age-seconds`). The maximum permitted
   attestation age is a **proposal** (for example 24h for production, 0 for
   volatile development) and requires explicit human approval; no interval is
   approved here.
5. **Fail closed.** Any inability to read the live configuration, any manifest
   difference, or any missing/stale/unreadable baseline or record yields a
   non-zero, fail-closed result with no success fallback.
6. **Residual administrative-compromise risk.** An issuer administrator with
   configuration and signing control can always compromise the trusted
   issuer. Production requires a restricted attestation principal, separation
   of duties for realm/configuration changes, an independently provisioned
   baseline, and audit. The local fixture does not establish those controls.

## 4. Part C — adversarial evidence matrix R01-R12

All mutations run against the **real isolated Keycloak configuration**;
attestation compares the live canonical manifest to the committed baseline.
Token tests use signed, issuer-verified tokens with the candidate predicates.

| ID | Status | Evidence |
| --- | --- | --- |
| R01 | PASS | Clean fixture canonical manifest equals the expected hash `9e9bb847…` (0 drift) |
| R02 | PASS | Genuine client-credentials token satisfies service predicate only |
| R03 | PASS | Genuine auth-code+PKCE user token satisfies user predicate only |
| R04 | PASS | User token carrying the service audience rejected by the service predicate |
| R05 | PASS | Service token carrying the user audience rejected by the user predicate |
| R06 | PASS | `client_id` injection spoofs the claim-only predicate (`claim_only_predicate_spoofed=true`); attestation detects the unauthorized mapper (drift=1) |
| R07 | PASS | `sub`/`typ`/`azp` overrides and a scope-level mapper detected (drift=2) |
| R08 | PASS | Removing the built-in `Client ID` mapper detected; service token then lacks `client_id` and fails the service predicate |
| R09 | PASS | Audience and grant-setting changes detected |
| R10 | PASS | Bad admin credentials, missing baseline, and a stale attestation record all fail closed |
| R11 | PASS | After restoring canonical configuration, attestation passes and genuine tokens classify correctly |
| R12 | PASS | Clean `down -v` recreate regenerates the identical manifest hash `9e9bb847…`; attestation passes (executed as a separate operator step; the matrix artifact records it as `NOT EXECUTED (separate step)`) |

Commands: `scripts/pr14-g0a-mapper-attestation.py manifest --out …`,
`… attest --expected …`, `… matrix --expected … --report …`, and the
documented `podman-compose … down -v` / `up` / `setup-realm.py` recreate.

**Distinction.** R06/R07/R08/R09 are **blocked/detected malicious
configuration** cases; they do not claim MTMF runtime token rejection (the
runtime verifier does not exist yet). R04/R05/R08 token checks are
signature-verified predicate rejections.

## 5. Conditioned A14-02 / §7 predicate contract (proposed, not approved)

Under a **fresh, drift-free attestation** of the canonical manifest:

- **Service class:** independently verified signed access token with
  `typ=Bearer`, the profile service audience, and `client_id` present and
  equal to the signed `azp` (the built-in `service_account` session-note
  mapper, driven only by the client-credentials grant).
- **User class:** independently verified signed access token with
  `typ=Bearer`, the profile user audience, a signed `azp` and `sub`, and
  **no** `client_id` claim.
- **Attestation precondition:** if attestation cannot be completed, detects
  drift, or its freshness window has expired, the verifier must **reject**
  (fail closed) rather than fall back to claim-only classification.
- **Baseline constraint:** the canonical manifest must contain no mapper that
  writes `azp`, `client_id`, `typ`, `sub`, or `aud` on the evidence clients;
  the D1 client-binding comparison must use the verified `azp`.

This contract is explicitly **conditional**: it depends on issuer
configuration integrity, not on JWT signatures alone. It is not approved by
this report.

## 6. Limitations and explicit non-goals

- **`azp` override / class confusion:** `azp` and `client_id` are
  realm-mapper-configurable; the attestation gate is what makes the predicate
  defensible. Without it, claim-only acceptance is unsafe (G0-T09 / R06).
- **Bearer replay:** tokens are not bound to a request; stolen valid tokens
  can be replayed. TLS, short expiry, redaction, and future holder-of-key/DPoP
  (if approved) are mitigations.
- **Separate-session acquisition:** the same client may obtain a user token in
  an unrelated session; D1 accepts this as the selected model and does not
  claim consent.
- **Freshness/continuous enforcement:** the checker is a preflight, not a
  continuous runtime guarantee; the runtime gate is a future PR 14 obligation.
- **Production issuer, root authentication and recovery are out of scope** and
  remain deferred/fail-closed. No MTMF production authentication, migration,
  API, dependency, runtime grant, or root code was added.

## 7. Remaining human approvals

1. Approve the §5 conditional A14-02/§7 predicate contract (with the
   attestation precondition) or choose an alternative (distinct clients or
   issuer introspection).
2. Approve the production attestation controls and maximum attestation age.
3. Approve A14-01/03/04/06/09/10 and §10 (dependency/JWKS constraints and the
   `mtmf-core` vs `mtmf-service` ownership reconciliation against PR 12 §2).
4. Confirm the A14-08 root scope split and the deferred root-only AUTH-26/27.
5. Confirm development-first vs production-issuer implementation scope.

The approval log is unchanged; this report records no approval.

## 8. Statement

**PR 14 production authentication implementation has NOT begun. Implementation
STOP remains active pending human security approval.**
