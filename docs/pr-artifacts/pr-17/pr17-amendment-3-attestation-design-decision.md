# PR 17 — Amendment #3 attestation design decision (D2, APPROVAL GATE)

**Status: DRAFT FOR HUMAN DECISION. No trust-verification code was changed.**
This document proposes the exact security projection and per-client
verification design required by Amendment #3 §5. Implementation must not begin
until D2 is explicitly approved.

## 1. Current projection (verified)

`canonical_manifest` compares `realm` (name only), the full `clients` list
(each client's security fields + effective default/optional scopes + normalized
protocol mappers), and `clientScopes` (realm-level scopes + mappers). `_diff`
requires exact structural equality. The committed baseline is
`dev/keycloak/expected-config-manifest.json` (15 clients).

## 2. Proposed partition

### 2.1 Realm trust projection (committed, independently maintained)
Retain and extend the realm-level checks so realm-wide mutation cannot bypass
per-client trust:

- realm name, enabled state, and (proposed addition) realm token/issuer-relevant
  settings: access-token/token lifespans, SSO/session idle limits, `sslRequired`,
  default signature algorithm, and authentication-flow bindings relevant to
  service and interactive-user tokens;
- realm `clientScopes` and their protocol mappers (already compared);
- client scopes that can change token class, `azp`, `client_id`, `sub`, `aud`
  or privileges.

Because the current projection does **not** capture realm-wide settings, adding
them is part of this proposal and must be reviewed (it can only make the check
stricter).

### 2.2 Expected-client policy (new, independently approved, static)
A versioned, secret-free, reviewed policy enumerating each client admitted into
MTMF's authenticated D1 path:

```
clientId, enabled, protocol, clientAuthenticatorType,
publicClient, serviceAccountsEnabled, standardFlowEnabled,
directAccessGrantsEnabled, implicitFlowEnabled,
defaultClientScopes, optionalClientScopes, effectiveProtocolMappers
(audience/azp/client_id/sub-producing mappers)
```

- Static file in `dev/keycloak/` (or an equivalent existing immutable PR 14
  policy mechanism), referenced explicitly with no fallback; **never** derived
  from live Admin REST or initializer output.
- Deterministic validation: duplicate client IDs, missing entries, unexpected
  fields, malformed data and ambiguous versions all fail closed.
- Must describe `mtmf-sample-app` **and** a second V12 client.

### 2.3 Effective-configuration verification (proposed operation order)
1. Fresh live realm fetch via the existing trusted PR 14 Admin REST reader.
2. Realm projection compared to the committed baseline (no cache).
3. Identify the authenticated service and acting-user clients from **verified
   signed claims** (`azp`), never from headers/body.
4. Resolve exact expected-client entries; reject missing/duplicate/unapproved.
5. Fetch fresh live client config and **effective** scopes/mappers for the
   involved clients; compare to the approved projection.
6. Preserve existing JWT verification, same-client D1 binding, persisted
   Application/Identity binding, eligibility and root exclusion; unchanged
   ordering where more conservative.
7. Any fetch/normalization/lookup/compare failure → existing fail-closed
   mapping (`ATTESTATION_UNAVAILABLE`/`ATTESTATION_DRIFT`), zero decisions.

Per-operation reuse of a single freshly fetched snapshot is permitted only if it
does not create a cross-request positive cache.

## 3. Unrelated Keycloak clients

Extra clients in the development realm are acceptable only if they (a) cannot
authenticate to MTMF (no MTMF credential binding) and (b) cannot influence
realm-wide trust or another client's effective claims. Because requirement (b)
depends on realm-wide mapper/scope semantics, the realm projection must include
the realm-wide settings that can change effective claims (§2.1), and the
expected-client policy must verify effective scopes/mappers for admitted clients
(§2.2). If this cannot be demonstrated, preserve whole-realm strictness and use
the fallback in §5.

## 4. Fail-closed table

| Condition | Result |
| --- | --- |
| Realm projection drift | `ATTESTATION_DRIFT`, zero decisions |
| Approved client drift (enabled/flow/class/scope/mapper) | `ATTESTATION_DRIFT`, zero decisions |
| Client present in realm but not in expected policy | not admitted; if signed claims reference it, reject |
| Duplicate/ambiguous client id | fail closed |
| Expected-client policy missing/malformed/duplicate | startup/operation fails closed |
| Admin REST/JWKS/transport failure | `ATTESTATION_UNAVAILABLE`, zero decisions |
| Any prior success | never cached |

## 5. Alternatives considered

| Alternative | Note |
| --- | --- |
| Freeze all clients in the whole-realm manifest (fallback) | lowest change; requires pre-provisioning `mtmf-sample-app` + V12 client into the reviewed manifest and making the initializer validate/reuse |
| Split realm + expected-client policy (recommended) | permits approved mutable dev clients with per-client freshness |
| Per-client checks only | rejected — would drop realm-wide trust |
| Static preprovisioning without initializer creation | compatible with the fallback |
| Dynamic manifest regeneration | **rejected** — violates independent-trust invariant |

## 6. Threat-model notes

- Fresh per-request Admin REST increases load; acceptable for the development
  profile and already the PR 14 contract.
- A newly added client must not gain MTMF authorization: it is denied unless it
  has an approved expected-client entry **and** a persisted credential binding.
- Initializer may create only policy-approved clients and must never rewrite
  approved policy; drift on an existing client fails closed.

## 7. Decision (required)

```
Decision: APPROVE | REJECT | DEFER
Reviewer:
Date:
Scope:
Rationale:
```

> Recorded disposition: **PENDING** (not supplied). Consequently **no
> trust-verification code was changed** and PR 17 acceptance remains STOPPED
> (S3-01). If D2 is REJECTED, the fallback in §5 is the proposed path and still
> requires an explicit decision.
