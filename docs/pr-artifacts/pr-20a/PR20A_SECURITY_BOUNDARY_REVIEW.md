# PR20A_SECURITY_BOUNDARY_REVIEW

**PR:** roadmap PR 20A — MTMF Reference Application Foundation
**Scope:** the independently deployed `mtmf-reference-app` and its isolated
acceptance topology.

## 1. Trust boundaries

```text
black-box HTTP client
        |  Authorization: Bearer <verified end-user access token>
        v
mtmf-reference-app (PEP, own container, own SQLite volume)
  1. verifies the inbound user token cryptographically (pinned issuer/JWKS/audience)
  2. resolves a server-owned subject->Tenant fixture binding
  3. loads the document with a Tenant-scoped SQL predicate
  4. derives the ResourceTarget from the loaded row
  5. calls MTMF only via the official mtmf-client over HTTPS
        |  Authorization: Bearer <service> + X-MTMF-User-Authorization: Bearer <user>
        v
MTMF service (PDP, restricted mtmf_runtime)
        v
MTMF PostgreSQL
```

- The reference app is a real PEP: it owns its data and enforcement. It is not a
  PDP, does not evaluate policy, and never infers authorization from the Session
  Token or any caller-supplied identifier.
- MTMF remains the authoritative PDP; the official client is a transport/response
  conformance library, not an authority.

## 2. Verdicts against the reviewer checklist

### Architecture

- **Separate container and independent storage.** `reference-app` is its own
  Compose service with its own project-scoped `reference-app-data` SQLite volume.
  It never mounts the MTMF PostgreSQL data/socket.
- **No alternate PDP / direct DB / private imports.** The package installs and
  imports only `mtmf-api`, `mtmf-client`, FastAPI/Uvicorn, PyJWT, httpx, and the
  SQLite stdlib. It imports no `mtmf-core`/`mtmf-service` and opens no MTMF DB
  connection. `pyproject.toml` and the Dockerfile encode this boundary.
- **Fixture-only policy.** The document Action/Permission are registered and
  granted by the privileged one-shot initializer through existing primitives; no
  built-in Role/Permission manifest was modified and no runtime grant was added.

### Authentication and PEP

- **Cryptographic inbound verification.** `auth.py` uses PyJWT's `PyJWKClient`
  against the pinned `jwks_uri` with the development CA, verifies signature,
  `iss`, `aud`, `exp`, `iat`, `nbf`, and requires the claims. The JWT header
  `typ` must be one of `Bearer`/`at+jwt`/`JWT`; `ID`, `Refresh`, `Logout`, and
  absent/unknown types are rejected. The algorithm is pinned to RS256.
- **No bearer-token laundering.** The reference app never accepts
  `X-MTMF-User-Authorization` from an inbound caller; only the official client
  constructs that outbound header. Unknown/absent/bad tokens fail closed with a
  generic 401 before any policy evaluation.
- **Trusted context derivation.** `TrustedActorContext` is built only after
  verification, from the verified `(issuer, subject)`, a server-owned
  subject→Tenant fixture mapping, the trusted Application UUID, and a
  process-local HMAC session key derived from the verified token. No
  query/body/header Tenant, actor, Application, or session authority is trusted.
- **Row-derived target.** The `ResourceTarget` is constructed from the actually
  loaded row (`resource_type="document"`, `resource_id=<canonical row id>`),
  never from a caller-selected target. `.require` is called with the exact Action
  and target before serialization.
- **No body before ALLOW.** The document body is written only after `require`
  succeeds. Every error path returns a static non-sensitive message and
  `Cache-Control: no-store`.
- **Real same-Tenant DENY.** The denied subject is a genuine verified Keycloak
  user with a same-Tenant membership but no document Role; MTMF returns
  `DENY/NO_PERMISSION`, not a local 404.
- **Fail-closed error mapping.** `AuthorizationDenied`/`RemoteEligibilityError`
  → 403; `ActorContextError`/`RemoteAuthenticationError` → 401; store,
  protocol, authentication-of-service, dependency, and unexpected failures → 503.
  No exception trace or raw remote body is returned.

### Secrets, TLS, and transport

- The reference app receives only its OAuth client secret file (mode 0600), the
  public CA bundle, the trusted issuer/audience/Application ID, and the
  subject→Tenant mapping. It receives no DB owner/migrator/initializer/Keycloak
  admin credential.
- TLS verification is never disabled: `ClientConfig` is HTTPS-only; the app's CA
  bundle is the same development CA used by Keycloak and the internal MTMF TLS
  terminator. There is no `verify=False` anywhere in the example.
- Tokens, secrets, and document bodies are never logged. Structured log lines
  contain only `event=...` and the application document id.

### Deployment isolation

- Standalone `compose.pr20a-acceptance.yaml`, project `mtmf-pr20a-acceptance`,
  never layered on `compose.yaml`/`compose.dev.yaml`, no `container_name`, no
  globally named volumes, no `external: true`, loopback-only host publications.
- The launcher refuses to operate on foreign projects and verifies the default
  `mtmf` stack inventory is unchanged across the acceptance cycles.

## 3. Static checks

- `./build.sh --sec` (Bandit Medium/High + Semgrep) reports **0 findings**.
- The canonical Semgrep target set is `packages tests`; the new example was also
  scanned explicitly (`semgrep scan --config=auto examples`). It initially flagged
  `dockerfile.security.missing-user` for the reference-app image; the image now runs
  as unprivileged `uid 10001`, and the explicit example scan reports **0 findings**.
- Repository search confirms the example contains no `mtmf-core`/`mtmf-service`
  import, no `psycopg`/Alembic import, no `verify=False`, and no untrusted JWT
  decode.
- No protected manifest (`v001`–`v013`, built-in Role seed, runtime grants) and no
  v1 wire schema was modified.

## 4. Residual limitations (deferred to PR 20B)

- No cross-request snapshot cache: every document GET re-evaluates MTMF. Revocation
  staleness, outage/timeout matrices, mixed-batch, concurrency, and parity testing
  are PR 20B.
- The reference app runs as an unprivileged in-container user (`uid 10001`). Its
  client secret is delivered mode 0600 and ownership-handed to that UID by the
  privileged initializer; the acceptance secret directory is traverse-only (0711)
  so the 0600 file is reachable without ever becoming group/other readable. This is
  development acceptance tooling; production secret distribution is out of scope.
