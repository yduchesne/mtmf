# mtmf-client

Official, HTTP-only Python client for the MTMF v1 batch-authorization API
(PR 18).

`mtmf-client` is a **consumer convenience library, not an authorization
authority**. MTMF remains the Policy Decision Point (PDP); the consuming
application remains the Policy Enforcement Point (PEP) and is responsible
for its own resource, row and Tenant isolation. An `ALLOW` capability is
never universal access to a resource.

## What it does

1. Obtains a **service** access token with OAuth 2.0 Client Credentials.
2. Propagates an independently authenticated **end-user** access token that
   the consumer's session layer supplies in a separate header.
3. Calls the frozen v1 `POST /v1/authorization/evaluate` endpoint.
4. Strictly validates the response against the original request using the
   `mtmf-api` codecs and conformance check.
5. Issues one immutable, context-bound, monotonically expiring
   `AuthorizationSnapshot`.
6. Exposes fail-closed `is_allowed` / `require` helpers.

It does not embed a policy evaluator, does not decode JWTs for trust, does
not follow redirects, and never retries an ambiguous authorization request.

## Installation

`mtmf-client` depends only on `mtmf-api` and `httpx`:

```bash
pip install mtmf-client
```

It imports no `mtmf-core`, `mtmf-service`, FastAPI, PostgreSQL, Alembic, or
native-engine code.

## Header trust boundary

A request carries two **separate** bearer credentials:

| Header | Meaning |
| --- | --- |
| `Authorization: Bearer <service>` | Client Credentials service token acquired by this library. |
| `X-MTMF-User-Authorization: Bearer <user>` | Independently authenticated end-user access token supplied by the consumer. |

`mtmf-client` cannot independently prove that the Python caller's session is
authenticated. The consumer's **server-side authenticated boundary** must
construct the `TrustedActorContext` from its own trusted session store and
supply the real end-user token. A caller-supplied UUID, JWT payload, query
parameter or body field is not authentication. MTMF re-verifies the user
token and derives the authoritative identity.

## Why snapshots are not bearer tokens

An `AuthorizationSnapshot` is bound to the exact Application/local session
actor, Tenant, optional Organization, and the exact ordered Action/resource
occurrences that were evaluated. `is_allowed`/`require` return true only
for the identical bound context and exact occurrence. A snapshot cannot be
replayed across a different actor, session, Application, Tenant,
Organization, resource, or non-matching Action occurrence, and it is
useless by itself. It is also not serializable into a transferable grant.

## Service-token renewal vs snapshot expiry

These lifetimes are **independent**:

- The service access token is cached per client instance and renewed
  proactively within a bounded leeway using monotonic time. OAuth refresh
  tokens are never requested, stored, or used.
- A snapshot's lifetime is derived from the server-issued `issued_at` /
  `expires_at` (bounded by 300 seconds, 60 seconds default, 15 seconds for
  security-sensitive Actions). The client currently caps **every** snapshot
  at 15 seconds because the authoritative sensitivity classifier is not a
  public contract.
- Renewing the service token **never** renews, extends or refreshes a
  snapshot. After its monotonic deadline, `is_allowed` returns `False` and
  `require` raises; no network I/O happens in the helpers.

Revocation may leave an already-issued, unexpired snapshot stale until its
bounded expiry; there is no instant-revocation promise. New evaluations
reflect the PDP's current decision.

## Exception taxonomy

| Exception | Meaning |
| --- | --- |
| `AuthorizationDenied` | `require` denied an unexpired, bound occurrence (policy DENY/unknown/absent/ambiguous). |
| `ClientAuthenticationError` | OAuth service-token acquisition/renewal failed. Never downgrades to an unauthenticated call. |
| `ActorContextError` | Missing/invalid user token or trusted actor/session binding, or a request Tenant/Organization that does not match the trusted context. |
| `RemoteAuthenticationError` | MTMF rejected the service credential (HTTP 401). |
| `RemoteEligibilityError` | MTMF rejected the actor/Application/subscription (HTTP 403). |
| `RemoteProtocolError` | Malformed, non-conformant, unexpected or oversized response; never a policy decision. |
| `DependencyUnavailableError` | Transient remote dependency or transport failure (HTTP 5xx/429, timeout). |
| `ClientClosedError` | The client is closed. |
| `ClientConfigurationError` | Invalid local configuration. |

No exception message contains a token, secret, response body or policy
detail.

## Example

```python
from uuid import UUID

from mtmf_api import (
    ActionRequest,
    AuthorizationBatchRequest,
    ResourceKind,
    ResourceTarget,
)
from mtmf_client import (
    ClientConfig,
    HttpMtmfClient,
    TrustedActorContext,
    require,
)

config = ClientConfig(
    base_url="https://pdp.example.test",
    token_endpoint="https://idp.example.test/realms/app/protocol/openid-connect/token",
    application_id=UUID("33333333-3333-4333-8333-333333333333"),
    client_id="sample-app",
    client_secret_file="/run/secrets/sample-app-client-secret",
    ca_bundle="/etc/ssl/certs/internal-ca.pem",
)

# Built at the server-side authenticated boundary from the consumer's
# own trusted session store; never from client input.
context = TrustedActorContext(
    actor_key="session-store-key",
    session_key="server-session-id",
    tenant_id=UUID("11111111-1111-4111-8111-111111111111"),
    application_id=config.application_id,
)

request = AuthorizationBatchRequest(
    tenant_id=context.tenant_id,
    organization_id=None,
    actions=(
        ActionRequest(
            request_id="check-1",
            action="urn:mtmf:iam:actions:system:principal:get-object",
            resource=ResourceTarget(
                kind=ResourceKind.APPLICATION_OWNED, resource_type="document", resource_id="row-42"
            ),
        ),
    ),
)

with HttpMtmfClient(config) as client:
    snapshot = client.evaluate(
        request,
        user_access_token=user_access_token,  # from the consumer's login
        context=context,
    )
    require(snapshot, context=context, request_id="check-1")

    # The application still enforces its own row/Tenant predicate.
    row = repository.load(owner_tenant_id=context.tenant_id, resource_id="row-42")
```

## Configuration

`ClientConfig` validates everything before any network call:

- HTTPS MTMF base URL and HTTPS token endpoint; no userinfo, no fragment,
  no `verify=False`, no redirects;
- expected local Application binding (`application_id`), OAuth `client_id`,
  and a secret reference (`client_secret_file` or a secret provider);
- optional `expected_issuer` (operator trust configuration, not JWT
  verification), `scope`/`audience` (only when the issuer supports them),
  and `ca_bundle` for development trust;
- bounded connect/read/write/pool timeouts, maximum response bytes, bounded
  renewal leeway, maximum snapshot TTL, and clock uncertainty.

No secret is ever rendered by `repr`, logged, or placed in an exception.

## Testing / live acceptance

- Deterministic unit/contract tests live in `tests/unit/client/`.
- The real Keycloak/Uvicorn/PostgreSQL vertical slice is
  `tests/integration/postgres/test_pr18_live_client.py`, opt-in via
  `MTMF_PR18_LIVE=1`.
