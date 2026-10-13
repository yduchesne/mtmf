# PR 18 — Implementation Report

**Roadmap ID:** PR 18 — Official Python HTTP client and scoped authorization helper
**Branch:** `dev/mtmf-client-impl`
**Baseline commit:** `ad30ff50feb84d8e2e9a15f6ca01b2ac01ec05c7`
**Status:** implemented and verified on the working tip; **ready for human review, not DONE**.

## 1. Objective

Replace the `mtmf-client` stub with an independently installable, HTTP-only
consumer library that obtains an OAuth 2.0 Client Credentials **service**
token, propagates a separately verified **end-user** access token, calls the
frozen v1 `POST /v1/authorization/evaluate` endpoint, strictly validates the
response, and exposes an immutable context-bound expiring
`AuthorizationSnapshot` with fail-closed `is_allowed`/`require`.

## 2. Files delivered

| File | Purpose |
| --- | --- |
| `packages/mtmf-client/pyproject.toml` | Adds the single bounded HTTP dependency `httpx>=0.28,<0.29`. Depends only on `mtmf-api`. |
| `packages/mtmf-client/src/mtmf_client/errors.py` | Typed, redacted exception taxonomy. |
| `packages/mtmf-client/src/mtmf_client/config.py` | `ClientConfig`, `SecretProvider`, `FileSecretProvider`; HTTPS-only, no userinfo/fragment, fail-closed validation before any network call. |
| `packages/mtmf-client/src/mtmf_client/transport.py` | Bounded, redirect-refusing, `trust_env=False` HTTPS transport; TLS verified via explicit CA context; response-size caps. |
| `packages/mtmf-client/src/mtmf_client/credentials.py` | OAuth 2.0 Client Credentials service-token manager; monotonic cache, single-flight renewal, no refresh token. |
| `packages/mtmf-client/src/mtmf_client/snapshot.py` | `TrustedActorContext`, immutable `AuthorizationSnapshot`, `is_allowed`, `require`. |
| `packages/mtmf-client/src/mtmf_client/client.py` | `HttpMtmfClient.evaluate`, strict success/error handling, conservative monotonic deadline, client-bound helpers. |
| `packages/mtmf-client/src/mtmf_client/__init__.py` | Narrow public API exports. |
| `packages/mtmf-client/src/mtmf_client/py.typed` | Typing marker. |
| `packages/mtmf-client/README.md` | Consumer documentation. |
| `tests/unit/client/` | 74 test functions (122 parametrized cases) CL-U01–CL-U45. |
| `tests/integration/postgres/test_pr18_live_client.py` | Real Keycloak/Uvicorn/PostgreSQL slice, opt-in `MTMF_PR18_LIVE=1`. |
| `docs/ARCHITECTURE.md`, `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`, `docs/DEVELOPMENT_SETUP.md`, `docs/ROADMAP_V01.md` | Status and configuration documentation. |
| `uv.lock` | Regenerated with `uv lock` for the new workspace dependency. |

No `mtmf-api`, `mtmf-core`, `mtmf-service`, Alembic, SQL, Rust, Compose, or
PR 14 fixture file was modified.

## 3. Public API

```python
from mtmf_client import (
    ClientConfig, FileSecretProvider, SecretProvider, USER_AUTHORIZATION_HEADER,
    HttpMtmfClient, TrustedActorContext, AuthorizationSnapshot,
    is_allowed, require,
    MtmfClientError, ClientConfigurationError, ClientClosedError,
    ClientAuthenticationError, ActorContextError,
    RemoteAuthenticationError, RemoteEligibilityError, RemoteProtocolError,
    DependencyUnavailableError, AuthorizationDenied,
)
```

`AuthorizationSnapshot` is immutable and only the validated client path can
issue one; module helpers require the private local provenance marker and
the exact bound `TrustedActorContext`. `HttpMtmfClient.is_allowed`/`require`
add a strict same-client-instance check.

## 4. Security-relevant design decisions

1. **HTTPS-only, TLS-verified, no redirects.** `httpx.Client(verify=<CA
   context>, follow_redirects=False, trust_env=False)`. No `verify=False`,
   no proxy/netrc environment influence, no credential forwarding.
2. **Two independent tokens.** The service token is obtained via Client
   Credentials; the end-user token is supplied by the consumer and never
   decoded or refreshed by the client. The response carries no
   Application/Principal/Identity UUID and the client does not invent one.
3. **Strict frozen-v1 wire reuse.** `serialize_request`, `parse_response_json`,
   `parse_error_json` and `validate_response_for_request` from `mtmf-api`
   are reused unchanged; no second wire contract.
4. **No partial snapshot.** A snapshot is created only after the media type,
   size, parse, conformance, timestamp and effect/reason checks all succeed.
   Redirects, malformed errors and oversized bodies are protocol failures.
5. **Conservative monotonic expiry.** The deadline is the minimum of the
   receipt-relative and server-lifetime remainders (minus clock
   uncertainty), the configured `max_snapshot_ttl_seconds`, 300 seconds, and
   the 15-second sensitive ceiling. A monotonic rollback denies.
6. **Universal 15-second cap.** No authoritative Action sensitivity
   classifier is a public contract, so every snapshot is conservatively
   capped at 15 seconds (plan §6 Step 9, STOP condition 5 not triggered).
7. **No automatic authorization retry.** PR 17 exposes no machine-readable
   service-token-expiry signal, so the controlled 401 retry is deferred by
   contract and no unsafe retry exists.
8. **Redaction.** Secret-file contents, service tokens and user tokens never
   appear in `repr`, logs or exception messages.

## 5. Deviations

See `PR18_FAILURES_AND_DEVIATIONS.md`. Summary: deferred optional 401 retry;
conservative 15-second universal cap; PR 17 sensitivity classifier not
public; live-slice disposable user (additive) due to ephemeral development
credential loss; CL-I16 not executed.
