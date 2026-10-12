# PR 17 — Amendment #1: acting-user token carrier decision (G1)

**Status: PENDING HUMAN APPROVAL. No approval is assumed. PR 17 remains
unmergeable and not DONE until a human reviewer records a disposition.**

## 1. Exact proposed interface

| Element | Value |
| --- | --- |
| Application credential | `Authorization: Bearer <service access token>` |
| Acting-user credential | `X-MTMF-User-Authorization: Bearer <user access token>` |
| Service-class predicate | signed `typ=Bearer`, `client_id` present and equal to signed `azp` (PR 14) |
| User-class predicate | signed `typ=Bearer`, signed `azp` and `sub`, absent `client_id` (PR 14) |
| Binding | service `azp` must equal user `azp` (same-client D1) |
| Attestation | fresh live Keycloak configuration attestation on **every** authentication operation, zero positive cache |
| Scope | development D1 profile only; TLS mandatory beyond loopback |

The header itself proves nothing. The token is accepted only after the full
independent PR 14 verification (signature, issuer, audience, time, class,
`azp`/`sub`/`client_id`), same-client binding, persisted credential→Application
and external-subject→Identity bindings, ordinary-Tenant membership, active
registration and subscription, and fresh issuer attestation.

## 2. Security analysis

- **Not an authentication shortcut.** A valid service token with a missing,
  duplicate, malformed, wrong-scheme, wrong-class, or forged user token never
  authorizes: service-slot failures are 401 `UNAUTHENTICATED`; user-slot and
  binding failures are 403 `UNTRUSTED_ACTOR`.
- **No caller identity authority.** No body field, `X-Forwarded-*`, `X-User-Id`,
  or caller-supplied UUID is used as identity. A service token can never act as
  a user.
- **One unambiguous carrier.** Exactly one `Authorization` and exactly one
  `X-MTMF-User-Authorization` header is required; duplicates are rejected
  (`request.headers.getlist`), which defeats comma-joined/ambiguous injection.
- **Proxy expectation.** A reverse proxy must forward the custom header intact,
  strip any client-injected copy, and never log credentials. Because the header
  is a security-sensitive transport contract, the deployment MUST terminate TLS
  for any non-loopback traffic.
- **Redaction.** Neither token is logged, echoed, or persisted; error bodies are
  static PR 15 envelopes with an opaque server trace id.

## 3. Alternatives explicitly rejected (would not be implemented without a
new approved design)

`X-Forwarded-User`, `X-User-Id`, caller-supplied Identity UUIDs, a
service-token-only actor, RFC 8693 token exchange (not implemented/frozen),
and any unsigned delegation assertion.

## 4. Reviewer decision required

- **APPROVE** the exact `X-MTMF-User-Authorization: Bearer` header for the
  v1 development-only D1 profile; or
- **REJECT** and supply an alternative independently verified carrier; or
- **DEFER** (which blocks PR 17 acceptance).

Record reviewer identity, date, reference, and exact approved scope here.

> Reviewer disposition: **_PENDING_** (not supplied during this execution).

## 5. Consequence

Because approval is absent, PR 17 **STOPs before merge** (plan §3, §13). All
independently safe verification described in the other Amendment #1 artifacts
was still executed and recorded.
