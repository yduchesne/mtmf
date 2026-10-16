# Multi-IdP Authentication and Issuer Assurance — Architecture Review Candidate

**Status:** Proposal only; no runtime change or release assignment. Track as [R-001](ROADMAP.md).

## Current implementation (verified against source)

The development-only Keycloak profile composes a shared `JwksKeyProvider` and `PyJWTTokenVerifier` for service and user tokens. JWKS retrieval is lazy; the default key cache is 300 seconds, and refresh attempts are throttled to at most one every 5 seconds per provider instance. An unknown `kid` can trigger a refresh. An expired cache is refreshed on demand, not by a background worker. Review the throttle behavior for cached keys after expiration.

`AuthenticatedActorContextService.resolve` performs realm attestation **before** verifying both tokens and performs client attestation for **each** verified token (even when both have the same `azp`). The `BaselineConfigurationAttestor` performs fresh Keycloak Admin REST reads with **no positive caching** and compares a reviewed realm-security manifest and approved per-client policy. `HttpAdminRestReader.get` obtains a new client-credentials token before every Admin REST GET. Thus JWKS caching does **not** eliminate IdP network calls from the authenticated request path. Any attestation failure fails closed.

This design protects against issuer configuration drift, including changes to realm token policy, client flows, scopes, and protocol mappers. It also couples availability and latency of MTMF authentication to Keycloak's privileged administrative API.

## Proposed architectural boundary

**Authentication (mandatory, request path):** Validate signed tokens against explicitly configured issuer trust and policy; verify signature, key, audience, time, token class and client binding; resolve only authoritative MTMF identities, Application registration, Tenant membership and subscription. Continue default-deny semantics.

**Issuer assurance (policy-governed, separate concern):** Assess whether a configured issuer's administrative settings conform to an independently reviewed baseline. The Keycloak adapter may use Admin REST; other providers may expose different controls or no comparable administrative API. An OIDC issuer's lack of an admin API is not, by itself, a JWT validation failure; whether assurance is mandatory is a separate, explicit deployment security decision.

**Credential classification:** Do not universalize Keycloak `azp` and `client_id` semantics. Define per-provider evidence rules mapping verified claims and approved issuer policy to a provider-neutral service or interactive-user identity. Require non-ambiguous evidence and prevent client confusion and impersonation.

**Freshness and failure:** Define the attestation snapshot's maximum age, how drift invalidates trust, how issuer outages affect new and ongoing requests, and whether the deployment requires an assurance adapter. If assurance is mandatory, expired or failed assurance must never silently downgrade to ordinary JWT validation. Keep bounded cache and concurrency protections for JWKS and assurance reads.

## Decisions required before implementation

- Which production IdPs and token profiles are supported, and which verifiable claims establish service/user token class?
- What assurance modes are supported and what is the default for production? Is lack of provider administrative attestation acceptable under a documented trust model?
- What are the maximum attestation age, refresh cadence, failure grace policy (if any), and alerting requirements?
- How are Keycloak development compatibility, admin-reader privileges, rotation, and issuer outage tested?
- What are the deployment and rollout gates, including the separately blocked production issuer/root authentication and recovery requirements?

## Explicit non-goals for this documentation PR

No new IdP integration, no runtime change, no reduction in current Keycloak attestation requirements, no production enablement, and no assignment to v0.1 or another release.
