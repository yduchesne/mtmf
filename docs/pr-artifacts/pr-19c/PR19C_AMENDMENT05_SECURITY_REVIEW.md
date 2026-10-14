# PR19C_AMENDMENT05_SECURITY_REVIEW

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

- **Trust boundary:** the authoritative live tests are black-box HTTP clients of the Compose-managed service. Both tokens are independently issued by real Keycloak; the deployed service performs signature, issuer, audience, token-class, tenant and actor-binding verification. No in-process app, no ASGI transport, no monkeypatched verifier.
- **Runtime least privilege:** the service container uses only `mtmf_runtime`; privileged seeding and read-back occur in the separate test process with existing integration DB privileges. No migrator/superuser credential enters the service.
- **Exact authorization + audit:** the deployed service authorizes the exact Action with the steward guard and commits exactly one membership + one atomic audit row; an authorized duplicate is a no-op with no second audit. Verified against committed PostgreSQL state.
- **Default DENY:** non-steward, cross-Tenant and missing/wrong-slot token requests are rejected with zero membership/audit writes and opaque responses.
- **Isolation:** acceptance project `mtmf-pr19c-acceptance`, ports `29443/29432/29001`, project-scoped volumes, separate CA/secrets; default `mtmf` stack untouched (inventory compared). No `podman prune`/broad cleanup.
- **Secret custody:** generated secrets remain owner-only and redacted; no token, password or private key in logs/reports/diff.
- **Acceptance-only config delta:** the acceptance service is configured with the shared-audience evidence client (`MTMF_AUTH_SERVICE_AUDIENCE=MTMF_AUTH_USER_AUDIENCE=mtmf-same-client-api`, `MTMF_AUTH_ALLOW_SHARED_AUDIENCE=1`) mirroring the PR 14/17 live harness. This is an acceptance-only Compose setting; the default launcher still requires distinct canonical audiences at `:28443`.
- **Residual risk:** shared `mtmf_runtime` credential is application-verified, not DB-attested (unchanged).
