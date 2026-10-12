# PR 17 — Amendment #5 runtime secret boundary (SEC-01)

## 1. Configuration change

`IssuerConfig` no longer accepts an administrator username/password. The HTTP
runtime requires:

- `MTMF_AUTH_ATTESTATION_CLIENT_ID` (dedicated reader client id), and
- `MTMF_AUTH_ATTESTATION_CLIENT_SECRET` **or** `MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE`.

`HttpAdminRestReader` now performs a `grant_type=client_credentials` POST to
`{base}/realms/{realm}/protocol/openid-connect/token`, rejects non-`https`
bases and non-loopback hosts before sending any credential, and reads both the
token and every configuration response with a hard byte bound and duplicate-JSON
rejection. There is no password-grant or anonymous fallback.
`MTMF_AUTH_ADMIN_USERNAME`/`PASSWORD` are now used **only** by the privileged
one-shot initializer.

## 2. Executed runtime container inspection

The development host-network service container was run with the reader via a
**mounted secret file** (`MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE`).

| Check | Result |
| --- | --- |
| `/health/ready` | 200 |
| Real-token `POST /v1/authorization/evaluate` | 200 `ALLOW`, `Cache-Control: no-store` |
| `MTMF_` env names in the container | `MTMF_AUTH_ISSUER/AUDIENCE/JWKS/MANIFEST/POLICY`, `MTMF_AUTH_ADMIN_BASE/REALM` (endpoint only), `MTMF_AUTH_ATTESTATION_CLIENT_ID`, `MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE`, `MTMF_RUNTIME_*`, `MTMF_SERVICE_*` |
| Forbidden names present | **none** (`MTMF_MIGRATOR_*`, `MTMF_MIGRATOR_POSTGRES_PASSWORD`, `MTMF_POSTGRES_PASSWORD`, `MTMF_AUTH_ADMIN_USERNAME`, `MTMF_AUTH_ADMIN_PASSWORD`, `MTMF_AUTH_ATTESTATION_CLIENT_SECRET`) |
| Secret value in `podman inspect` | **0 occurrences** (only the `_FILE` path and the read-only mount are visible) |

## 3. Secret delivery

Preferred mechanism: a 0600 file mounted read-only at
`/run/secrets/mtmf-attestation-reader`, read via
`MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE`. The launcher writes the dev secret
to a 0600 file (never to argv). The compose file documents the plain-variable
form as the development placeholder and the `_FILE` form as preferred.

## 4. Residual

The development fixture's reader secret is deterministic
(`mtmf-attestation-reader-dev-secret`) and is not a production secret. The plan's
stop condition S5-03 does not apply because the value is not exposed in argv or
`podman inspect`.
