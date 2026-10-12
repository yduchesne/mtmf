# PR 17 — Security and deployment report

**Artifact directory:** `docs/pr-artifacts/pr-17/`.
**Scope:** authenticated HTTP PDP package, trust boundary, operational controls,
development initializer separation, and deployment wiring.

## 1. Trust boundary

The service is a Policy Decision Point (PDP); consuming applications remain
Policy Enforcement Points (PEPs). The only public surface is
`POST /v1/authorization/evaluate` plus liveness/readiness probes. External
consumers never reach `mtmf-core`, a local connector, or MTMF PostgreSQL.

Pipeline order (`mtmf_service.app`):

1. per-transport-peer rate admission (no forwarded header is trusted);
2. media-type / content-encoding gate (415);
3. bounded streamed body read with an actual byte count (413);
4. strict reverse-compatible PR 15 JSON decode (`mtmf_api.json_codec`);
5. service `Authorization: Bearer` token extraction (401) and the separately
   carried user token (`X-MTMF-User-Authorization`) extraction (403);
6. PR 14 verified actor composition (fresh zero-cache issuer attestation,
   independent service/user verification, same-client D1 binding, ordinary
   Tenant, persisted registration + subscription via PR 13 eligibility);
7. authoritative Role/context and Action-catalog resolution in a second
   UnitOfWork;
8. one shared core `AuthorizationContext` and one PR 16 Python batch call;
9. ordered core→public decision mapping with fail-closed overrides;
10. response conformance validation, one bounded UTC snapshot, PR 15
    serialization.

No DB transaction is held across the issuer/JWKS/Admin-REST calls (they complete
inside step 6 before the actor service opens its transaction).

## 2. Authenticated Application and acting user

- Service and acting-user tokens are verified independently by the PR 14 seam;
  a service token is never accepted as a user, and no caller-supplied UUID,
  body actor id, root flag, or `SYSTEM`/root Tenant selector can grant.
- Fresh issuer configuration attestation runs on **every** authentication
  operation; there is no positive attestation cache (unit case H32).
- `INELIGIBLE_*` outcomes never reach policy resolution; exceptions are
  whole-request errors, never a partial HTTP 200 and never a semantic DENY.
- Public codes are mapped exactly: 401 `UNAUTHENTICATED` (service class),
  403 `UNTRUSTED_ACTOR` (user proof/binding/Tenant), 403
  `INELIGIBLE_APPLICATION` (registration/subscription).

## 3. Decision mapping and non-disclosure

| Core decision | Public effect/reason |
| --- | --- |
| `ALLOW` | `ALLOW`/`PERMITTED` |
| `DENY`/`NO_MATCH` | `DENY`/`NO_PERMISSION` |
| `DENY`/`MATCHED_DENY` | `DENY`/`EXPLICIT_DENY` |
| `DENY`/`INSUFFICIENT_DOMINANCE` | `DENY`/`INVALID_SCOPE` |
| `DENY`/`UNSUPPORTED_CONSTRAINT` | `DENY`/`UNSUPPORTED_RESOURCE` |
| `DENY`/`INVALID_CONTEXT`, `TENANT_MISMATCH`, `NO_MANAGEMENT_SCOPE` | internal `500 INTERNAL_ERROR` |

Unregistered Actions are overridden to `DENY/UNKNOWN_ACTION`; `mtmf_owned`
targets are overridden to `DENY/UNSUPPORTED_RESOURCE`. Neither can ALLOW
regardless of wildcard Permission text. No matched specificity, Role,
Permission, Principal/Identity/Application id, diagnostic, token, or JWKS data
appears on the wire (unit case H21).

## 4. Operational controls

- Body bound: 64 KiB actual streamed bytes (declared `Content-Length` checked
  early but never trusted); chunked/absent length enforced by the stream count.
- Rate control: bounded in-process token bucket keyed by transport peer,
  explicitly **not** cluster-global; saturation returns `429 RATE_LIMITED`.
- Snapshot TTL: default 60 s, absolute maximum 300 s, sensitive maximum 15 s.
  Because no authoritative sensitivity catalog exists, the default classifier
  bounds **every** response to 15 s. One `issued_at` clock reading per batch.
- Timeouts: bounded issuer/JWKS transport timeout and a bounded per-request
  evaluation timeout (threadpool + `wait_for`).
- `Cache-Control: no-store` on decisions and errors; interactive OpenAPI/docs
  disabled; permissive CORS absent; debug disabled; errors are static PR 15
  envelopes with a server-generated opaque trace id.
- Health: `/health/live` is process-only; `/health/ready` is fail-closed on
  database/dependency state and (development profile) completed initialization.

## 5. Privileged-initializer separation

- The HTTP runtime uses **only** the restricted `mtmf_runtime` PostgreSQL
  identity and never holds migrator/owner/bootstrap credentials.
- The opt-in one-shot `scripts/mtmf-dev-initialize.py` holds migrator/owner and
  development Keycloak bootstrap-admin credentials, refuses any non-development
  profile, and invokes only existing sanctioned primitives
  (`upgrade_to_head` + mandatory privilege postflight, `bootstrap_root`,
  `designate_steward`, `activate_tenant`, entity/membership/Role functions,
  PR 13 application/registration/subscription functions, PR 14 binding
  functions).
- No new schema, migration, stored function, or privileged runtime grant was
  introduced. The initializer never recovers root, creates a second root,
  resets a client secret, or broadens a grant; conflicting state fails closed.
- Initialization is serialized by a session advisory lock; restart re-validates
  and reuses exact state (real-PostgreSQL acceptance in
  `test_pr17_dev_initializer.py`).

## 6. Port and resource isolation

- MTMF keeps host-port prefix `2`: PostgreSQL `25432`; development Keycloak
  `28080`/`28443`; HTTP service `28001`. All non-Postgres publications bind
  loopback.
- MTMF tooling manages only the explicit `mtmf` Compose project. No generic
  podman discovery/prune and no modification of ATI/Digr/Darkula resources.

## 7. Residual risks and explicit non-goals

- **No production profile.** `ServiceSettings.validate_startup()` refuses
  `production`; production issuer trust and root authentication/recovery remain
  separate release gates.
- **No Action→dominance/sensitivity metadata.** `dominance_requirement` is
  `NONE` and every response uses the 15 s sensitive TTL. `mtmf_owned` targets
  deny. This is conservative but must be revisited with an approved authoritative
  Action metadata catalog.
- **Threadpool timeout.** A blocking DB/issuer call in the evaluation
  threadpool cannot be forcibly interrupted on timeout; the response is still a
  clean error and no partial body is emitted, but a runaway worker is possible
  until the underlying call returns.
- **In-process rate limiting** provides no cluster-global guarantee.
- **V01–V16 real acceptance NOT EXECUTED** (live Keycloak + real Uvicorn ASGI);
  the development Compose wiring is **not acceptance-verified** and
  `podman-compose 1.0.6` does not reliably support
  `service_completed_successfully`.
