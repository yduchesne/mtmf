# mtmf-reference-app

A minimal, **independently deployed** MTMF reference consumer and Policy
Enforcement Point (PEP) for roadmap PR 20A. It exists to prove the MTMF
consumer contract end to end; it is an **example, not a framework**.

> **Non-production status.** This application is development/acceptance
> tooling. Do not deploy it as a production service. Its SQLite store, fixture
> loader, and single-Action policy fixture are deliberately minimal.

## What it demonstrates

The app owns a small Tenant-scoped `documents` resource in its **own** SQLite
database (never MTMF's PostgreSQL). A request to read a document is disclosed
only when **all four** conditions hold:

1. the app has independently authenticated the end user at its own HTTP
   boundary;
2. the document is present in the app's own Tenant-scoped store;
3. MTMF returned a verified, bound, unexpired `ALLOW` for the exact Action and
   the exact document `ResourceTarget`;
4. the app itself enforced that result against the loaded row.

None of these can be replaced by a client-provided identifier or a locally
invented policy decision.

## Trust boundaries

- The app **is** the PEP. MTMF **is** the PDP. The official `mtmf-client` is a
  transport/conformance library, **not** a policy decision point.
- The app verifies the inbound end-user access token cryptographically against a
  pinned issuer/JWKS/audience (RS256, token-type and temporal checks). A decoded
  but unverified JWT is never trusted.
- `TrustedActorContext` is built only from the verified subject, a server-owned
  subject→Tenant fixture mapping, the trusted Application UUID, and a
  process-local HMAC session key. No request-supplied Tenant, actor,
  Application, or session is trusted.
- The `ResourceTarget` is derived from the actually loaded row, never from a
  caller-selected target. An `ALLOW` capability is never treated as universal
  access.
- The app never accepts `X-MTMF-User-Authorization` from a caller; only the
  official client constructs that outbound header.
- Errors fail closed: 401 for unauthenticated, 403 for policy/eligibility denial,
  404 for missing/malformed/cross-Tenant documents, 503 for dependency or
  verification failure. No document body is ever written before `require`
  succeeds, and every document/error response sets `Cache-Control: no-store`.
- The app imports no `mtmf-core`/`mtmf-service`, opens no MTMF database
  connection, embeds no policy evaluator, and never disables TLS verification.

## Endpoints

| Method | Path | Meaning |
| --- | --- | --- |
| `GET` | `/health/live` | liveness |
| `GET` | `/health/ready` | readiness (config + SQLite schema usable) |
| `GET` | `/v1/documents/{document_id}` | authenticated, Tenant-scoped document content read |
| `GET` | `/v1/documents/{document_id}/metadata` | metadata-only read (`id` + `title`, never `body`) |
| `POST` | `/v1/documents/batch-read` | bounded multi-document content read with all-or-nothing disclosure |
| `POST` | `/v1/documents/batch-access` | bounded mixed metadata/content batch with atomic disclosure |

Single-document success body:
`{"id": "<canonical UUID>", "title": "...", "body": "..."}`.

### Batch read semantics

Request: `{"document_ids": ["<canonical UUID>", ...]}` with **1–16 unique**
canonical UUIDs and no other fields. Duplicates, malformed/non-canonical
UUIDs, excess/missing entries, unknown fields, and a malformed body are
rejected with `400` **before any MTMF call**. The route accepts no Action,
Tenant, Application, or target parameter from the caller.

Success body: `{"documents": [{"id": ..., "title": ..., "body": ...}, ...]}`
in request order. The app resolves **every** row against its Tenant-scoped
store first; any absent or cross-Tenant row is a generic `404` with no
evaluation and no body. It then sends **one** MTMF batch (one occurrence per
loaded row, `request_id="document-read-<zero-based-index>"`), calls `require`
for every occurrence in order, and only then serializes content. A single
non-ALLOW occurrence is `403` with **zero** document bodies (atomic disclosure;
no partial-allow). ### Metadata read

`GET /v1/documents/{document_id}/metadata` is a genuine second operation with
its own exact Action `urn:mtmf:iam:actions:system:document:read-metadata` and a
server-defined Tenant-scoped metadata-reader Role. Success is
`{"id": ..., "title": ...}` and **never** includes a `body`. A content-read
grant alone does not authorize metadata, and a metadata-read grant alone does
not authorize content.

### Mixed metadata/content batch

`POST /v1/documents/batch-access` accepts exactly
`{"operations": [{"document_id": "<canonical UUID>", "operation":
"metadata"|"content"}, ...]}` with 1–16 entries, no unknown keys, and no
duplicate `(document_id, operation)` pair (the same id with different
operations is required and legal). The operation string is a closed server enum
mapped to the two server-defined exact Actions; it never selects policy by
itself and the caller cannot supply an Action, Tenant, Application, or target.
All distinct documents are resolved first (any absent/cross-Tenant row is a
generic `404` with no MTMF call), one ordered MTMF batch is evaluated, and
`require` is called for every occurrence before serialization. A single
non-ALLOW occurrence is `403` with zero results. The success shape is
`{"results": [{"operation": ..., "document": {...}}, ...]}` in input order;
a `metadata` result never contains a `body` key.

There is no list/create/update/delete/admin/generic-authorize
endpoint and no per-document fallback.

## Configuration

All configuration is strict and fail-closed (HTTPS-only endpoints, private
secret file, trusted issuer/audience, existing CA bundle and fixture mapping):

| Variable | Meaning |
| --- | --- |
| `MTMF_REFERENCE_APP_ISSUER` | Trusted OIDC issuer (HTTPS, no trailing slash) |
| `MTMF_REFERENCE_APP_USER_AUDIENCE` | Expected user access-token audience |
| `MTMF_REFERENCE_APP_MTMF_BASE_URL` | MTMF PDP base URL (HTTPS) |
| `MTMF_REFERENCE_APP_TOKEN_ENDPOINT` | OAuth 2.0 token endpoint (HTTPS) |
| `MTMF_REFERENCE_APP_APPLICATION_ID` | Registered Application UUID |
| `MTMF_REFERENCE_APP_CLIENT_ID` | OAuth client id (Client Credentials) |
| `MTMF_REFERENCE_APP_CLIENT_SECRET_FILE` | Owner-only secret file (mode 0600) |
| `MTMF_REFERENCE_APP_CA_BUNDLE` | PEM CA bundle for issuer and MTMF TLS |
| `MTMF_REFERENCE_APP_SQLITE_PATH` | SQLite database path |
| `MTMF_REFERENCE_APP_FIXTURE_MAPPING_PATH` | Initializer-generated subject→Tenant mapping |

Optional bounded values: `MTMF_REFERENCE_APP_JWKS_CACHE_SECONDS`,
`MTMF_REFERENCE_APP_MTMF_TIMEOUT_SECONDS`, `MTMF_REFERENCE_APP_JWKS_TIMEOUT_SECONDS`,
`MTMF_REFERENCE_APP_RENEWAL_LEEWAY_SECONDS` (proactive OAuth service-token renewal
margin; the default 30s absorbs the token-endpoint round-trip so the client never
presents a service token the PDP considers expired).

## Package layout

```text
src/mtmf_reference_app/
  config.py          strict environment configuration + fixture mapping
  models.py          Document / fixture mapping value types
  store.py           Tenant-scoped SQLite store (parameterized SQL)
  auth.py            independent JWT/JWKS verification + session derivation
  app.py             FastAPI boundary and ordered PEP flow
  fixture_loader.py  explicit test-only document seeding
```

## Fixture-only policy

The read Action
`urn:mtmf:iam:actions:system:document:read-object` and matching Permission
`urn:mtmf:iam:permissions:system:document:read-object` are registered by the
privileged one-shot initializer (`scripts/pr20a-initialize.py`) and granted to a
new Tenant-defined Role through existing sanctioned primitives. No built-in
MTMF Role, protected manifest, migration, or runtime grant is modified.

Documents are seeded only by the explicit fixture loader:

```bash
python -m mtmf_reference_app.fixture_loader \
  --manifest /run/fixtures/documents.json \
  --sqlite /data/reference-app.db
```

The loader is idempotent for identical rows and fails closed on any differing
existing row.

## Tests

Deterministic unit tests (fake outbound transport / fake issuer material only):

```bash
uv run pytest examples/mtmf-reference-app/tests \
  --cov=mtmf_reference_app --cov-fail-under=85
```

The real deployed vertical slice is the opt-in black-box suite
`tests/e2e/reference_app/test_pr20a_live_reference_app.py`, driven by
`scripts/pr20a-reference-acceptance.py` (see
[docs/DEVELOPMENT_SETUP.md](../../docs/DEVELOPMENT_SETUP.md)). It requires an
already-deployed stack and genuine Keycloak-issued tokens; a test-owned in-process
app is never a substitute.

## Container build

```bash
podman build -f examples/mtmf-reference-app/Dockerfile .
```

The image installs only the official `mtmf-api`/`mtmf-client` distributions,
FastAPI/Uvicorn, PyJWT, httpx, and the SQLite stdlib.

## Manual smoke check

```bash
curl -sS http://127.0.0.1:29511/health/ready
curl -sS -H "Authorization: Bearer <verified-user-access-token>" \
  http://127.0.0.1:29511/v1/documents/<document-uuid>
```

Expected: `200` with exactly the seeded document for an authorized user; `403`
for a verified same-Tenant user without the grant; `401` without a valid token;
`404` for a missing or other-Tenant document.
