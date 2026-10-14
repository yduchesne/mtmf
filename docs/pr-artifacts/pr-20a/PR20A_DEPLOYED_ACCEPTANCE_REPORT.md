# PR20A_DEPLOYED_ACCEPTANCE_REPORT

**PR:** roadmap PR 20A — MTMF Reference Application Foundation
**Acceptance launcher:** `scripts/pr20a-reference-acceptance.py`
**Live suite:** `tests/e2e/reference_app/test_pr20a_live_reference_app.py`
**Raw launcher log:** `/tmp/pr20a-acceptance.log` (the sanitized result is
reproduced below; no token or secret is included).

## 1. Deployed topology (isolated project `mtmf-pr20a-acceptance`)

| Service | Image/build | Container | Host publication |
| --- | --- | --- | --- |
| PostgreSQL 18 | `docker.io/library/postgres:18` | `..._postgres_1` (`b8919d76f246`) | `127.0.0.1:29532` |
| Keycloak 26.8.0-1 | `quay.io/keycloak/keycloak:26.8.0-1` | `..._keycloak_1` (`2c45c647785b`) | `127.0.0.1:29543` |
| Keycloak TLS forwarder | `python:3.14-slim` | `..._forwarder_1` (`855a24eeb32f`) | internal only |
| Restricted MTMF service | `Dockerfile.service` | `..._service_1` (`732577236cd8`) | `127.0.0.1:29501` |
| MTMF TLS terminator | `scripts/pr20a-service-tls-proxy.py` | `..._service-tls-proxy_1` (`46c0810b566b`) | internal only |
| Reference app (PEP) | `examples/mtmf-reference-app/Dockerfile` | `..._reference-app_1` (`90890e1b4c93`, uid `10001(app)`) | `127.0.0.1:29511` |
| Privileged initializer | `Dockerfile.service` | one-shot `run --rm` (exits 0) | none |

- Canonical issuer for this topology:
  `https://keycloak.mtmf.test:29543/realms/mtmf-dev` (host and container namespaces).
- Reference app → MTMF base URL: `https://mtmf.mtmf.test:29501` (internal alias to
  the TLS terminator, verified against the development CA; no TLS bypass).
- All host publications bind loopback. No `container_name`; all volumes are
  project-scoped.

## 2. Fixture identifiers (non-secret, deterministic)

| Item | Value |
| --- | --- |
| Tenant UUID | `17ab63f3-16d9-57e9-a7a1-e42b9f0c0850` (stable `uuid5`) |
| Application UUID | `dcc867e4-3841-59aa-b716-e88741661a13` (stable `uuid5`) |
| OAuth client | `mtmf-evidence-same-client` (approved expected-client policy) |
| Action | `urn:mtmf:iam:actions:system:document:read-object` |
| Permission | `urn:mtmf:iam:permissions:system:document:read-object` |
| Fixture Role | `urn:mtmf:iam:roles:tenant:17ab63f3-...:reference-document-reader` |
| Allowed document | `d0c0a1e0-0001-4000-8000-000000000001` |
| Other-Tenant document | `d0c0a1e0-0002-4000-8000-000000000002` |
| Allowed user | `mtmf-user-alice` (verified Keycloak subject) |
| Denied user | `mtmf-user-bob` (verified Keycloak subject, same Tenant, no grant) |

Keycloak subject identifiers are realm-instance data and therefore differ per
recreate; they are recorded only in the runtime fixture mapping, never in the
repository.

## 3. Live L01–L05 results

Genuine Keycloak tokens were obtained through the approved scripted
Authorization Code + PKCE fixture. No signed JWT was fabricated.

| ID | Scenario | Observed | Evidence |
| --- | --- | --- | --- |
| L01 | allowed user GET of seeded document | **HTTP 200** + exact seeded JSON | reference-app log shows `event=mtmf_evaluate document=d0c0a1e0-...0001` then `event=document_allowed document=d0c0a1e0-...0001`; httpx log shows `POST https://mtmf.mtmf.test:29501/v1/authorization/evaluate "HTTP/1.1 200 OK"` |
| L02 | denied same-Tenant user GET of the **same** document | **HTTP 403**, no body | evaluate count increases by exactly one, then `event=access_denied`; authoritative MTMF policy DENY |
| L03 | missing inbound token | **HTTP 401**, no body, **no evaluation** | evaluate count unchanged |
| L04 | valid user, nonexistent document | **HTTP 404**, no body, **no evaluation** | `event=document_not_found`; evaluate count unchanged |
| L05 | valid user, other-Tenant document | **HTTP 404**, no body | `event=document_not_found`; evaluate count unchanged |

Real outbound MTMF evaluation is corroborated by the reference-app container log:

```text
INFO mtmf_reference_app event=mtmf_evaluate document=d0c0a1e0-0001-4000-8000-000000000001
INFO httpx HTTP Request: POST https://keycloak.mtmf.test:29543/realms/mtmf-dev/protocol/openid-connect/token "HTTP/1.1 200 OK"
INFO httpx HTTP Request: POST https://mtmf.mtmf.test:29501/v1/authorization/evaluate "HTTP/1.1 200 OK"
INFO mtmf_reference_app event=document_allowed document=d0c0a1e0-0001-4000-8000-000000000001
INFO uvicorn.access 10.89.29.29 - "GET /v1/documents/d0c0a1e0-0001-4000-8000-000000000001 HTTP/1.1" 200
INFO mtmf_reference_app event=mtmf_evaluate document=d0c0a1e0-0001-4000-8000-000000000001
INFO mtmf_reference_app event=access_denied document=d0c0a1e0-0001-4000-8000-000000000001
INFO uvicorn.access 10.89.29.29 - "GET /v1/documents/d0c0a1e0-0001-4000-8000-000000000001 HTTP/1.1" 403
INFO uvicorn.access 10.89.29.29 - "GET /v1/documents/d0c0a1e0-0001-4000-8000-000000000001 HTTP/1.1" 401
INFO mtmf_reference_app event=document_not_found
INFO uvicorn.access 10.89.29.29 - "GET /v1/documents/d0c0a1e0-0009-4000-8000-000000000009 HTTP/1.1" 404
INFO mtmf_reference_app event=document_not_found
INFO uvicorn.access 10.89.29.29 - "GET /v1/documents/d0c0a1e0-0002-4000-8000-000000000002 HTTP/1.1" 404
```

The client secret and all end-user access tokens are deliberately absent from the
log excerpt and were never logged by the app.

## 4. Stability cycles — COLD / REPEAT / RECREATE

Executed by `scripts/pr20a-reference-acceptance.py acceptance`. Each cycle
executes **all** L01–L05 with zero skips and no retry masking failures.

```text
PR 20A acceptance stack is ready
.....                                                                    [100%]
5 passed in 8.14s
reference-app container 11bd89ecc9d3: 5 passed, 0 skipped
COLD-01 PASS
PR 20A acceptance stack is ready
.....                                                                    [100%]
5 passed in 7.49s
reference-app container 11bd89ecc9d3: 5 passed, 0 skipped
REPEAT-01 PASS
PR 20A acceptance stack is ready
.....                                                                    [100%]
5 passed in 8.19s
reference-app container 90890e1b4c93: 5 passed, 0 skipped
RECREATE-01 PASS
default stack inventory unchanged
```

- **COLD** = fresh isolated project, fresh volumes.
- **REPEAT** = same project, no state recreation (idempotent re-provision).
- **RECREATE** = explicit owned-project `down -v` teardown, fresh volumes.
- 3 cycles × 5 checks = **15 executed checks, 0 skipped**.
- The launcher verified the default `mtmf` stack inventory (containers and the
  default Keycloak volume) was byte-for-byte unchanged across the run.

## 5. Reproduction

```bash
uv run python scripts/pr20a-reference-acceptance.py preflight
uv run python scripts/pr20a-reference-acceptance.py acceptance
```

`up`/`down`/`test`/`recreate` are also available individually. Secrets and CA
material live under `/tmp/mtmf-pr20a-acceptance-secrets` and
`/tmp/mtmf-pr20a-acceptance-ca` (owner-only, uncommitted).
