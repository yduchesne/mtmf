# PR 18 — Security Report

**Status:** all listed threat tests pass; canonical security scan clean.

## 1. Threat checklist (plan §10)

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Credential exfiltration through redirects | `follow_redirects=False`; a 3xx is rejected as a protocol/auth error and its body is never read | `test_cl_u13_token_endpoint_redirect_is_not_followed`, `test_cl_u41_redirect_is_not_followed` |
| TLS disablement / insecure fallback | HTTPS-only endpoints; explicit verified CA context; `trust_env=False`; no `verify=False` anywhere | `test_cl_u03_rejects_unsafe_endpoints`, `test_cl_i14_invalid_ca_fails_closed` |
| Forged user token | The user token is propagated unchanged and never trusted by the client; MTMF re-verifies | `test_cl_i06_forged_user_token_is_rejected` |
| Wrong service/client binding | Service token from Client Credentials; local Application binding checked | `test_cl_i07_cross_client_pairing_is_rejected`, `test_cl_u15_wrong_context_and_tenant_are_rejected_before_post` |
| Token endpoint substitution / SSRF-like URL misuse | HTTPS-only, host required, no userinfo/fragment; no redirects; no proxy env | `test_cl_u03_rejects_unsafe_endpoints`, `test_cl_u13_token_endpoint_redirect_is_not_followed` |
| Unauthorized issuer/audience assumptions | Optional scope/audience only when configured; no JWT decoding; issuer trust is operator config | `test_cl_u06_scope_and_audience_only_when_configured`, README §Header trust boundary |
| Cross-Tenant/Org/actor/Application/resource snapshot replay | Exact context + request binding; client-instance provenance | `test_cl_u30`–`test_cl_u34`, `test_cl_i10`, `test_cl_i17` |
| Stale grant after revocation | Bounded monotonic expiry; no renewal on token refresh; new evaluations reflect the PDP | `test_cl_u38`, `test_cl_i09` |
| Malformed 200 with partial ALLOW | Strict parse + conformance before snapshot; no partial snapshot | `test_cl_u17`–`test_cl_u21` |
| Duplicate occurrence confusion | Exact occurrence required; ambiguous semantic tuple denies | `test_cl_u29` |
| Unbounded body/timeout | Connect/read/write/pool timeouts; declared and streamed byte bounds | `test_cl_u41_oversized_response_is_rejected` |
| Sensitive data in exception/repr/logs | Static redacted messages; secret provider repr suppressed | `test_cl_u40`, `test_cl_u42_token_failure_is_redacted`, `test_snapshot_repr_is_redacted` |
| Automatic token renewal extending authorization | Service-token renewal and snapshot expiry are independent | `test_cl_u38`, `test_cl_i11` |
| Tampered/reconstructed snapshot | Immutable snapshot; provenance marker; client-bound helpers | `test_cl_u45_tampered_snapshot_is_never_accepted`, `test_snapshot_direct_construction_is_guarded` |

## 2. Documented trust limit

`mtmf-client` **cannot independently authenticate the consuming
application's Python session**. The consumer must construct the
`TrustedActorContext` at its own authenticated server-side boundary and
supply the real end-user access token; a UUID, JWT payload, query parameter
or body field is not authentication. MTMF independently verifies the
propagated user token. This limit is documented in
`packages/mtmf-client/README.md`.

## 3. Dependency and secret hygiene

- `mtmf-client` dependency metadata contains only `mtmf-api` and `httpx`
  (`test_cl_u01_dependency_metadata_is_http_only`).
- Import graph in an isolated interpreter contains no `mtmf_core`,
  `mtmf_service`, FastAPI, PostgreSQL driver, Alembic, or native engine
  (`test_cl_u01_import_graph_has_no_forbidden_dependencies`).
- Secrets are read on demand from a file/provider, never stored on
  `ClientConfig`, never rendered by `repr`, and never placed in an
  exception. The live test asserts that the client secret and both bearer
  tokens are absent from failure text.

## 4. Canonical security scan

```bash
./build.sh --sec
# Bandit (packages + tests): 0 Medium, 0 High
# Semgrep: 297 rules, 197 targets, 0 findings
# exit 0
```

The two Bandit B108 (hardcoded `/tmp`) findings introduced by the new tests
were removed by deriving temporary paths from `tempfile.gettempdir()` /
`tmp_path`; no `# nosec` suppression was used. `tests/unit/client` and
`tests/integration/postgres/test_pr18_live_client.py` report **0 Medium /
0 High** under Bandit.
