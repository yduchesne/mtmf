# PR 17 — Amendment #5 reader permission matrix (SEC-01)

**Reader:** dedicated confidential client `mtmf-attestation-reader`
(`serviceAccountsEnabled=true`, no standard flow), authenticated with a
`client_credentials` grant at the **target realm** token endpoint. Its service
account holds exactly `view-realm`, `view-clients`, `query-clients` from
`realm-management`. No `manage-*`, `realm-admin`, `admin` or wildcard role.

**Proof method:** real Keycloak 26.8.0, real reader token. Denials return
`403`; the same class of operation succeeds under the separately held
privileged (bootstrap admin) test identity, so the denial is RBAC, not a
malformed request. Live test: `tests/integration/postgres/test_pr17_attestation_reader_permissions.py`
(`MTMF_PR17_LIVE=1`), 3 passed.

## Required reads — all HTTP 200

| Operation | Result |
| --- | --- |
| `GET /admin/realms/{realm}` | 200 |
| `GET .../client-scopes` | 200 |
| `GET .../client-scopes/{id}/protocol-mappers/models` | 200 |
| `GET .../clients?clientId={id}` | 200 |
| `GET .../clients/{uuid}/default-client-scopes` | 200 |
| `GET .../clients/{uuid}/optional-client-scopes` | 200 |
| `GET .../clients/{uuid}/protocol-mappers/models` | 200 |

## Mutation / escalation — all denied

| Operation | Result |
| --- | --- |
| `POST /admin/realms/{realm}/clients` | 403 |
| `PUT .../clients/{id}` | 403 |
| `DELETE` client (via disposable) | 403 |
| `POST .../users` | 403 |
| `PUT /admin/realms/{realm}` | 403 |
| `POST .../clients/{id}/protocol-mappers/models` | 403 |
| `POST .../users/{reader-sa}/role-mappings/...` (self-escalation) | 403 |

**State unchanged:** after the denied attempts, a disposable client that the
reader tried to create does not exist; the same creation succeeds under the
privileged identity and is then deleted. Before/after realm state is identical.

**Conclusion:** genuine least privilege. The runtime cannot administer the
issuer or escalate. No STOP (S5-01/S5-02 do not apply).
