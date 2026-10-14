# PR19C_AMENDMENT04_TOPOLOGY_AND_SECURITY_REVIEW

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

## Effective isolated topology (verified by `podman inspect` after startup)

| Property | Default dev | Acceptance (verified) |
| --- | --- | --- |
| Compose project | `mtmf` | `mtmf-pr19c-acceptance` |
| Compose model | `compose.yaml`+`compose.dev.yaml` | `compose.pr19c-acceptance.yaml` (standalone) |
| Issuer | `…:28443/realms/mtmf-dev` | `https://keycloak.mtmf.test:29443/realms/mtmf-dev` |
| Keycloak host port | 28443 | `127.0.0.1:29443->8443` |
| PostgreSQL host port | 25432 | `127.0.0.1:29432->5432` |
| Service host port | 28001 | `127.0.0.1:29001->28001` |
| Keycloak volume | global `mtmf-dev-keycloak-data` | project-scoped `mtmf-pr19c-acceptance_mtmf-dev-keycloak-data` |
| PostgreSQL volume | project-scoped | `mtmf-pr19c-acceptance_mtmf-postgres-data` |
| CA / secrets | `/tmp/mtmf-dev-ca`, default secrets | `/tmp/mtmf-pr19c-acceptance-ca`, `/tmp/mtmf-pr19c-acceptance-secrets` |

Actual mounts (read-only inspection):
`mtmf-pr19c-acceptance_keycloak_1` -> `mtmf-pr19c-acceptance_mtmf-dev-keycloak-data:/opt/keycloak/data`;
`mtmf-pr19c-acceptance_postgres_1` -> `mtmf-pr19c-acceptance_mtmf-postgres-data:/var/lib/postgresql`.
The default `mtmf-dev-keycloak-data` volume is untouched and still present.

## Isolation enforcement in code

- `compose.pr19c-acceptance.yaml` declares both volumes with no `name:`/`external:` and no `container_name`. `_validate_compose_isolation` rejects a model with a global name, `external: true`, or `container_name` **before** any startup.
- `_assert_owned` refuses any acceptance-project-labeled container that is not `mtmf-pr19c-acceptance_*`.
- `_ports_free` fails (without killing anything) if 29432/29443/29001 are already published.
- `_default_inventory` compares default-project containers/volumes before/after.

## Issuer / TLS

The acceptance issuer/JWKS are literal constants validated by `_verify_issuer_constants`. The existing `scripts/mtmf-dev-probe.py` was given a narrow `--expected-issuer` (default = canonical 28443) so the acceptance issuer can be validated exactly without weakening the default check; the host and container probe required exact discovery `issuer`, JWKS URI, TLS/SAN and signing keys. No `verify=False` or fallback exists. The default launcher still requires the exact 28443 issuer (regression-tested).

## Secret custody

Secrets are staged `0700`/`0600`, reused when valid, and redacted from every captured line/error (`_redact`). No generated secret appears in logs or the diff. The service container receives only the restricted runtime role and the read-only attestation reader; the bootstrap admin/migrator credentials are confined to the initializer.
