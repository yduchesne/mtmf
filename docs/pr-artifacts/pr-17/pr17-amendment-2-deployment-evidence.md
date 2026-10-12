# PR 17 — Amendment #2 deployment evidence (Part B)

**Status: PARTIAL — containerized service demonstrated end to end with host
networking and the approved issuer identity; the network/canonical-hostname
Compose topology and full volume destroy/recreate were not executed.**

## 1. Executed sequence (fresh)

| Step | Command (redacted) | Result |
| --- | --- | --- |
| Build image | `podman build -f Dockerfile.service -t mtmf-service:dev .` | exit 0 |
| Start issuer | `podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml up -d` | exit 0 |
| Wait issuer | `scripts/pr14-keycloak-evidence.py wait` | ready, issuer `https://127.0.0.1:28443/realms/mtmf-pr14-dev` |
| Reset + seed | host script (admin reset/migrate + live-HTTP `_seed`) | exit 0 |
| Run container | `podman run -d --network=host … localhost/mtmf-service:dev` | container up |
| Readiness | `GET http://127.0.0.1:28001/health/ready` | **200** `{"status":"ready"}` |
| Authenticated | real service+user tokens → `POST /v1/authorization/evaluate` | **200** `ALLOW` / `PERMITTED`, `cache-control: no-store` |

The container received only the restricted runtime credential, the rollout
limits, and the issuer-attestation credential; no migrator/owner/bootstrap
variable was present (verified via the container environment).

## 2. Initializer lifecycle

- Fresh initialization against real PostgreSQL + live Keycloak: exit 0.
- Re-run (idempotent): exit 0; no duplicate root/Tenant/Application/
  registration/subscription/binding; Keycloak client secret not rotated.
- Concurrency and conflict: `test_pr17_dev_initializer.py` (3 passed) —
  serialized concurrent runs and fail-closed conflicting root.
- Owner-only secret delivery: `/tmp/mtmf-dev-secrets/<client>.secret` mode
  `0600`, never printed.

## 3. Runtime privilege and secret isolation (A2-12)

- Container environment contains **no** `MTMF_MIGRATOR_*`, no
  `MTMF_POSTGRES_*` admin/owner variables, and no bootstrap credential.
- The only privileged-looking variable is `MTMF_AUTH_ADMIN_*` (the issuer
  attestation reader). The plan permits a read-only attestation credential;
  the current PR 14 design uses the realm admin for the fresh Admin REST
  manifest comparison. Restricting this to a dedicated read-only reader is
  recorded as a residual/deviation.
- The runtime PostgreSQL role's restricted privilege surface (exact EXECUTE
  allowlist, no direct table access) is verified by
  `test_postgres_runtime_security.py` / `test_runtime_privileges.py`.

## 4. Not executed / blockers

| Item | Reason |
| --- | --- |
| Compose network topology (`compose.dev.yaml`) end to end | issuer hostname unresolvable from host without `/etc/hosts` (no sudo) and the alias topology changes the issuer identity (STOP-01) |
| Canonical hostname `keycloak.mtmf.test` | needs host DNS control + approved issuer/manifest/TLS change |
| V13 full MTMF volume destroy/recreate | destroys the shared dev PostgreSQL volume used by the integration suite; not isolated enough to run safely in this environment |
| Second live Keycloak client (V12) | adding a client with the shared audience changes the approved whole-realm manifest (STOP-01) |

## 5. Critical finding — initializer client drifts the attestation manifest

The Amendment #1 initializer created the Keycloak client `mtmf-sample-app`.
The PR 14 fresh attestation compares the **whole realm** against the committed
`dev/keycloak/expected-config-manifest.json`, which does not contain that
client. Result: after the initializer runs, every authentication fails closed
with `ATTESTATION_DRIFT` (verified by running the attestor from inside the
service container: `AuthenticationError: attestation_drift`). Deleting the
added client restored `status: ok, drift_count: 0` and the containerized
authenticated `200 ALLOW` succeeded.

This is a genuine design conflict between PR 14 whole-realm attestation and
PR 17 per-Application client provisioning. It requires a reviewer decision
(update the reviewed manifest vs. scope attestation to security-relevant
clients); it is in the STOP register.
