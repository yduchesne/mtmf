# PR 17 — Amendment #4 V12 / V13 evidence

## V12 — two independent Keycloak clients and MTMF Applications — PASS (live)

Two genuine, independently approved clients (`mtmf-evidence-same-client` and
`mtmf-evidence-same-client-b`) with distinct `client_id`, secrets, MTMF
Application bindings, registrations, subscriptions and user subject bindings
(`mtmf-user-bob` / `mtmf-user-carol`). Both are in the approved
`expected-client-policy.json`. `dev/keycloak/setup-realm.py` provisions both.

| ID | Case | Result | Test node |
| --- | --- | --- | --- |
| CL01 | Service A + user A, valid context → ALLOW | PASS | `test_cl01_client_a_allows` |
| CL02 | Service B + user B, valid context → ALLOW | PASS | `test_cl02_client_b_allows` |
| CL03 | Service A + user B → deny | PASS | `test_cl03_client_a_service_with_client_b_user_is_rejected` |
| CL04 | Service B + user A → deny | PASS | `test_cl04_client_b_service_with_client_a_user_is_rejected` |
| CL05 | A token with B-only Tenant → deny | PASS | `test_cl05_client_a_with_foreign_tenant_is_rejected` |
| CL06 | Unapproved client with valid JWT → fail closed | PASS | `test_cl06_unapproved_client_is_rejected` |
| CL07 | Mutate B's client config → B fails; A unaffected | PASS | `test_cl07_client_b_drift_does_not_affect_client_a` |
| CL08 | Remove B's binding/policy → fail closed | PASS (policy/approval path) | AT03/AT04/CL06 |
| CL09 | Re-run initializer → no duplicate/secret rotation | PASS | `test_pr17_dev_initializer.py`, live re-run |
| CL10 | Fresh attestation per operation, no positive cache | PASS | `test_v07_no_positive_attestation_cache` |

Cross-client negatives returned **zero ALLOW decisions** (403 / fail-closed).
CL07 demonstrates per-client independence: B's drift fails only B's operation
while A continues under its own approved configuration and the realm projection.

## V13 — disposable MTMF-only destroy/recreate — PASS

Conditional destructive testing approved 2026-10-12 for **newly created,
exclusively MTMF-owned disposable resources**. Executed with a dedicated,
uniquely named isolated environment (no shared resource targeted):

| Step | Evidence |
| --- | --- |
| Isolated resources created | `podman volume mtmf-v13-pg-data`, container `mtmf-v13-pg` (`postgres:18`, loopback `25433`) |
| Roles provisioned | `scripts/mtmf-provision-roles.py` against `25433` |
| Fresh bootstrap | initializer exit 0; isolated DB `root=1, active tenant=1, application=1, active registration=1, active subscription=1` |
| Fresh attestation + HTTP ALLOW | service container on the isolated DB → `/health/ready` 200 and real `POST` → `200 ALLOW`, `Cache-Control: no-store` |
| Destroy | `podman rm -f mtmf-v13-svc mtmf-v13-pg` + `podman volume rm -f mtmf-v13-pg-data` (exact new resources only) |
| Recreate from empty volume | new volume + container + role provisioning + initializer exit 0 → again `1|1|1|1|1` |
| Shared resources untouched | before/after inventory: `mtmf_mtmf-postgres-data`, `mtmf-pr14-keycloak-data`, `mtmf_postgres_1` (healthy), `mtmf-pr14-keycloak_keycloak_1` all unchanged |

No `podman system prune`/`volume prune`/cross-project command was used. The
approved issuer `https://127.0.0.1:28443` was reused (the isolated database
shared the approved Keycloak realm), so no trusted issuer identity changed.

Residual: the isolated Keycloak state was preserved (reused) rather than
recreated, because a new Keycloak on a new port would change the trusted issuer
identity/manifest; the V13 volume destruction covered the PostgreSQL state.
