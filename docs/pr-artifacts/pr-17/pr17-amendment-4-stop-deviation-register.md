# PR 17 — Amendment #4 STOP / deviation register

Approvals D1, D2, D3 and conditional V13 destructive testing were recorded by
the human reviewer on 2026-10-12 (see `pr17-amendment-4-decision-register.md`).
The previously blocking STOP items are cleared:

| ID | Status |
| --- | --- |
| S4-01 (D2 not approved) | **CLEARED** — approved and implemented |
| S4-02 (D1 not approved) | **CLEARED** — approved |
| S4-03 (D3 not approved) | **CLEARED** — approved for development; launcher implemented |
| S4-04 (realm/effective checks absent) | **CLEARED** — realm-security projection + effective client verification implemented |
| S4-05 (duplicate client not rejected) | **CLEARED** — explicit duplicate/ambiguity rejection |
| S4-09 (V13 ownership) | **CLEARED** — isolated disposable project created, destroyed, recreated; shared resources untouched |
| S4-10 (V12 two clients) | **CLEARED** — two genuine clients, CL01–CL07 pass |
| S4-11 (V incomplete) | **CLEARED** — V01–V16 executed and passing |

## Remaining residuals (not mandatory STOP)

| ID | Residual | Smallest resolution |
| --- | --- | --- |
| R-1 | Issuer attestation still uses the realm admin credential rather than a dedicated read-only reader. | Provision/approve a read-only attestation reader. |
| R-2 | The realm-security projection is a curated 18-field allowlist; a new security-relevant realm field not on the list is not compared. | Review/extend the field list when Keycloak adds security-relevant realm settings. |
| R-3 | Per-statement DB timeouts bound each statement; the total per-batch downstream budget is not contractually bounded. | Accept the documented allowance, or add a reviewed total-budget mechanism. |
| R-4 | `--network=host` removes the service container network-namespace isolation (development only). | Approve the canonical-hostname isolated topology as a future hardening. |
| R-5 | V13 reused the approved Keycloak realm (isolated PostgreSQL volume only); a new Keycloak port would change the trusted issuer identity. | Approve a per-topology issuer/manifest or a network-alias design if Keycloak state must also be recreated. |
| R-6 | The development initializer's user binding subject (`mtmf-dev-user`) is not a provisioned Keycloak user; authenticated live flows seed a real subject. | Provision a real Keycloak user and bind its `sub`. |

No unresolved mandatory STOP item remains; all are residuals for future
hardening. PR 17 is not merged and not marked DONE pending human review.
