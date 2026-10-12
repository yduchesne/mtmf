# PR 17 — Amendment #2 STOP / deviation register

| ID | Type | Record | Smallest human decision / remediation |
| --- | --- | --- | --- |
| A2-SD-01 | **STOP (STOP-02)** | Acting-user carrier `X-MTMF-User-Authorization: Bearer` still has **no human approval**. | Reviewer APPROVE / REJECT / DEFER with identity/date/scope in `pr17-amendment-1-carrier-decision.md`. Blocks final acceptance. |
| A2-SD-02 | **STOP (STOP-01)** | The development initializer creates a Keycloak client (`mtmf-sample-app`) that drifts the committed whole-realm attestation manifest, so authentication fails closed after initialization. | Decide: update/re-authorise the reviewed expected manifest, or scope attestation to security-relevant clients. |
| A2-SD-03 | Deployment blocker | Canonical issuer hostname (`keycloak.mtmf.test`) cannot be made to resolve from the host (no passwordless sudo for `/etc/hosts`) and would change the approved issuer identity/manifest (STOP-01). | Approve host DNS control and the issuer/manifest change, or accept the host-network dev candidate. |
| A2-SD-04 | Scope deviation | The executed containerized demonstration uses `--network=host` (preserves the approved issuer, reduces network isolation). | Approve host networking for dev, or approve the canonical network topology. |
| A2-SD-05 | Not executed (STOP-07) | V13 MTMF-only full volume destroy/recreate not run; shared dev PostgreSQL volume is not isolated enough. V12 second live Keycloak client not provisioned (manifest). | Provide an isolated disposable stack/volume and manifest approval. |
| A2-SD-06 | Not executed | V08 live HTTP database outage (stop PostgreSQL while serving) not run; DB outage covered at unit H18, privilege mismatch by the integration security suite. | Provide approval to stop/restart the shared MTMF PostgreSQL during acceptance. |
| A2-SD-07 | Residual security | Issuer attestation uses the realm admin credential rather than a dedicated read-only reader. | Approve/provision a read-only attestation reader. |
| A2-SD-08 | Residual | V05 different-client pair could only be exercised fail-closed at the audience/class gate; same-audience cross-client D1 is covered by the PR 14 live suite and unit H13. | Approve a second shared-audience client fixture for a direct live cross-client case. |
| A2-SD-09 | Residual | Per-statement DB timeouts bound each statement; the total per-batch downstream budget is not contractually bounded. | Accept the documented allowance, or add a reviewed total-budget mechanism. |
| A2-SD-10 | Gated non-goal | Production issuer trust and root recovery remain disabled/unimplemented. | Separate production release gate. |

No unresolved item is silently marked PASS. Where an item is STOP, the branch is
preserved and committed, and PR 17 is **not** marked DONE or merged.
