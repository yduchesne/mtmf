# PR 17 — Amendment #1: STOP / deviation register

**Not empty.** The following records are open at the end of the Amendment #1
execution. Per the plan, any missing carrier approval or live-V result is
**STOP**, not conditional PASS.

| ID | Type | Description | Smallest remaining decision / remediation |
| --- | --- | --- | --- |
| SD-1 | **STOP** | G1 acting-user carrier `X-MTMF-User-Authorization: Bearer` has **no human approval**. | Reviewer APPROVE / REJECT / DEFER with identity, date, scope. Blocks merge and DONE. |
| SD-2 | STOP-adjacent (environment) | Original V cases not fully live-executed: V01 (container Compose path), V04 (cancelled/expired), V05 (different-client/foreign-Org), V08 (live HTTP DB outage), V12 (second live client), V13 (volume destroy/recreate), V15 (rate/timeout). | Provide an isolated container issuer-hostname design and run the container path; the remaining negatives are covered deterministically and by the live actor/HTTP suites. |
| SD-3 | Deployment blocker | Containerized service cannot reach the trusted issuer at `https://127.0.0.1:28443`; host-run ASGI over loopback was used instead. | Approve a container-internal issuer URL/network-alias and expected-manifest update, or accept host-run dev topology. |
| SD-4 | Scope note | Initializer delivers the generated Keycloak client secret to an owner-only file (`0600`) under `MTMF_DEV_SECRET_DIR`, not a Podman secret. | Approve Podman-secret delivery as a follow-up if required before DONE. |
| SD-5 | Residual risk | Synchronous workers cannot be forcibly interrupted; downstream database statement/lock timeouts are not configurable via MTMF runtime config. | Add reviewed DB statement/lock timeout configuration; bounded admission already prevents unbounded accumulation. |
| SD-6 | Residual risk | Permit release races a worker that begins exactly at the deadline, transiently under-counting in-flight work by one. | A race-free bound requires a dedicated bounded executor; explicitly deferred per plan G4.3. |
| SD-7 | Tooling limitation | `podman-compose 1.0.6` cannot express `service_completed_successfully`. | Resolved by `scripts/mtmf-dev-stack.py`; honest that Compose alone is insufficient. |
| SD-8 | Gated non-goal | Production issuer trust and root authentication/recovery remain disabled and unimplemented. | Separate production release gate; PR 17 is development-only. |
| SD-9 | Test regression (fixed) | PR 17's refined failure categories left 6 stale PR 14 live assertions (`INELIGIBLE_CONTEXT`). | Fixed in this amendment; live suite now 22/22. |
