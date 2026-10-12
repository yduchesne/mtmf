# PR 17 — Amendment #4 decision register (D1 / D2 / D3)

**No decision has been supplied by a human. This is not approval.**
The coding agent must not sign on the reviewer's behalf.

## D1 — acting-user credential carrier

| Field | Value |
| --- | --- |
| Proposed contract | `Authorization: Bearer <service-access-token>` + `X-MTMF-User-Authorization: Bearer <user-access-token>` |
| Scope | v1 development D1 profile only; TLS mandatory beyond loopback |
| Security conditions | reject missing/duplicate/malformed/wrong-class tokens; independent signed-token verification; same-client `azp`; redaction; proxy must strip injected copies |
| Existing enforcement | single-header extraction + duplicate rejection; independent PR 14 service/user verification; same-client D1; static error envelopes |
| **Decision** | **PENDING** |
| Reviewer / date / scope | (not supplied) |
| Evidence | `pr17-amendment-1-carrier-decision.md`; unit H11–H13; live V05 |

## D2 — independently anchored attestation architecture

| Field | Value |
| --- | --- |
| Proposed design | realm-security projection (committed) + static expected-client policy (independently approved, no secrets), checked freshly per authentication through the existing `canonical_manifest`/`_diff` seam |
| Exact scope | see `pr17-amendment-3-attestation-design-decision.md`; field inventory in `pr17-amendment-4-baseline.md` §3 |
| Current verifier | strict whole-realm: all clients (6 security fields + scopes + mappers) + realm name + clientScopes |
| Identified gaps | realm-wide security settings not compared; duplicate client IDs not explicitly rejected; effective inherited scopes/mappers not separately projected |
| Tradeoffs | splitting permits approved mutable development clients but requires proving unrelated clients cannot gain authority; fallback (pre-provision clients into the reviewed whole-realm manifest) is lower change but less flexible |
| **Decision** | **PENDING** |
| Reviewer / date / scope | (not supplied) |
| Evidence | `pr17-amendment-3-attestation-diagnosis.md`, `pr17-amendment-3-attestation-design-decision.md` |

**Consequence while PENDING:** S4-01 applies — no PR 14 attestation
trust-semantics change is implemented.

## D3 — development host-network topology

| Field | Value |
| --- | --- |
| Proposed topology | MTMF-only `podman run --network=host`, service binds `127.0.0.1`, retained issuer `https://127.0.0.1:28443`; development profile only |
| Scope | local development; not production or general deployment |
| Tradeoff | removes the service container's network-namespace isolation |
| **Decision** | **PENDING** |
| Reviewer / date / scope | (not supplied) |
| Evidence | `pr17-amendment-3-deployment-evidence.md`; Amendment #2 container ALLOW |

**Consequence while PENDING:** S4-03 applies — the launcher/topology is not
finalized.

## Fallback (requires its own explicit decision)

If D2 is rejected: retain strict whole-realm attestation and pre-provision every
approved PR 17 client into a statically reviewed whole-realm manifest; the
initializer must validate/reuse, never introduce unapproved clients. This is not
selected by the agent.

## Review record

```
D1 Decision: PENDING   Reviewer:            Date:        Scope:
D2 Decision: PENDING   Reviewer:            Date:        Scope:
D3 Decision: PENDING   Reviewer:            Date:        Scope:
```
