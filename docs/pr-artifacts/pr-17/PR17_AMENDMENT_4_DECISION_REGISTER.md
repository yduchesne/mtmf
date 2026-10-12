# PR 17 — Amendment #4 decision register (D1 / D2 / D3)

> **UPDATE 2026-10-12 — HUMAN APPROVAL RECORDED.** The human reviewer explicitly
> approved **D1**, **D2**, and **D3**, plus **conditional V13 destructive testing**,
> on **October 12, 2026**. The approval references the exact scope recorded
> below. This unblocks the gated phases; implementation proceeds under that
> approval. The original PENDING records are retained beneath for traceability.

## D1 — acting-user credential carrier

| Field | Value |
| --- | --- |
| Proposed contract | `Authorization: Bearer <service-access-token>` + `X-MTMF-User-Authorization: Bearer <user-access-token>` |
| Scope | v1 development D1 profile only; TLS mandatory beyond loopback |
| Security conditions | reject missing/duplicate/malformed/wrong-class tokens; independent signed-token verification; same-client `azp`; redaction; proxy must strip injected copies |
| Existing enforcement | single-header extraction + duplicate rejection; independent PR 14 service/user verification; same-client D1; static error envelopes |
| **Decision** | **APPROVE** |
| Reviewer / date / scope | Human reviewer, **2026-10-12**, approval recorded in this register and cross-referenced by `pr17-amendment-4-acceptance-report.md`; scope = v1 development D1 profile only |
| Conditions | single-header extraction + duplicate rejection; independent signed-token verification; same-client `azp`; redaction; TLS outside loopback; proxy must strip injected copies |
| Evidence | `pr17-amendment-1-carrier-decision.md`; unit H11–H13; live V05 |

## D2 — independently anchored attestation architecture

| Field | Value |
| --- | --- |
| Proposed design | realm-security projection (committed) + static expected-client policy (independently approved, no secrets), checked freshly per authentication through the existing `canonical_manifest`/`_diff` seam |
| Exact scope | see `pr17-amendment-3-attestation-design-decision.md`; field inventory in `pr17-amendment-4-baseline.md` §3 |
| Current verifier | strict whole-realm: all clients (6 security fields + scopes + mappers) + realm name + clientScopes |
| Identified gaps | realm-wide security settings not compared; duplicate client IDs not explicitly rejected; effective inherited scopes/mappers not separately projected |
| Tradeoffs | splitting permits approved mutable development clients but requires proving unrelated clients cannot gain authority; fallback (pre-provision clients into the reviewed whole-realm manifest) is lower change but less flexible |
| **Decision** | **APPROVE** |
| Reviewer / date / scope | Human reviewer, **2026-10-12**, approval recorded in this register and cross-referenced by `pr17-amendment-4-acceptance-report.md`; scope = development trust profile; adds comprehensive realm-security projection, independently approved expected-client policy, effective-client verification, and explicit duplicate-client rejection |
| Conditions | preserve every existing PR 14 security invariant; fresh per-authentication attestation; no live-derived baseline, no auto-repair of drift, no secret rotation |
| Evidence | `pr17-amendment-3-attestation-diagnosis.md`, `pr17-amendment-3-attestation-design-decision.md`, `pr17-amendment-4-attestation-implementation.md` |

**Consequence:** S4-01 cleared; implementation proceeds per the approved design.

## D3 — development host-network topology

| Field | Value |
| --- | --- |
| Proposed topology | MTMF-only `podman run --network=host`, service binds `127.0.0.1`, retained issuer `https://127.0.0.1:28443`; development profile only |
| Scope | local development; not production or general deployment |
| Tradeoff | removes the service container's network-namespace isolation |
| **Decision** | **APPROVE (development only)** |
| Reviewer / date / scope | Human reviewer, **2026-10-12**, approval recorded in this register and cross-referenced by `pr17-amendment-4-acceptance-report.md`; scope = local development only, never production or general deployment |
| Conditions | service binds `127.0.0.1` only; retain approved issuer `https://127.0.0.1:28443`; no privileged credentials in the runtime container |
| Evidence | `pr17-amendment-3-deployment-evidence.md`; Amendment #2 container ALLOW |

**Consequence:** S4-03 cleared for development; production remains gated.

## Fallback (requires its own explicit decision)

If D2 is rejected: retain strict whole-realm attestation and pre-provision every
approved PR 17 client into a statically reviewed whole-realm manifest; the
initializer must validate/reuse, never introduce unapproved clients. This is not
selected by the agent.

## Review record

```
D1 Decision: APPROVE   Reviewer: Human reviewer   Date: 2026-10-12   Scope: v1 development D1 profile
D2 Decision: APPROVE   Reviewer: Human reviewer   Date: 2026-10-12   Scope: development trust profile (§ above)
D3 Decision: APPROVE   Reviewer: Human reviewer   Date: 2026-10-12   Scope: local development host-network only
V13 Decision: APPROVE (conditional destructive testing of newly created, exclusively MTMF-owned disposable resources)
             Reviewer: Human reviewer   Date: 2026-10-12
```

Cross-reference: `pr17-amendment-4-acceptance-report.md` §1.
