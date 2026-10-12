# PR 17 — Amendment #3 baseline reconciliation

**Branch:** `dev/pr17-http-service` (continued). **Verified head:** `040f8d0`
(`963c9cc` feature). **`origin/main`:** `4eea688`. Clean working tree.

## 1. Actual artifact inventory (not guessed)

`docs/pr-artifacts/pr-17/` contains the Amendment #1 and #2 reports with the
following verified names: `pr17-baseline-reconciliation.md`,
`pr17-security-and-deployment-report.md`, `pr17-acceptance-report.md`,
`pr17-amendment-1-{baseline,carrier-decision,live-matrix,deployment-evidence,timeout-evidence,acceptance-report,stop-deviation-register}.md`,
`pr17-amendment-2-{baseline,network-diagnosis,deployment-evidence,timeout-evidence,live-matrix,security-review,acceptance-report,stop-deviation-register}.md`.

## 2. Verified implementation facts

| Fact | Value |
| --- | --- |
| Attestation module | `packages/mtmf-service/src/mtmf_service/authentication/attestation.py` |
| Projection builder | `canonical_manifest(reader, realm)` |
| Comparator | `BaselineConfigurationAttestor.attest(profile)` + strict `_diff` |
| Expected manifest | `dev/keycloak/expected-config-manifest.json`, sha256 `07d8f8169763c9f7b461784e3d66d768becd67329d81c4e6566e80a5174894fb` |
| Manifest top-level keys | `realm`, `clients`, `clientScopes` |
| Per-client fields | `clientId`, `enabled`, `publicClient`, `serviceAccountsEnabled`, `standardFlowEnabled`, `directAccessGrantsEnabled`, `implicitFlowEnabled`, default/optional client scopes, normalized protocol mappers |
| Realm-level settings | **only the realm name** is captured — token lifetimes, flows and auth policies are **not** in the projection |
| Initializer order | `DevelopmentBootstrap.run()` performs `ensure_client()` per Application, then `verify_issuer()`; `ensure_client` creates the client if absent |
| Fixture clients | `dev/keycloak/setup-realm.py` provisions the PR 14 evidence clients; the expected manifest has **15** clients |
| Keycloak fixture | `dev/keycloak/compose.yaml`, image `quay.io/keycloak/keycloak:26.8.0-1`, project `mtmf-pr14-keycloak` |
| Environment | Podman 4.9.3, `podman-compose` 1.0.6, no passwordless sudo (no `/etc/hosts` control) |

## 3. Capability classification

| Capability | Classification |
| --- | --- |
| PR 17 HTTP PDP, PR 15 contract, PR 14 trust, PR 13 eligibility, PR 16 Python batch | DONE + VERIFIED (unit/ASGI + live) |
| Runtime DB timeouts, bounded admission, permit race | DONE + VERIFIED (real PostgreSQL) |
| Containerized service (host-network) ALLOW/DENY | DONE + VERIFIED (Amendment #2) |
| Whole-realm attestation vs initializer-created client | **BLOCKED** (reproduced; design approval D2 required) |
| Per-client independent expected configuration | NOT STARTED (D2) |
| Realm-wide security-setting projection (flows/lifetimes) | NOT STARTED (D2; today only the realm name is captured) |
| Acting-user carrier approval | BLOCKED (D1) |
| V08 live DB outage/recovery | PARTIAL (unit only) |
| V12 two live clients | PARTIAL (single client) |
| V13 destroy/recreate | NOT EXECUTED |
| Production issuer/root recovery | BLOCKED (separate release gate) |

## 4. Baseline test evidence (historical, re-run in this amendment)

Amendment #2 reported 1,762 QA / 90.04% coverage, 564 integration passes /
41 opt-in skips, PR 17 live 19/19, PR 14 live 22/22. These are baselines only;
Amendment #3 re-runs the affected gates on its own tree.

## 5. Approval gates carried into Amendment #3

- **D1** acting-user carrier: PENDING.
- **D2** attestation architecture: PENDING (no trust-semantics change permitted).
- **D3** host-network development topology: PENDING.
