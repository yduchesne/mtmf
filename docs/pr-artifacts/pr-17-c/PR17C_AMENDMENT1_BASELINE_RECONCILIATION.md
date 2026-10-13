# PR 17-C Amendment 1 — Baseline Reconciliation

**Base branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `f4d1905` (PR 17-C canonical issuer and development networking)
**Main comparator:** `669337c1b496a5660d36e5d72cff5544f6c04722`
**Amendment:** exact issuer/JWKS validation and fail-closed PKI state.

## Reuse (no redesign)

The amendment reuses the existing PR 17-C seams exactly: `CANONICAL_KC_HOSTNAME`,
`CANONICAL_KC_PORT`, `_required_env`, `up`, `preflight`, `check_issuer`,
`_parse_issuer`, `_fetch`, `CertPaths`, `generate`, `check`, `harden`, and the
`test_pr17c_dev_stack` / `test_pr17c_dev_probe` / `test_pr17c_dev_certs` modules.
No new validation library, certificate manager, topology, or container was added.

## Confirmed defects on the base tip

| # | Severity | Defect | Evidence |
| --- | --- | --- | --- |
| 1 | High | `up()`/`preflight()` accepted any `MTMF_AUTH_ISSUER` containing `keycloak.mtmf.test` as a substring (`if CANONICAL_KC_HOSTNAME not in issuer`). `https://evil-keycloak.mtmf.test:...`, wrong ports/schemes/realms, userinfo, and trailing-slash/query/fragment values passed the gate. | source inspection; new AM03–AM07 tests fail on the base logic |
| 2 | High | The probe accepted a discovered `jwks_uri` with `jwks_uri.startswith(anchor)`, permitting prefix/path deception and unintended same-origin endpoints before fetching the JWKS. | source inspection; new AM09–AM12 tests fail on the base logic |
| 3 | High | `generate()` regenerated only missing components (`if not ca_key or not ca_cert: _make_ca`), so a partially populated directory was silently completed and an existing CA could be paired with a foreign leaf. `check()` did not verify CA/leaf key-pair consistency. | source inspection; new AM16–AM21 tests fail on the base logic |

## Pre-existing behavior preserved

- Canonical TLS-transparent forwarder, isolated `mtmf` Compose network,
  loopback-only publications, host/container probes, strict Keycloak hostname,
  CA mounting, and container secret isolation are unchanged.
- `compose.dev.yaml`, `compose.yaml`, and `scripts/mtmf-dev-forwarder.py` were
  not modified by this amendment.
- PR 17-B provisioning/provenance and authentication/authorization packages were
  not modified.
- All existing N01–N24 tests remain intact and passing; none were weakened,
  skipped, or removed.

## Pre-existing launcher sequencing transient (not introduced here)

`up()` sets `MTMF_DEV_FORWARDER_IP` only after the first
`compose up -d postgres keycloak forwarder`. Because the value participates in
the podman-compose config hash via the initializer/service `extra_hosts`, the
final `compose up -d service` recreates Keycloak/forwarder/initializer/service.
`up` therefore returns while Keycloak is briefly restarting, so a `preflight`
invoked *immediately* after `up` can observe a transient connection reset until
Keycloak becomes healthy again. This sequence is present on the base tip and is
not caused by this amendment; it is recorded in
`PR17C_AMENDMENT1_STOP_DEVIATIONS.md`. The amendment's hardening runs before
this sequencing and does not change it.
