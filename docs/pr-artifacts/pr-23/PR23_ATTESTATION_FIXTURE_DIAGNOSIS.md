# PR 23 — Attestation Mismatch Diagnosis and Fixture Correction

**Date:** 2026-11-11
**Scope:** read-only diagnosis; no committed trust baseline, authentication
policy, client-approval rule, or security-relevant Keycloak setting was changed.

## Effective configuration under test

| Item | Value |
| --- | --- |
| Initial (wrong) issuer URL | `https://127.0.0.1:28443/realms/mtmf-pr14-dev` |
| Initial realm | `mtmf-pr14-dev` |
| Realm-security baseline | `dev/keycloak/expected-realm-security.json` |
| Expected-client policy | `dev/keycloak/expected-client-policy.json` |
| Baseline realm string | `mtmf-dev` |
| Attestation reader | `mtmf-attestation-reader` (least-privilege) |

## Field-by-field result for the initial fixture

Compared with `mtmf_service.authentication.attestation.canonical_manifest`,
which by design contains `realm`, `realmSecurity`, and `clientScopes` and
**intentionally excludes the realm client inventory**:

| Projection | Expected | Live (`mtmf-pr14-dev`) | Match |
| --- | --- | --- | --- |
| `realm` | `mtmf-dev` | `mtmf-pr14-dev` | **NO** |
| `realmSecurity` | 18 approved fields | identical 18 fields | YES |
| `clientScopes` | 15 approved scopes | identical 15 scopes | YES |

No `realmSecurity` or `clientScopes` difference existed. The only attestation
mismatch was the realm name, which made `BaselineConfigurationAttestor.attest()`
fail closed with `ATTESTATION_DRIFT` before token-class evaluation.

The live client inventory contained additional clients
(`mtmf-attestation-reader`, `mtmf-evidence-same-client-b`, etc.). Per the
attestor contract, `canonical_manifest` deliberately does **not** include the
realm client inventory; individual admitted clients are verified separately by
`canonical_client_projection` against `expected-client-policy.json`. Comparing
the full live client inventory to the realm baseline is therefore not the
correct diagnosis and was not used as the acceptance criterion.

## Fixture correction (selection only)

The isolated Keycloak fixture was configured with the approved realm name using
the existing `dev/keycloak/setup-realm.py --realm mtmf-dev` path. No baseline
file, client policy, issuer-validation rule, attestation rule, or Keycloak
security setting was edited.

Resulting approved topology:

| Item | Value |
| --- | --- |
| Issuer URL | `https://127.0.0.1:28443/realms/mtmf-dev` |
| Realm | `mtmf-dev` |
| `realm` match | YES |
| `realmSecurity` match | YES |
| `clientScopes` match | YES |
| `mtmf-evidence-same-client` policy match | YES |
| `mtmf-evidence-same-client-b` policy match | YES |
| `mtmf-sample-app` policy entry | not created by `setup-realm.py`; not used by L01–L04 or the PR 14 live regression |

This isolated loopback topology demonstrably reproduces the committed
`mtmf-dev` realm-security projection and the approved client projections used by
the live tests. The previously failing PR 14 live regression now passes, and the
PR 23 live default fixture is corrected to `mtmf-dev`.

## Exact commands

```bash
# Isolated fixture (existing project-scoped Compose file)
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml \
  --env-file /tmp/mtmf-pr14-kc.env up -d
uv run --no-sync python scripts/pr14-keycloak-evidence.py wait

# Approved realm configuration (existing idempotent bootstrap)
set -a; . /tmp/mtmf-pr14-kc.env; set +a
uv run --no-sync python dev/keycloak/setup-realm.py --realm mtmf-dev

# Diagnosis (read-only)
SSL_CERT_FILE=/tmp/mtmf-pr14-kc-tls/server.crt uv run --no-sync python - <<'PY'
# canonical_manifest("mtmf-dev") vs expected-realm-security.json
# canonical_client_projection(...) vs expected-client-policy.json
PY
```

## Outcome

- Attestation mismatch: **realm name only** (`mtmf-dev` vs `mtmf-pr14-dev`).
- Resolution: **fixture selection**, not policy change.
- No committed trust baseline was modified.
