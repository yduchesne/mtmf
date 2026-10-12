# PR 17 — Amendment #3 attestation conflict diagnosis (Part A, no trust changes)

## 1. Exact comparator seam

`BaselineConfigurationAttestor.attest()` loads the committed baseline JSON and
compares it to `canonical_manifest(reader, realm)` using a strict structural
`_diff` (dict key-set equality, list length + positional equality). Therefore
adding **any** client changes the `clients` list and fails.

`canonical_manifest` returns exactly:

```json
{
  "realm": "<realm name>",
  "clients": [ {clientId, enabled, publicClient, serviceAccountsEnabled,
                standardFlowEnabled, directAccessGrantsEnabled,
                implicitFlowEnabled, defaultClientScopes, optionalClientScopes,
                protocolMappers} ... ],
  "clientScopes": [ {name, protocol, attributes, protocolMappers} ... ]
}
```

## 2. Reproduced drift (A1/A2)

Commands (secrets redacted): start the MTMF-owned Keycloak fixture, snapshot the
live canonical manifest and its hash, run `scripts/mtmf-dev-initialize.py`, then
snapshot again.

| Snapshot | Hash | Clients | Matches expected | Added | Removed | Changed | Scopes equal | Realm equal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| before initializer | `9e9bb847…fed5` | 15 | **yes** | — | — | — | yes | yes |
| after initializer | `2372a2bd…b75c39` | 16 | **no** | `mtmf-sample-app` | — | — | yes | yes |
| expected baseline | `9e9bb847…fed5` | 15 | — | — | — | — | — | — |

**Root cause:** `canonical_manifest` enumerates **every** realm client and the
strict `_diff` requires exact list equality. The initializer creates the
development Application client `mtmf-sample-app`, so the realm contains one
client more than the committed baseline. No existing client changed and no
scope/mapper changed; the failure is purely **client-set equality**.

This means every authentication fails closed with `ATTESTATION_DRIFT` after the
initializer runs — a genuine conflict between PR 14 whole-realm attestation and
PR 17 per-Application client provisioning.

## 3. Fail-closed baseline proof (A3)

In a disposable realm, toggling the security-critical `enabled` field on the
approved `mtmf-evidence-same-client` client was performed via Admin REST, then
restored:

```
baseline:            OK
client-enabled-false: FAIL attestation_drift
restored:            OK
```

This proves the existing verifier is freshly re-evaluated per operation and
fails closed on a security-relevant client mutation.

## 4. Security-relevant fields and projection gaps

- Compared client fields that can change token identity/class/privilege:
  `enabled`, `publicClient`, `serviceAccountsEnabled`, `standardFlowEnabled`,
  `directAccessGrantsEnabled`, `implicitFlowEnabled`, effective default/optional
  client scopes, and normalized protocol mappers.
- Normalization: mapper names/config sorted; scope lists sorted; explicit
  booleans; deterministic `manifest_hash`.
- **Gap:** the projection captures only the realm **name**, not realm-wide
  settings (token lifetimes, flows, authentication policies) and does not
  explicitly reject duplicate client IDs (a duplicate currently surfaces only as
  a structural list difference). Additive realm/effective-scope verification is
  a D2 design item.

## 5. Smallest safe change (proposal only — D2 approval required)

The diagnosis supports the plan's split: keep the committed **realm projection**
independently authoritative, and add an independently approved, static
**expected-client policy** checked per admitted client from verified signed
claims, so approved mutable development clients (`mtmf-sample-app`, a second
V12 client) can exist without weakening per-client verification. The alternative
fallback is to pre-provision all PR 17 clients into the reviewed whole-realm
manifest and have the initializer validate/reuse rather than create.

**No trust-verification behavior was changed in this amendment.** The design is
submitted for D2 approval in
`pr17-amendment-3-attestation-design-decision.md`.
