# PR 17-C Amendment 3 Fixup 3 — Final Acceptance

## Delivered

The standard development realm is now **`mtmf-dev`**, with the single canonical
issuer `https://keycloak.mtmf.test:28443/realms/mtmf-dev` and JWKS
`.../protocol/openid-connect/certs`. The master-realm administrator remains
`mtmf-admin`. The independent PR 14 evidence-only fixture remains on
`mtmf-pr14-dev`. The operator's existing persistent volume was **not** reset or
mutated.

## Canonical gates (fixup tip)

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — **2153 passed**, coverage **90.75%** |
| `./build.sh --sec` | PASS — Bandit Medium/High 0, Semgrep 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |

## Live verification (disposable MTMF-owned environment)

| Case | Result |
| --- | --- |
| CR-I01/I02 isolation | PASS — disposable `mtmf-fixup3-*` volumes; operator + PR14 volumes preserved; only named test resources removed |
| CR-I03 fresh bootstrap | PASS — `mtmf-admin` in `master`; `mtmf-dev` provisioned |
| CR-I04 fresh binding | PASS — initializer completed; `mtmf-dev-user` sub `a9983174-ded6-4ec3-9129-e0b9c259db00` |
| CR-I05/I06 discovery + JWKS | PASS — issuer and JWKS exactly canonical, TLS verified |
| CR-I07 token `iss` | PASS — exactly the new issuer |
| CR-I08 old issuer | PASS — old realm 404; no dual trust |
| CR-I09 attestation | PASS — unchanged security projection/expected-client policy |
| CR-I10 runtime secrets | PASS — no admin/migrator/owner credential in the service |
| CR-I11 isolated `up` | PASS — forwarder unpublished; loopback-only; no host networking |
| CR-I12 three `up` cycles | PASS — identical IDs/`StartedAt`, 0 unexpected stop/rm |
| CR-I13 `down`/`up` | PASS — realm, 18 clients, sub, 1 active binding, 2 tenants preserved |
| CR-I14 old-volume STOP | PASS — standard `up` failed closed; Keycloak untouched |
| CR-I15 negative config | PASS — CR-U20/CR-U21/CR-I14 |
| CR-I16 forwarder reliability | PASS — 100/100 sequential (max 0.023 s); 50/50 @10 (max 0.048 s); 30/30 direct control |
| CR-I17 live regressions | PASS — PR 17-B **13**, PR 14 **22**, PR 17 **26** |
| CR-I18 disposable reset | PASS — fresh subject `a9983174-…` (was `5d198663-…`), matching binding, no foreign resources |

## Existing-volume state

The operator's `mtmf-dev-keycloak-data` and `mtmf_mtmf-postgres-data` volumes
retain the old `mtmf-pr14-dev` realm and MTMF state. A standard `up` now fails
closed with an actionable, non-secret error (`MTMF_AUTH_ISSUER` / realm
mismatch); the tooling never auto-creates `mtmf-dev`, repoints bindings, or
resets accounts. The documented clean-reset procedure (operator authorization
required) is in `docs/DEVELOPMENT_SETUP.md`.

## Reset performed?

**NO.** No destructive reset was performed; no persistent volume was deleted or
mutated.

## Disposition

PARTIAL only in that PR 17-C as a whole awaits human review and the operator has
not authorized the destructive clean reset. The Fixup 3 objective — canonical
`mtmf-dev` configuration plus verified fresh-environment provisioning — is
complete and evidenced. **PR 17-C remains AWAITING HUMAN REVIEW — NOT DONE.**

Human decisions still needed:

1. Authorize (or not) the clean reset of the existing development volumes.
2. Confirm the Windows N17/N18 gate classification.
3. Human review and merge approval.
