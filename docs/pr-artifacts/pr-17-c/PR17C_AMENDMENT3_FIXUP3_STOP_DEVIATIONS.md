# PR 17-C Amendment 3 Fixup 3 — STOP / Deviations

No unresolved STOP blocks the fixup objective. The required configuration and
fresh-environment provisioning path are delivered and verified; the destructive
operator reset was intentionally not performed.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| AM3F3-D1 | Required operator authorization (not performed) | The existing persistent `mtmf-pr14-dev` volume was **not** reset/migrated. Per the plan, the clean reset is an explicit, separately approved destructive action. Standard `up` against that volume now fails closed with an actionable error. | Operator action required: follow the documented clean-reset procedure when ready to discard the old development realm. No automatic migration. |
| AM3F3-D2 | Test-harness accommodation | The PR17 live harness hardcodes the standard project's container name (`mtmf_postgres_1`) for its DB-outage case. The disposable verification was therefore run under the standard project name with disposable `mtmf-fixup3-*` volumes; the operator's volumes were never used and remain intact. An initial run under a different project name failed only `test_v08`; re-running under the standard project name passed 26/26. | Classified as environment/harness (container-name coupling), not a feature defect. No production change made to accommodate it. |
| AM3F3-D3 | Stale image during verification | Early disposable initializer runs used an image built before the Fixup 3 initializer changes; they failed. After rebuilding `mtmf_initializer`, the initializer completed and the binding was created. | Environment/harness; resolved by rebuild. The committed source is correct. |
| AM3F3-D4 | Human decision — Windows gate | Windows-browser N17/N18 acceptance remains unexecuted. A prior amendment reclassified them as optional manual smoke tests without a clear explicit user approval. | **Human-review decision required**: confirm the optional classification or restore them as a mandatory gate. This fixup does not change the gate; no Windows testing is claimed. |
| AM3F3-D5 | Independent PR 14 fixture | The fixture remains on `mtmf-pr14-dev`; the standard stack passes `--realm mtmf-dev` to the shared `setup-realm.py`. The shared standard-stack manifest `expected-realm-security.json` had its realm name updated; the PR 14 `expected-config-manifest.json` and evidence are unchanged. | Documented; no fixture semantics changed. |

## Failure classification

- All four canonical gates pass on the final tip.
- All CR-U01–CR-U30 deterministic tests pass.
- CR-I01–CR-I18 live checks pass, with AM3F3-D2/D3 recorded as environment/harness
  accommodations.
- No skip/xfail/assertion weakening was used. No secret was committed or printed.

## Outstanding human decisions

1. Authorize (or not) the destructive clean reset of the operator's existing
   development Keycloak/PostgreSQL volumes.
2. Confirm the Windows N17/N18 gate classification.
3. Human review and merge approval for PR 17-C (remains **NOT DONE**).
