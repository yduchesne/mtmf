# PR 17-C Amendment 3 Fixup 2 — STOP / Deviations

No mandatory STOP condition remains unresolved. The canonical administrator was
created and independently verified before the legacy administrators were
disabled; the final state is the required one. Three deviations are recorded.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| AM3F2-D1 | Environment/harness (Keycloak behavior) | The recovery administrator `mtmf-pr14-admin2` had been created with Keycloak's **temporary bootstrap-admin** mechanism. When the first `--apply` created the permanent `mtmf-admin`, Keycloak retired the temporary recovery account, so the recovery session expired mid-run and the tool exited non-zero (`GET admin request failed with HTTP 401`) **after** the create/verify phases had already run. | Not a tool mutation defect. The state after that run was already correct (`mtmf-admin` enabled with `admin` role; both legacy admins disabled). Reconciled idempotently with `--apply --recovery-username mtmf-admin`, which exited 0. Documented in the admin migration report. Recommend operators migrating an existing volume verify the canonical admin before the temporary recovery account is retired. |
| AM3F2-D2 | Development-only credential custody | The canonical `mtmf-admin` credential is stored in an owner-only file outside ephemeral `/tmp` (`~/.config/mtmf/dev-admin.env`, `0600`, not committed). Runtime environment exposure is a development-only limitation. | Operator action: move the credential to a password manager/approved secret store. Documented in `docs/DEVELOPMENT_SETUP.md`. |
| AM3F2-D3 | Legacy account lifecycle | `mtmf-pr14-admin` was disabled even though its credential had been lost in the earlier host crash and it was never authenticated during this fixup. | Consistent with the plan: the decision was to retire legacy PR-numbered administrators only after the **new** canonical administrator was independently verified. `mtmf-admin` was verified before the disables; the disabled accounts are retained, not deleted. |
| AM3F2-D4 | Manual smoke tests | Windows N17/N18 remain optional manual workstation smoke tests, not mandatory automated gates. | Recorded in the roadmap; no execution claimed. |

## Failure classification

- First `--apply` non-zero exit: **environment/harness** (Keycloak temporary
  bootstrap-admin retirement), proven by the post-run inventory already matching
  the required state and by the idempotent exit-0 rerun. Not an introduced
  regression and not a source defect.
- All canonical gates and live regressions pass on the fixup tip. No test was
  skipped, xfailed, deleted, or weakened; no secret was committed or printed.

## Outstanding human actions

1. Move the `mtmf-admin` credential from `~/.config/mtmf/dev-admin.env` into a
   password manager / approved secret store.
2. Human review and merge approval for PR 17-C (remains **NOT DONE**).
