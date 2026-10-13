# PR 17-C Amendment 3 Fixup 1 — STOP / Deviations

One STOP condition was triggered: **Part C (FX-I10), recovery administrator
reconciliation.** The DNS and cancellation fixups (Parts A/B) completed and
passed; no STOP applied to them.

## STOP — recovery administrator (FX-I10)

**Condition (per plan §11.5):** the original admin is not verifiably usable, or
the recovery admin cannot safely be disabled.

**Read-only evidence (no secrets recorded):**

```text
mtmf-pr14-admin2: enabled=True requiredActions=[] realmRoles=['admin','default-roles-master']
mtmf-pr14-admin : enabled=True requiredActions=[] realmRoles=['admin','default-roles-master']
admin2 authenticates with the current known credential: True
mtmf-pr14-admin authenticates with the current known credential: False
```

`mtmf-pr14-admin` cannot be authenticated because its credential was lost when
the workstation crashed/rebooted and the ephemeral `/tmp` admin password file
was cleared. The plan forbids changing admin credentials or resetting the realm
as a workaround, so no reset was attempted and **`mtmf-pr14-admin2` was left
enabled** — disabling it would remove the only known working recovery route.

**Required human action (choose one):**

1. Recover/confirm the `mtmf-pr14-admin` credential and authenticate it; then
   disable `mtmf-pr14-admin2` via the supported Keycloak admin API/CLI
   (do not delete), and re-verify the realm/clients/user `sub` values; or
2. Explicitly authorize keeping `mtmf-pr14-admin2` as the development recovery
   admin and disabling `mtmf-pr14-admin` instead, documenting the decision.

Until then, PR 17-C remains **AWAITING HUMAN REVIEW — NOT DONE**; the recovery
administrator reconciliation is an environment-specific security gate, not a
source test, and is **not** reported as PASS.

## Other deviations

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| A3F-D1 | Environment/harness (carried from Amendment 3) | The workstation crash/reblocked cleared `/tmp`; the dev CA/secrets and the pre-crash admin password were lost, and a second master admin (`mtmf-pr14-admin2`) was created with the supported `bootstrap-admin user` command. | No volume deleted, no realm reset. The loss is the direct cause of the Part C STOP above. |
| A3F-D2 | Scope note | Only `scripts/mtmf-dev-forwarder.py` and its unit tests changed; `compose.dev.yaml`, `dev/nsswitch.conf`, `scripts/mtmf-dev-stack.py`, `scripts/mtmf-dev-probe.py`, and cert code are unchanged. | Conforms to the plan. |
| A3F-D3 | Manual smoke tests | Windows N17/N18 remain unexecuted and are classified as **optional manual workstation smoke tests**, not mandatory automated PR gates. | Recorded in the roadmap; not a fixup gate. |

## Failure classification

- Parts A/B: no failures — all FX-U01–FX-U26 and FX-I01–FX-I09 pass; all
  authoritative gates and live regressions pass.
- Part C: **BLOCKED/STOP** (environment/security), not a code defect.
