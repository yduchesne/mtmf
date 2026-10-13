# PR 17-C Amendment 3 — STOP / Deviations

No mandatory STOP condition was triggered. The intermittent forwarder stall was
reproduced, root-caused with direct instrumentation (not timings alone), and
fixed; no TLS termination, relaxed verification, second issuer, host networking,
host publication, elevated privilege, secret logging, or retry/timeout inflation
was required. The first-attempt real-topology gate passes 100/100 and 50/50.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| AM3-D1 | Environment/harness recovery | The workstation crashed and rebooted mid-session, clearing `/tmp`: the generated development CA, `dev-user` password file, and ephemeral Keycloak admin password file were lost. MTMF volumes persisted. | Regenerated the CA/leaf and secret files; used Keycloak's supported `bootstrap-admin user` command to add a **second** master admin (`mtmf-pr14-admin2`); the existing realm and clients were left intact. **No volume was deleted**; no Keycloak data was reset. Recorded here for reviewer awareness. |
| AM3-D2 | Authorized file change | `scripts/mtmf-dev-forwarder.py` was modified. Amendment 2 and earlier plans restricted this file, but the Amendment 3 plan explicitly scopes the forwarder as the fix target. | Within the Amendment 3 scope; no other normally-untouched file was changed. |
| AM3-D3 | Live case not separately run | A deliberate "rebuild only the forwarder" live step was not run; the D3 target-down → restore case already exercises address invalidation and re-resolution without a forwarder restart. | Deterministic `test_fw16_target_recovers_without_forwarder_restart` passes; D3 live passes. |
| AM3-D4 | Manual acceptance unchanged | Windows N17/N18 remain unexecuted. | Out of scope for this amendment; PR 17-C remains NOT DONE pending human review. |

## Failure classification

- Forwarder intermittent stall (DNS search-query resolution): **feature
  implementation defect** — reproduced, root-caused, fixed, and verified
  0/30 on the trigger plus 100/100 and 50/50 on the mandatory gate.
- Forwarder pump lifecycle (`write_eof` `OSError`, eager connect, unbounded
  teardown): **feature implementation defect** — fixed.
- No introduced regression; no canonical gate or live regression failed.
- No test was skipped, xfailed, deleted, or weakened; no launcher retry was
  changed to make the transport gate pass.

## Outstanding

Windows N17/N18 remain the only unexecuted mandatory items for PR 17-C as a
whole. PR 17-C remains **AWAITING HUMAN REVIEW — NOT DONE**.
