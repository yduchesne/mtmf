# PR24P_PR77_OAUTH_CALLBACK_REVIEW_FIXUP_REPORT

**Roadmap work:** in-progress PR 24P, held at the topology gate (not a new implementation project)
**Branch:** `dev/pr24p-part-deux`
**Baseline branch SHA:** `aa8873266f650c995046398f1c798428b6257eda`
**PR:** [#77](https://github.com/yduchesne/mtmf/pull/77) (documentation proposal)
**Review:** [PR #77 discussion](https://github.com/yduchesne/mtmf/pull/77#issuecomment-6857722638)
**Disposition:** `PR77_OAUTH_DOC_FINDINGS_CORRECTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`
**Human Gate A/B approvals:** NOT RECORDED
**Implementation, acceptance, live Podman and benchmarks:** NOT EXECUTED

## Exact corrections

| Review ID | Previous contradiction/ambiguity | Frozen correction |
|---|---|---|
| P1-01 | Rejected Keycloak `iss`/`session_state` and unknown OAuth params | Accept canonical `iss`, bounded opaque `session_state`, standard OAuth error response and safe extensions; reject duplicates/invalid fields; verify original `state` and exact issuer |
| P1-02 | Claimed authorization code never appears in browser | Accept unavoidable one-time browser redirect code; prohibit disclosure in logging, HTML, completion URL/Referer or storage; `303` clean completion with no-store and no-referrer |
| P2-01 | Undefined environment fingerprint allowed historical interactive-login PASS reuse | Remove historical reuse entirely. Every unattended startup proves infrastructure security afresh; no interactive user sign-in or privileged-operator-ready claim without a current genuine operator session |
| P2-02 | Client secret also can authenticate a service account | Explicit residual risk because existing confidential client has `serviceAccountsEnabled=true`; keep secret CLI-only and deny genuine client-credentials tokens in worker operator authorization |

## Source reconciled

- Existing `dev/keycloak/expected-client-policy.json` continues to set
  `mtmf-evidence-same-client`: confidential, `standardFlowEnabled=true`,
  `serviceAccountsEnabled=true`, `directAccessGrantsEnabled=false`,
  redirect `http://127.0.0.1:28400/callback` and target audience
  `mtmf-same-client-api`. The policy was **not modified**.
- Current rootless Podman/Keycloak callback forwarding and worker
  are **proposed**, not deployed or measured.
- No control worker, privileged private socket, DB control role or
  migration `0016` was added. The already-started PR 24P work remains
  held at `STOP-P24P-TOPOLOGY` for explicit human Gate A+B approval.

## Future acceptance checks (NOT EXECUTED)

| ID | Requirement |
|---|---|
| RFX01 | Real Keycloak redirect containing `code`, `state`, `iss` and `session_state` accepted and issuer matched |
| RFX02 | Duplicate/state mismatch/issuer mismatch/invalid OAuth error denied; no code exchange |
| RFX03 | One code appears only in unavoidable redirect; clean `303` completion, no logs, HTML, Referer or persisted tokens |
| RFX04 | Real confidential-client-credentials service token denied as operator even with valid signature/audience/azp |
| RFX05 | Every unattended `up`: actual UID/socket/mount/DB/issuer checks, no callback port or false operator-ready report |
| RFX06 | New operator action: fresh interactive browser flow, genuine user token, exact Role check; old session not reused |
| RFX07 | No new grant, migration, code or privileged deployment while Gate A+B absent |

## Preservation

- This fixup changes exactly four PR 24P Markdown files: the decision
  record, development-profile proposal, STOP report, and this report.
- Existing D01–D20 and E01–E20 remain unchanged in count and meaning;
  CB01–CB08 remain eight planned future checks.
- Exactly five private SQL signatures remain in §7,
  `mtmf_runtime` retains the 78-signature policy, production
  automatic SYSTEM bootstrap stays forbidden.
- Gate A/B human authorization is still missing, Gate C remains
  future acceptance; no test, benchmark or deployed privilege proof
  is claimed.

**Terminal state:** `PR77_OAUTH_DOC_FINDINGS_CORRECTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`.
