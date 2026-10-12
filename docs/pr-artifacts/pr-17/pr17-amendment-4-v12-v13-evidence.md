# PR 17 — Amendment #4 V12 / V13 evidence

**Status: V12 BLOCKED (D2); V13 NOT EXECUTED.**

## V12 — two independent Keycloak clients and MTMF Applications

**BLOCKED (S4-10).** V12 requires an independently approved expected-client
policy containing two distinct clients (D2) and a reviewed second Keycloak
client. The approved whole-realm manifest currently contains one
shared-audience client (`mtmf-evidence-same-client`); adding a second
shared-audience client changes the committed whole-realm manifest, which is a
trust-contract change (STOP-01 / S4-01).

| ID | Status | Note |
| --- | --- | --- |
| CL01–CL02 (two positives) | BLOCKED | needs approved second client + application/subscription/bindings |
| CL03–CL05 (cross-client/Tenant negatives) | PARTIAL | unit H13 and live V05 different-client fail-closed; a genuine two-client live pair is D2 |
| CL06 (unapproved client) | PASS (current semantics) | any extra realm client ⇒ whole-realm drift ⇒ fail closed |
| CL07–CL10 | BLOCKED | require the approved multi-client policy |

No case is marked PASS from a single-client topology.

## V13 — disposable MTMF-only destroy/recreate

**NOT EXECUTED.** Amendment #3 correctly stopped because the shared development
PostgreSQL volume's disposability was not provable. Amendment #4 would require
creating a **new**, uniquely named MTMF-only disposable project/volumes and
supplying explicit ownership/disposability proof before destruction. That
step was not performed in this amendment because (a) V13 also depends on the
approved attestation/client policy (D2) to reach fresh attestation and a
genuine ALLOW after recreation, and (b) destructive testing requires explicit
operator confirmation that was not supplied.

| V13 sub-step | Status |
| --- | --- |
| Dedicated disposable MTMF project + volumes | NOT EXECUTED |
| Before/after ownership inventory | NOT EXECUTED |
| Fresh bootstrap + attestation + HTTP ALLOW | NOT EXECUTED |
| Stop/restart preserving volumes | NOT EXECUTED |
| Destroy + recreate from empty volumes | NOT EXECUTED |

Smallest resolution: approve D2, provide explicit destruction approval, then
run an isolated disposable project end to end.
