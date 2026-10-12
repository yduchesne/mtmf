# PR 17 — Amendment #3 STOP / deviation register

| ID | Type | Record | Smallest human decision |
| --- | --- | --- | --- |
| S3-01 | **STOP** | D2 attestation design not approved; no trust-verification code changed. | APPROVE / REJECT / DEFER the design in `pr17-amendment-3-attestation-design-decision.md`. |
| S3-02 | **STOP** | D1 acting-user header not approved. | Record the decision in `pr17-amendment-1-carrier-decision.md`. |
| S3-03 | **STOP** | D3 host-network development topology not approved; launcher unchanged. | APPROVE / REJECT / DEFER host-network dev topology. |
| S3-04 | Blocked | Initializer-created `mtmf-sample-app` makes whole-realm attestation drift (reproduced); per-client design needs D2. | Approve the split design or the pre-provisioned fallback. |
| S3-05 | Not executed | V13 MTMF-only destroy/recreate not run: the shared dev PostgreSQL volume is not demonstrably disposable. | Provide an isolated disposable stack/volume + explicit destruction approval. |
| S3-06 | Blocked | V12 two-client live isolation needs an approved second client + expected-client policy (D2). | Approve second client + policy. |
| S3-07 | Residual security | Issuer attestation uses the realm admin credential, not a dedicated read-only reader. | Approve/provision a read-only attestation reader. |
| S3-08 | Scope note | Realm-wide settings (token lifetimes, flows) are not in the current projection; only the realm name is compared. | Approve extending the realm projection (part of D2). |
| S3-09 | Residual | Per-statement DB timeouts bound each statement; total per-batch downstream budget not contractually bounded. | Accept documented allowance or approve a total-budget mechanism. |
| S3-10 | Gated non-goal | Production issuer trust and root recovery remain disabled. | Separate production release gate. |

No STOP item is silently promoted to PASS; PR 17 is not DONE and is not merged.
