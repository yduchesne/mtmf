# PR 17 — Amendment #4 STOP / deviation register

| ID | Type | Record | Smallest resolution |
| --- | --- | --- | --- |
| S4-01 | **STOP** | D2 (attestation architecture) not approved; no trust-semantics change made. | Human APPROVE/REJECT/DEFER of the proposed realm projection + expected-client policy. |
| S4-02 | **STOP** | D1 (acting-user carrier) not approved. | Record decision in the carrier/decision register. |
| S4-03 | **STOP** | D3 (host-network topology) not approved; launcher unchanged. | Human decision on development topology. |
| S4-04 | Blocked | Realm-wide security settings are not projected (only the realm name); effective inherited client scopes/mappers are not separately proven. | Approve the expanded realm/effective-client projection (part of D2). |
| S4-05 | Blocked | Duplicate client IDs are not explicitly rejected (detected only as a structural list difference). | Approve explicit duplicate/ambiguity rejection (D2). |
| S4-09 | STOP (S4-09) | V13 ownership/disposability not proven for the shared volume; a new disposable project was not created. | Provide an isolated disposable project + explicit destruction approval. |
| S4-10 | STOP (S4-10) | V12 cannot be genuinely two independent clients without an approved second client/policy (D2). | Approve second client + expected-client policy. |
| S4-11 | Not ready | V12 BLOCKED, V13 NOT EXECUTED, V01 partial. | Resolve above. |
| S4-08 residual | Deviation | The issuer attestation reader uses the realm admin credential, not a dedicated read-only reader. | Approve/provision a read-only attestation reader. |
| S4-13 | Gated non-goal | Production issuer trust and root recovery remain disabled. | Separate production release gate. |

Per the plan's STOP rule: work and evidence are preserved and committed; PR 17
is **not** marked DONE and is **not** merged.
