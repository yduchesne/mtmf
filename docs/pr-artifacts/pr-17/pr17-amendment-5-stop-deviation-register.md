# PR 17 — Amendment #5 STOP / deviation register

## Mandatory STOP conditions

| ID | Status |
| --- | --- |
| S5-01 (no read-only reader possible) | **NOT TRIGGERED** — reader with `view-realm`/`view-clients`/`query-clients` performs all required GETs and is denied every mutation. |
| S5-02 (would need `realm-admin`/`manage-*`/bootstrap admin) | **NOT TRIGGERED** — no such role used; bootstrap admin is initializer-only. |
| S5-03 (secret exposure) | **NOT TRIGGERED** — reader secret delivered via mounted `_FILE`; absent from argv and `podman inspect`. |
| S5-04 (security-relevant field not attestable) | **PARTIAL residual** — curated allowlist; AT16 remains PARTIAL. |
| S5-05/S5-06 (cleanup ownership/destructive scope) | **NOT TRIGGERED** — ownership-verified; foreign containers refused; no shared resource touched. |
| S5-07 (Keycloak behavior contradicts assumptions) | **NOT TRIGGERED** — endpoint matrix matches. |
| S5-08/S5-09 (relax trust / new migration/grant/issuer) | **NOT TRIGGERED** — no TLS/issuer/DB change. |
| S5-10 (mandatory env unavailable) | **NOT TRIGGERED** — real Keycloak + PostgreSQL executed. |
| S5-11/S5-12 (gate/test failure or shared mutation) | **NOT TRIGGERED** — gates pass; reader mutation attempts were denied; the privileged disposable mutation was created and deleted. |
| S5-13 (read-skew needs architecture) | **NOT TRIGGERED** — bounded read characterization; ABA residual documented. |

## Residuals (non-blocking, documented)

| ID | Residual | Note |
| --- | --- | --- |
| R-1 | **RESOLVED** by SEC-01 | the runtime reader is now least-privilege; no admin password |
| R-2 | Realm projection is a reviewed curated allowlist; unknown future fields not compared (AT16 PARTIAL) | re-review on issuer upgrade |
| R-3 | Per-batch total downstream DB budget not contractually bounded | out of scope (per-statement timeouts exist) |
| R-4 | Host-network removes dev network-namespace isolation | approved development-only |
| R-5 | V13 reused the approved Keycloak realm | isolated PostgreSQL volume only |
| R-6 | Initializer dev-user subject not a provisioned Keycloak user | live flows seed a real subject |
| R-7 | Non-atomic Admin REST reads: a transient ABA mutation that restores before each later read is not detectable | bounded final comparison detects any observable difference; documented |

No unresolved mandatory STOP remains. PR 17 is not merged or marked DONE pending
human review.
