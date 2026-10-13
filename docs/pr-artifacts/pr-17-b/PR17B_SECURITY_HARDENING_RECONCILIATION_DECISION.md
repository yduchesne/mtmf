# PR 17-B Security-Hardening Reconciliation Decision (A2)

**Status:** DECIDED — no blocking STOP. The minimum-scope provenance policy below
is implementable against the real Keycloak API **and** preserves the approved I12
concurrency contract as written.

## 1. Problem

After a create `POST`, the previous code accepted any single exact-username
account that passed attribute validation, regardless of whether the POST
succeeded, conflicted, was definitely rejected, or was indeterminate. A user
created independently during a rejected/uncertain POST could therefore be bound
as if this initializer had created it. Username/email matching is not ownership
proof.

## 2. Available evidence

Real Keycloak `26.8.0-1` (probed, see baseline §5):

- `2xx` create → `Location: .../admin/realms/{realm}/users/{id}`; the trailing
  `id` equals the created account's immutable subject.
- Duplicate username → `409`.
- Invalid body → `400`.

The Admin REST user representation also carries `username`, `id`, `enabled`,
`email`, `federationLink`, `serviceAccountClientId`, and `origin`, all of which
are **mutable or non-authoritative for creation provenance** except `id`.

## 3. Outcome classification

| Outcome | Trigger | Provenance available | Policy |
| --- | --- | --- | --- |
| `CREATED` | 2xx | `Location` user id | Re-read; require exactly one exact match, valid attributes, `id == Location id`; optional subject assertion must match. |
| `REJECTED` | HTTP non-409 4xx except 408 (400/401/403/404/405/406/410/413/415/422) | none (authoritative) | Fail closed immediately; **never** re-read-and-accept. Redacted status only. |
| `CONFLICT` | HTTP 409 | none | Bounded re-read; accept only with an independent correlation (below). |
| `INDETERMINATE` | timeout, transport error, dropped/malformed response, HTTP 5xx, HTTP 408 | none | Bounded re-read; accept only with an independent correlation. No second POST. |

## 4. Ownership rule (minimum scope)

1. **Existing account on the initial lookup** — reuse under the existing
   verified-account contract: exactly one exact-username match, non-empty
   immutable `id`, strict boolean `enabled=true`, non-federated/non-service/
   non-brokered, optional email consistency, optional `MTMF_DEV_USER_SUBJECT`
   equality, read-only (no password reset, no attribute/role/MFA/verification
   mutation). This is an operator-approved trust decision within the isolated
   development realm and is unchanged.
2. **`CREATED` with `Location`** — accept only when the re-read account's `id`
   equals the `Location` user id. This is cryptographic-equivalent provenance
   from the authority that performed the creation and is independent of any
   mutable username/email/profile field.
3. **`CONFLICT` or `INDETERMINATE`** — no automatic promotion of a matching
   username/email. Accept only when an **independent correlation** is present:
   an explicit `MTMF_DEV_USER_SUBJECT` assertion equal to the authoritative
   re-read `id`. Otherwise fail closed. (An unrelated creator who knows the
   username/email still cannot make the initializer bind the account without the
   operator asserting that exact subject; a mutable profile marker is explicitly
   rejected as insufficient.)
4. **Ambiguity / lookup failure** — multiple exact matches, malformed rows,
   HTTP errors, or exhausted zero-result retries fail closed.

No user-editable profile attribute is used as provenance. No new realm/client
policy, marker attribute, or production API is introduced.

## 5. Concurrency analysis (I12 preserved)

Two initializers race for the same fresh username without an assertion:

- A: initial lookup empty → `POST` `201` + `Location` → re-read matches `Location`
  id → **succeeds**.
- B: initial lookup empty → `POST` `409` (or indeterminate) → re-read matches, but
  **no assertion** → **fails closed** on the first invocation.
- A later invocation (or the harness retry) performs an initial lookup, finds the
  now-existing account, and reuses it under rule 1 → **succeeds**.

This is exactly the bounded fail-closed outcome the committed
`test_i12_two_simultaneous_initializers_converge` already permits (one success
plus one recoverable failure, then an idempotent retry). **The I12 success
expectation is unchanged; the test is not rewritten to pass.**

If both processes provide the same `MTMF_DEV_USER_SUBJECT`, the loser accepts the
409/indeterminate re-read under rule 3 and both succeed; this is additive, not a
weakening.

## 6. Consequence for the existing I15a expectation

`test_i15a_lost_create_response_is_reconciled` previously asserted a lost-response
create succeeded without an assertion. Under this policy that is exactly the
vulnerable behavior being removed. I15a becomes:

1. lost response, no assertion → **fail closed** (no MTMF writes);
2. unchanged rerun → initial lookup reuses the now-existing account → **succeeds**.

A separate assertion-driven variant runs with `MTMF_DEV_USER_SUBJECT` set to the
observed subject and a still-missing account to exercise the rule-3 acceptance
path. This is a deliberate, documented change required by SH09/SH10, not a
silent test rewrite.

## 7. Decision

Strict provenance is reconcilable with I12 and the real API; no human policy
decision is required to proceed. Implementing the policy above. If any live test
shows Keycloak does not return `Location`, or that I12 cannot pass with the
bounded-failure outcome, the amendment will STOP and raise a STOP report rather
than accept a matching username.
