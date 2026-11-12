# PR 23 — Verified Subject Contract

## Frozen internal result

Added to `mtmf_core.authentication.contracts` and exported:

```python
@dataclass(frozen=True, slots=True)
class VerifiedPreTenantSubject:
    application_id: DomainId
    service_credential: ServiceCredentialKey
    external_subject: ExternalSubjectKey
    verified_at: datetime
    user_token_expires_at: datetime
    existing_identity_id: DomainId | None
    existing_principal_id: DomainId | None
```

- `(existing_identity_id, existing_principal_id)` is either both `None` or both
  populated; the dataclass rejects the mixed state.
- Both datetimes are validated timezone-aware.
- There is no Tenant, Role, Permission, entitlement, trusted operator, raw
  token, or pre-issued `ALLOW` field.
- The object is detached and internal. Constructing it is **not**
  authentication or authorization; a future privileged executor must
  independently establish provenance and revalidate all authoritative database
  state inside its one transaction.
- It is never serialized as a public DTO.

## Verification order

`PreTenantSubjectVerificationService.verify(service_token=…, user_token=…, at=None)`:

1. Reject a naive verification instant and empty/malformed token input.
2. Run the same extracted `_verify_token_pair` used by
   `AuthenticatedActorContextService.resolve`:
   fresh attestation of the service profile, independent service/user token
   verification, service/user class requirements, exact signed `azp` equality,
   exact issuer/profile match, and fresh attestation of both signed client
   identifiers.
3. Open exactly one read-only UnitOfWork.
4. Resolve the ACTIVE `(issuer, client_id)` service binding to the persisted
   Application and require ACTIVE lifecycle.
5. Require the initialized canonical root registry; never auto-initialize it.
6. Resolve the ACTIVE exact `(issuer, subject)` external binding. If absent,
   return both global IDs `None` without creating anything. If present, load the
   Identity and Principal and require active FEDERATED Identity, active
   Principal, and non-root canonical objects.
7. Leave the UnitOfWork without `commit()`.
8. Map `PersistenceError` to `AuthenticationFailure.INFRASTRUCTURE`, never to
   `UNKNOWN_SUBJECT` or a success.

## Trust model

- Two independent proofs are required: a signed service credential resolving to
  a registered Application and a separately verified interactive-user token
  resolving to the exact `(issuer, subject)`.
- Same-client attestation and PR 14 issuer/class policy are unchanged.
- No caller-supplied Application/Identity/Principal/Tenant UUID can
  authenticate.
- No Tenant, membership, registration, subscription, or entitlement is required
  or read.
- No new IdP, issuer pairing, credential class, or attestation policy is
  introduced.

## Negative cases

- Empty/naive input, wrong token class, cross-client, untrusted issuer,
  attestation drift/unavailability, missing/revoked service binding, inactive
  Application, missing root registry, deleted/non-FEDERATED Identity, missing/
  deleted Principal, canonical root subject, and backend failure all fail
  closed.
- A missing active subject binding is a **candidate**, not an `ALLOW` and not
  entitlement/capacity.
- A caller cannot fabricate proof by constructing the dataclass; this is stated
  in the contract and is why the future executor must use the trusted verifier.
