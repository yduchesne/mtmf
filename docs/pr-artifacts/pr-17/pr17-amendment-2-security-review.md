# PR 17 — Amendment #2 security review

## 1. Authentication and trust

- Service and acting-user credentials remain **separate** inputs, independently
  verified (PR 14); a service token is never accepted as a user and no
  caller-supplied UUID/header proves identity.
- Same-client D1 binding (`service.azp == user.azp`) and root/SYSTEM exclusion
  are unchanged. The unit H13 and the PR 14 live suite
  (`test_dc07_v05_cross_client_rejected`) cover cross-client rejection; the
  approved fixture has no second client with the shared audience, so a
  same-audience cross-client pair cannot be built without a manifest change
  (STOP-01).
- Fresh issuer-configuration attestation remains mandatory on every operation
  with **no positive cache** (`test_v07_no_positive_attestation_cache`); drift
  and outage fail closed.

## 2. TLS / issuer / networking

- No verification was weakened: certificate validation, hostname validation,
  issuer matching and JWKS trust remain strict. The containerized demonstration
  used `--network=host` so the approved issuer `https://127.0.0.1:28443` stayed
  identical; it did not disable TLS, rewrite `iss`, trust a forwarded host, or
  fall back to HTTP.
- A proposed canonical-hostname topology would change the trusted issuer
  identity/manifest and is therefore **not** adopted without reviewer approval.

## 3. Authorization invariants preserved

- Default DENY; ordered per-action decisions; one shared `AuthorizationContext`
  and one pure-Python `BatchAuthorizer` call; unknown Action → `DENY/
  UNKNOWN_ACTION`; `mtmf_owned` → `DENY/UNSUPPORTED_RESOURCE`; conservative 15 s
  TTL; Application–Tenant subscription enforcement; SYSTEM/root denial.
- New live tests confirm V04 eligibility states and V05 fail-closed cases; no
  case produced an ALLOW.

## 4. Persistence and privileges

- All application DB access remains through the sanctioned SPI/stored
  functions; no direct application-table SQL and no new grant.
- The only persistence change is adding **session timeouts** to the runtime DSN
  (`options`). No global database setting, no owner/migrator timeout, no
  privilege expansion, no new root authority.
- The runtime role privilege surface is independently verified by the existing
  integration security tests (exact EXECUTE allowlist, no direct table access).

## 5. Runtime secret isolation

- The containerized service received only the restricted runtime credential,
  rollout limits, and the issuer-attestation credential; the container
  environment contained no `MTMF_MIGRATOR_*`, `MTMF_POSTGRES_*` admin/owner, or
  bootstrap credential.
- **Residual:** the attestation reader uses the realm admin credential. The plan
  permits a read-only attestation credential; narrowing this to a dedicated
  read-only reader is recorded as a deviation.

## 6. Timeout/saturation safety

- A bounded admission counter limits concurrent synchronous evaluations;
  saturation is a deterministic `503` with no decisions.
- The permit race is closed: a worker cannot execute unless it owns a permit,
  and each permit is released exactly once.
- Configurable PostgreSQL `statement_timeout`/`lock_timeout` bound blocked
  database work; terminated statements roll back and the session stays healthy.
  No timeout is converted into an ALLOW.

## 7. Redaction and failure envelopes

- Errors remain static PR 15 envelopes with `Cache-Control: no-store`; no
  token, secret, policy, or stack detail is echoed. Live V15 confirms size/media/
  credential/rate-limit failures and no-store on success and error.

## 8. Resource ownership

- Only MTMF-owned projects (`mtmf`, `mtmf-pr14-keycloak`) were inspected or
  modified. No ATI/Digr/Darkula/Hammeridian resource was touched and no global
  Podman prune was used.

## 9. Open security-relevant items

- Acting-user carrier approval (STOP-02).
- Initializer Keycloak client vs whole-realm attestation manifest (STOP-01).
- Administrator attestation reader vs read-only reader.
- Container-network canonical issuer topology (host DNS + issuer approval).
