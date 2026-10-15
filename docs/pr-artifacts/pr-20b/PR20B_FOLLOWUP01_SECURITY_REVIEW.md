# PR20B_FOLLOWUP01_SECURITY_REVIEW

**PR:** roadmap PR 20B — Follow-up 01: genuine mixed-action conformance,
deployed faults, and spoofing closure.
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Validated implementation SHA:** `7f9092ddebb7913059a03c6996e5394180247bc2`

## 1. Dominant invariant (unchanged, now proven multi-operation)

> Every disclosed field is covered by an actual MTMF decision for the precise,
> independently verified actor, Action, and loaded resource; a batch containing
> any denied operation discloses **nothing**.

The metadata operation strengthens this: a metadata result can never carry a
`body`, and a content grant never authorizes metadata (or vice versa).

## 2. Identity trust

- End-user authentication stays entirely at the reference-app boundary
  (`auth.py`): pinned issuer, audience, JWKS, RS256 signature, token-type and
  temporal checks. No decoded-but-unverified JWT is trusted.
- The Tenant and Application are server-owned; the metadata and mixed-operation
  routes accept **no** caller-supplied Action, Tenant, Application, actor,
  session, request-id, or resource target.
- The metadata operation's closed enum (`metadata`/`content`) is mapped
  server-side to the two exact Action URNs; the caller string never selects
  policy.
- The metadata fixture derives Identity IDs only from the persisted verified
  external-subject binding and the established deterministic initializer
  convention; it never trusts an arbitrary caller UUID and never creates a
  second Principal.

## 3. Action / Permission separation

- `read-object` and `read-metadata` are distinct exact Actions with matching
  Permissions. The metadata Role has exactly one ALLOW permission set and one
  Permission, no DENY or wildcard, and is reconciled as an ordered,
  multiplicity-preserving aggregate (drift fails closed, never repaired).
- Bob holds metadata-reader only (never content-reader); Alice holds both.
- No resource-instance ACL, wildcard grant, new policy predicate, migration, or
  evaluator change was introduced. `read-metadata` is not a protected built-in.

## 4. Metadata serialization and atomic disclosure

- `MetadataResponse` is a distinct DTO (`id`, `title`) and is never serialized
  through the content `DocumentResponse`.
- The mixed-operation route serializes the `body` key only for the closed
  `content` operation; metadata results never carry or default a body.
- All distinct documents are resolved **before** the single MTMF evaluation; any
  absent/cross-Tenant row is a generic `404` with zero PDP calls and zero
  partial results.
- `require` is called for every exact `(action, loaded-resource, request-id)`
  occurrence in input order; a single non-ALLOW occurrence returns `403` with
  zero results and zero partial disclosure.

## 5. Error classification (unchanged)

`400` invalid request (no evaluation), `401` invalid/unverified identity or
remote authentication failure, `403` verified actor denied by policy/eligibility
or unmapped subject, `404` missing/malformed/cross-Tenant resource, `503`
transport/timeout/protocol/dependency failure. Every response sets
`Cache-Control: no-store`. A `503` is never reinterpreted as a DENY.

## 6. Fault-boundary TLS and isolation

- The fault fronting component presents a dedicated CA-signed leaf
  (`DNS:mtmf-fault.mtmf.test`), runs only inside the isolated
  `mtmf-pr20a-acceptance` project, publishes no host port, and is removed on
  teardown.
- The canonical `service-tls-proxy` and its `mtmf.mtmf.test` alias are
  untouched; TLS verification is never disabled; the client, the PDP transport,
  and the default stack are unmodified.
- Fault mode is read from a **local, host-owned control file** (read-only inside
  the proxy). There is no HTTP fault-control endpoint and the reference app
  cannot set faults.
- Faults apply only to `/v1/authorization/evaluate`; the token endpoint, JWKS,
  and health traffic are never substituted. Each test restores `none` in
  `finally`, and F07 proves healthy recovery.

## 7. Evidence and secret handling

- The proxy's evidence file is non-secret: a monotonic counter plus
  `request_id`, exact Action, effect, non-secret resource id, fault-mode
  activations, and error status/code. It never records tokens, authorization
  headers, request/response bodies, claims, or document content.
- `POST` authorization is never retried; a timed-out or cancelled evaluation
  never becomes a late disclosure; `asyncio.CancelledError` propagates and
  worker permits remain held until the underlying work finishes (PR 20A fixup 01
  preserved).

## 8. Deliberately unchanged

- `packages/**`, `sql/**`, migrations, protected built-in manifests,
  `compose.yaml`, `compose.dev.yaml`, `compose.pr20a-acceptance.yaml`,
  `scripts/pr20a-reference-acceptance.py`, `scripts/pr20a-initialize.py`,
  `scripts/pr20a_reference_fixture.py`, historical PR 20A reports, and
  `dev/keycloak/expected-*.json`.
- Default `mtmf` stack and all foreign (ATI/Darkula/PR 19C) resources.

## 9. Residual notes

- The example client now configures a proactive service-token renewal leeway
  (default 30s) so the long deployed suite never presents a service token the
  PDP considers expired. This is an example-level `ClientConfig` value, not a
  change to the official client or MTMF authorization semantics.
- No production policy change, no new runtime DB grant, and no new HTTP
  management surface was added.
