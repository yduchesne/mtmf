# PR 17-C Final Report

## Summary

PR 17-C makes the **standard isolated Compose `up`** the supported normal development
path with one canonical, TLS-verified Keycloak authority —
`https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev` — visible to the Windows
browser, the WSL2 host, the privileged one-shot initializer, and the restricted MTMF
service. It removes the host-network workaround from the normal path without relaxing
issuer or TLS verification.

## What changed

- **Canonical TLS/PKI:** `scripts/mtmf-dev-certs.py` generates an idempotent local CA
  and a `keycloak.mtmf.test` leaf, owner-maps the leaf key to the Keycloak container UID
  (`podman unshare chown`), and fails closed rather than widening key permissions.
- **Canonical networking:** `compose.dev.yaml` runs Keycloak with strict canonical
  hostname and explicit certificate files; a new non-privileged, unpublished
  `forwarder` (`scripts/mtmf-dev-forwarder.py`) maps canonical `28443` to Keycloak
  `8443` without terminating TLS; the initializer/service pin the canonical authority
  to the forwarder via `extra_hosts`.
- **Preflight:** `scripts/mtmf-dev-probe.py` checks DNS, TCP, TLS/SAN/CA, discovery
  issuer equality, and JWKS from both the host and a container namespace; the launcher
  runs it with bounded retry before any state is written.
- **Launcher:** `scripts/mtmf-dev-stack.py` prep data CA/leaf, starts
  postgres+keycloak+forwarder, probes both namespaces, runs the privileged initializer
  exactly once, then starts the restricted service; it rewrites container DB URLs to
  the internal `postgres:5432` authority, refuses a non-canonical issuer, and redacts
  secrets from captured subprocess output.
- **Approved development authority:** a central helper allows loopback plus
  `keycloak.mtmf.test` only; arbitrary hosts stay rejected.
- **Loopback-only publications:** `compose.yaml` PostgreSQL is now
  `127.0.0.1:25432:5432`.
- **Docs:** `docs/DEVELOPMENT_SETUP.md`, `dev/keycloak/README.md`, `docs/ARCHITECTURE.md`,
  `.env.example`, and `docs/ROADMAP_V01.md`.

## Verification (final code)

- `./build.sh --qa` — 1947 passed, coverage 90.75%.
- `./build.sh --sec` — 0 findings.
- `./build.sh --rust` — pass (no native change).
- `./build.sh --integration` — 564 passed, 65 skipped.
- Standard `up` (no host networking) — exit 0; host+container preflight OK; initializer
  complete; service ready.
- Repeat `up` — exit 0, identical DB counts; Keycloak user count 1.
- `down`/`up` cycle — MTMF-only teardown, volumes preserved, canonical issuer stable.
- Live regressions against the canonical issuer: PR 17-B 13/13, PR 14 22/22, PR 17
  26/26.
- Negative controls (DNS, CA, SAN, realm) all fail closed.

## Status

**Implementation and WSL/Podman live acceptance are complete. Windows-browser manual
cases (N17/N18) are NOT EXECUTED and NOT claimed. The PR remains awaiting human review
and is not marked DONE.** See:

- [baseline](PR17C_BASELINE_REPORT.md)
- [network decision](PR17C_NETWORK_DECISION.md)
- [test matrix](PR17C_TEST_MATRIX.md)
- [security review](PR17C_SECURITY_REVIEW.md)
- [acceptance report](PR17C_ACCEPTANCE_REPORT.md)
- [STOP/deviation register](PR17C_STOP_DEVIATION_REGISTER.md)
