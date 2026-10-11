# MTMF PR 14 Track 2 — isolated Keycloak evidence fixture

**Status: DEVELOPMENT-ONLY EVIDENCE FIXTURE. Not production configuration and
not part of the MTMF runtime or integration stack.**

This directory contains a deliberately isolated Keycloak issuer used only to
collect reproducible, sanitized evidence about issuer claim behavior for the
PR 14 authentication security decisions. It does **not** implement any MTMF
authentication; see [`docs/PR14_KEYCLOAK_EVIDENCE.md`](../../docs/PR14_KEYCLOAK_EVIDENCE.md).

## What is here

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Isolated single-service Compose fixture (explicit project `mtmf-pr14-keycloak`) |
| `setup-realm.py` | Idempotent Admin REST realm/client/user/mapper setup; prints a secret-free manifest |
| `evidence/pr14-keycloak-evidence.json` | Sanitized observed results (no tokens, secrets, or PII) |
| `evidence/pr14-keycloak-config-manifest.json` | Sanitized configuration manifest |

The collector itself is [`scripts/pr14-keycloak-evidence.py`](../../scripts/pr14-keycloak-evidence.py).

## Pinned versions

- Keycloak image: `quay.io/keycloak/keycloak:26.8.0-1`
- Image digest: `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741`
- Reported server version: `Keycloak 26.8.0`
- Container runtime: rootless Podman + `podman-compose` (tested with Podman 4.9.3 / podman-compose 1.0.6)

## Isolation and resource ownership

- The Compose project name is always explicit: `mtmf-pr14-keycloak`.
- Service: `keycloak`. Named volume: `mtmf-pr14-keycloak-data`.
- No `container_name`; no wildcard prune/discovery. MTMF tooling must never
  touch ATI, Digr, Darkula, Hammeridian, or other projects' resources.
- Host ports use the MTMF `2` prefix and bind to loopback only:
  `127.0.0.1:28080 -> 8080` and `127.0.0.1:28443 -> 8443`.
- This file is intentionally separate from the repository-root `compose.yaml`
  and is never started by the MTMF production/integration workflows.

## TLS

The pinned issuer emits `Secure` cookies, which an HTTP client (and a browser
over plain HTTP) will not return. The fixture therefore serves HTTPS on
loopback using an operator-generated self-signed certificate. Generate it
before starting:

```bash
mkdir -p /tmp/mtmf-pr14-kc-tls
openssl req -x509 -newkey rsa:2048 -sha256 -days 3 -nodes \
  -keyout /tmp/mtmf-pr14-kc-tls/server.key \
  -out    /tmp/mtmf-pr14-kc-tls/server.crt \
  -subj "/CN=mtmf-pr14-dev" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
chmod 755 /tmp/mtmf-pr14-kc-tls
chmod 644 /tmp/mtmf-pr14-kc-tls/server.crt /tmp/mtmf-pr14-kc-tls/server.key
```

The certificate and key are disposable, are never committed, and live only
under `/tmp`. The collector pins the CA with `MTMF_PR14_KC_CA_FILE`.

## Secrets

Create an **uncommitted** env file (never commit it, never put it in an image):

```bash
umask 077
cat > /tmp/mtmf-pr14-kc.env <<EOF
MTMF_PR14_KC_ADMIN_USERNAME=mtmf-pr14-admin
MTMF_PR14_KC_ADMIN_PASSWORD=$(python -c 'import secrets;print(secrets.token_hex(24))')
MTMF_PR14_KC_USER_PASSWORD=$(python -c 'import secrets;print(secrets.token_hex(24))')
MTMF_PR14_KC_HTTP_PORT=28080
MTMF_PR14_KC_HTTPS_PORT=28443
MTMF_PR14_KC_TLS_DIR=/tmp/mtmf-pr14-kc-tls
MTMF_PR14_KC_BASE=https://127.0.0.1:28443
MTMF_PR14_KC_CA_FILE=/tmp/mtmf-pr14-kc-tls/server.crt
EOF
```

Client secrets and user passwords are created at runtime by
`setup-realm.py`; they are not committed.

## Start, configure, collect, stop

```bash
# Start the isolated fixture
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml \
  --env-file /tmp/mtmf-pr14-kc.env up -d

# Wait for readiness
set -a; . /tmp/mtmf-pr14-kc.env; set +a
uv run --no-sync python scripts/pr14-keycloak-evidence.py wait

# Configure the synthetic realm/clients/users/mappers (idempotent)
uv run --no-sync python dev/keycloak/setup-realm.py

# Collect and print the sanitized evidence report
uv run --no-sync python scripts/pr14-keycloak-evidence.py collect \
  --report dev/keycloak/evidence/pr14-keycloak-evidence.json

# Inspect one token supplied on stdin (never prints the raw token)
uv run --no-sync python scripts/pr14-keycloak-evidence.py inspect-token < token.jwt

# Clean-recreate (K22) — removes only the owned project's container/volume
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml \
  --env-file /tmp/mtmf-pr14-kc.env down -v

# Stop without deleting data
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml \
  --env-file /tmp/mtmf-pr14-kc.env down
```

## D1 client-binding evidence (DC01–DC08)

`scripts/pr14-keycloak-evidence.py collect` also runs the D1 follow-up cases
against the same fixture: one client obtaining both a client-credentials
and an auth-code+PKCE token (DC01), distinct-client mismatch (DC02), wrong
audience (DC03), ID/refresh/swapped tokens (DC04), missing client identity
(DC05), untrusted issuer/bad signature/expired token (DC06), domain-binding
limits (DC07), and clean-recreate reproducibility (DC08). `DC05` and
`DC07` are **NOT EXECUTED** and must not be read as PASS. See
[`docs/PR14_KEYCLOAK_EVIDENCE.md`](../../docs/PR14_KEYCLOAK_EVIDENCE.md) §6A.

The fixture includes a short-lived (`access.token.lifespan=1`)
`mtmf-evidence-expiry` client used only for the expired-token negative case.

## Manual-only cases

- **Root phishing-resistant assurance (K15–K17).** Enrolling a WebAuthn/passkey
  credential and completing a high-assurance login requires a real browser and
  authenticator. It is **NOT EXECUTED** here and is reported as BLOCKED. Do not
  substitute an OTP or password login and call it phishing resistance.
- **Root low-assurance control (K17).** The collector runs a password-only root
  login and records only the generic realm assurance (`acr=1`, no `amr`).

## Harness caveat

`podman-compose` echoes the fully substituted `podman run` command, including
environment values, to its stdout. This can print the bootstrap admin password
to a terminal or CI log. Run fixture startup with output redirected (as above)
and treat any such log as sensitive. The evidence collector itself never prints
secrets, tokens, or PII.
