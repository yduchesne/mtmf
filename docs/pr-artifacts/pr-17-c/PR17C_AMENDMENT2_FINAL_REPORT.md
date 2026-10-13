# PR 17-C Amendment 2 — Final Report

## Objective

Eliminate Compose configuration-hash-induced recreation of running
infrastructure during ordinary and repeated `up` operations.

## Root cause (measured)

`compose.dev.yaml` interpolated the dynamic forwarder address into
`initializer`/`service` `extra_hosts`
(`keycloak.mtmf.test:${MTMF_DEV_FORWARDER_IP:-127.0.0.1}`). `podman-compose 1.0.6`
derives a project-wide config hash from the rendered model; because the launcher
discovered and exported `MTMF_DEV_FORWARDER_IP` only after infrastructure
started, the later `compose up -d service` rendered a different hash and
recreated all four containers. Repeated `up` also recreated them because the
forwarder address is reassigned on recreation. Confirmed by container
ID/`StartedAt` snapshots and two different config hashes in the launcher log.

## Fix

- Removed the dynamic `extra_hosts` from `initializer`/`service`.
- Added a committed static resolver override `dev/nsswitch.conf`
  (`hosts: dns files`) mounted at `/etc/nsswitch.conf` in both services, making
  the MTMF network alias authoritative over the copied host `/etc/hosts`.
- Launcher: removed `_forwarder_ip()`/`MTMF_DEV_FORWARDER_IP`; the container
  probe mounts the same resolver override; `preflight()` uses the same bounded
  probe retry as `up()`.

No dynamic value remains in the Compose model, so the hash is invariant across
invocations and runs.

## Verification (amended tip)

- **Gates:** `--qa` **2014 passed / 90.75%**, `--sec` 0 findings, `--rust` PASS,
  `--integration` **564 passed / 65 skipped**.
- **Lifecycle:** transition `up` recreated once (expected), then **three
  consecutive `up` cycles** each exited 0 with **zero** `podman stop`/`rm`, and
  preserved all four container IDs and `State.StartedAt`; immediate `preflight`
  exited 0 after every cycle. `down` → `up` preserved volumes, used the same
  stable Compose hash, had `stop/rm=0`, and preserved the Keycloak development
  user `sub`.
- **Routing:** running service resolves `keycloak.mtmf.test` to the current
  forwarder even with the copied `127.0.0.1` entry present; discovery issuer,
  JWKS URI and token `iss` remain exact; forwarder unpublished; all host
  publications loopback-only; no privileged runtime credentials.
- **Regressions:** PR 17-B 13/13, PR 14 22/22, PR 17 26/26.

## Changed files

```text
compose.dev.yaml
dev/nsswitch.conf                       (new)
scripts/mtmf-dev-stack.py
tests/unit/service/test_pr17c_dev_stack.py
docs/pr-artifacts/pr-17-c/PR17C_AMENDMENT2_*.md
docs/DEVELOPMENT_SETUP.md
docs/ROADMAP_V01.md
```

`scripts/mtmf-dev-forwarder.py`, `scripts/mtmf-dev-probe.py`,
`scripts/mtmf-dev-certs.py`, authentication/authorization code, SQL/migrations,
public APIs and PR 17-B provisioning were **not** modified.

## Remaining risks / reviewer action

- **AM2-D1:** a pre-existing forwarder event-loop transient can still make a
  single container probe time out; `preflight` mitigates it with a bounded probe
  retry (same as `up`). A separate approved forwarder fix is recommended if the
  retry is judged insufficient.
- **AM2-D3:** live forwarder-rebuild refresh (LC13) not executed; deterministic
  counterpart passes and no address is cached.
- **N17/N18:** Windows-browser acceptance remains unexecuted.

PR 17-C remains **AWAITING HUMAN REVIEW — NOT DONE**.
