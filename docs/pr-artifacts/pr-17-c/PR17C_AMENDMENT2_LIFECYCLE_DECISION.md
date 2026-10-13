# PR 17-C Amendment 2 — Lifecycle Decision

## Decision

Remove the **dynamic forwarder address from the Compose model** so the effective
configuration is identical for every Compose invocation of a `up` and across
repeated `up` operations. This is done by replacing the IP-interpolated
`extra_hosts` mapping with a **static resolver override** mounted into the
initializer and service.

## Exact change

1. `compose.dev.yaml`:
   - removed `extra_hosts: "keycloak.mtmf.test:${MTMF_DEV_FORWARDER_IP:-127.0.0.1}"`
     from `initializer` and `service`;
   - added the constant bind mount
     `./dev/nsswitch.conf:/etc/nsswitch.conf:ro` to both services.
2. `dev/nsswitch.conf` (new, committed): `hosts: dns files`.
3. `scripts/mtmf-dev-stack.py`:
   - `up()` no longer sets `os.environ["MTMF_DEV_FORWARDER_IP"]` mid-run;
   - `_forwarder_ip()` (IP discovery) was removed;
   - `_probe_container()` mounts the same `dev/nsswitch.conf` instead of passing
     `--add-host keycloak.mtmf.test:<ip>`;
   - `preflight()` uses the same bounded `_probe_until_stable` retry as `up()`
     (transport robustness; documented deviation).
4. `tests/unit/service/test_pr17c_dev_stack.py`: LC01–LC16 deterministic tests.

## Why this prevents recreation

Rootless Podman copies the host `/etc/hosts` into every container, so an
operator `127.0.0.1 keycloak.mtmf.test` entry shadows the MTMF network alias.
Ordering DNS before `files` makes the isolated MTMF DNS (aardvark) authoritative:
`keycloak.mtmf.test` resolves to whatever address the `forwarder` service
currently has, with **no per-container address in the Compose model**.

Because the Compose model now contains only static values, the project-wide
config hash is invariant across the first (`postgres keycloak forwarder`) and
second (`service`) invocations and across repeated `up` runs. `podman-compose`
therefore finds no changed containers to recreate.

The final running containers were verified live to resolve
`keycloak.mtmf.test` to the actual current forwarder address
(`getent hosts` → `10.89.26.111`, the forwarder IP) even though the copied
`/etc/hosts` still contains `127.0.0.1 keycloak.mtmf.test`, and the immediate
`preflight` passed with TLS + exact issuer/JWKS.

## Alternatives considered

| Alternative | Rejected because |
| --- | --- |
| `--no-deps` on the service start only | Does not fix the first `compose up` invocation: the stored container hash still differs from the model whenever the forwarder address changes, so infrastructure would still be recreated on repeated `up`. |
| Static network IP for the forwarder | Requires inventing/owning a subnet and relying on addresses staying fixed across recreation; explicitly discouraged by the plan. |
| Resolve-and-rewrite `/etc/hosts` inside an entrypoint wrapper | Larger behavioural change to image startup; the static `nsswitch.conf` mount is smaller and does not change the entrypoint. |
| Mount a launcher-written hosts file over `/etc/hosts` | Works, but replaces the whole file and is more invasive than a resolver-policy file; the plan prefers preserving normal container `/etc/hosts`. |
| Keep `extra_hosts` with a dynamic IP | The dynamic value is the defect. |
| Retry/`--force-recreate` masking | Explicitly forbidden by the plan. |

## Canonical-routing preservation

- The forwarder path (`canonical 28443 → keycloak:8443`, no TLS termination) is
  unchanged; `scripts/mtmf-dev-forwarder.py` was **not** modified.
- TLS verification, exact issuer equality, and exact JWKS endpoint (Amendment 1)
  are unchanged and re-verified live.
- `MTMF_DEV_FORWARDER_IP` is no longer referenced anywhere in the repository.

## Supported Compose semantics verified in this environment

- `podman-compose 1.0.6` assigns the same `io.podman.compose.config-hash` to all
  project containers and recreates a container whose rendered service config
  differs (observed live as `podman stop`/`podman rm` + `podman run`).
- Compose `volumes` bind mounts support overriding `/etc/nsswitch.conf`
  read-only (verified with a throwaway container and live service).
- glibc honours `nsswitch.conf` `hosts: dns files` ordering: the MTMF DNS alias
  wins over the copied host entry (verified live in the running service).
