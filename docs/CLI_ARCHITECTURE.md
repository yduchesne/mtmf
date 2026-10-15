# MTMF Administrative CLI — Architecture and Requirements

**Status:** Approved design baseline; documentation only. Commands below are a proposed public interface, not implemented features.

## Purpose and boundaries

MTMF SHALL provide a first-class, application-neutral `mtmf` administrative command-line interface distributed as `mtmf-cli` from the MTMF monorepo. It serves interactive administrators, operators, and scripted automation without weakening the existing HTTP-only integration architecture.

The CLI MUST call MTMF through the official `mtmf-client` and public versioned HTTPS APIs. It MUST NOT import `mtmf-core`, `mtmf-service`, native permission engine, database drivers/repositories, privileged installation helpers, or access MTMF persistence directly. `mtmf-api` may be a transitive public-contract dependency through `mtmf-client`. Every mutation requires server-side verified actor context, exact-Action authorization, Tenant scope validation, and atomic server-side audit. CLI-side checks are UX only, never authority.

The separately specified production root recovery operator utility is **not** a subcommand or privileged mode of `mtmf-cli`. No root impersonation, arbitrary user-ID override, emergency bypass, or unrestricted client-credentials administration.

## Technology and packaging

- Python 3.14+; Typer for composable hierarchical commands, typed parameters, help, and shell completion; Rich for human-readable tables and diagnostics.
- New `packages/mtmf-cli` distribution with `[project.scripts] mtmf = "mtmf_cli.main:app"`; dependency on `mtmf-client`, not internal service/core.
- Include `mtmf-cli` in the uv workspace and coordinated version/release policy once implemented; update lockfile, packaging gates, README, and VERSIONING.md in the implementation PR.
- Proposed package layout: `mtmf_cli/main.py`, `context.py`, `config.py`, `output.py`, `auth/`, and resource modules under `commands/`. Separate argument parsing/presentation from typed HTTP operations.

## Proposed command hierarchy

```text
mtmf [--profile NAME] [--output table|json] [--endpoint URL]
  auth login | logout | status
  config show | set | profiles
  tenants list | show | add | update
  organizations list | show | add | update
  principals list | show
  groups list | show | add
  groups members list | add | remove
  roles list | show | assign
  applications list
  applications subscriptions list | add | remove
  authorization evaluate
```

Examples (illustrative, not executable until corresponding APIs exist):

```shell
mtmf tenants add --name Acme
mtmf organizations add --tenant <tenant-uuid> --name Engineering
mtmf groups add --tenant <tenant-uuid> --name Analysts
mtmf groups members add --tenant <tenant-uuid> --group <group-uuid> --principal <principal-uuid>
mtmf --profile staging --output json tenants list
```

Command groups are plural resource nouns; verbs are explicit subcommands (`list`, `show`, `add`, `update`, `remove`, `assign`). Resource identifiers are canonical UUIDs. Commands operating on Tenant-owned resources MUST require explicit Tenant context unless the server's API contract defines a safe unambiguous alternative. Do not infer Tenant from an unrelated local setting for security-sensitive mutations. IDs printed on creation must be authoritative server-returned IDs. CLI flags MUST map to actual HTTP contracts; no client-side fabricated permissions or identifiers.

**API availability rule:** A documented command is not implemented until a corresponding authorized HTTP operation exists in `mtmf-client` and the deployed service. Do not substitute local database writes, privileged scripts, or fake success. Initial implementation must only expose operational commands backed by existing endpoints. Deferred commands remain in this design catalog, not in executable help as functional features. `tenants add` depends on the PR 21–26 onboarding/management contracts.

## Authentication and credential security

- Interactive human administration: standards-based OIDC Authorization Code + PKCE or Device Authorization **only where the configured IdP and service identity-propagation contract support it**; exact login mechanism is a design/implementation gate, not an assertion that it currently exists.
- Automation: OAuth 2.0 Client Credentials through the official client and configured IdP, subject to the service's actual authorization model. Client Credentials alone MUST NOT imply a human actor or administrative privilege.
- Propagate verified end-user identity separately from service identity using the approved MTMF trust boundary; never accept a free-form `--as-user` override as proof of identity.
- Never log or print tokens, client secrets, refresh tokens, passwords, or sensitive HTTP headers. Redact config output. Avoid placing secrets on command lines; prefer protected environment/credential stores or interactive secret entry. File permissions and token storage/refresh/logout semantics require explicit review before implementing persistent interactive login.
- TLS certificate verification is enabled by default; no production insecure bypass. Timeouts, retry policy, idempotency keys, and safe error reporting follow `mtmf-client` semantics. Mutations must not be automatically retried unless the operation is contractually idempotent.

## Configuration and deterministic CLI contracts

- Support named profiles (for endpoint and nonsecret defaults), documented environment overrides, and explicit command options. Define and test precedence: CLI option > environment > selected profile > safe built-in default. No implicit fallback to a production endpoint.
- `--output table|json`: table for interactive humans, JSON for scripts; JSON goes to stdout with stable versioned fields and no decorative text. Diagnostics and progress go to stderr. Consider `--output json` on every command with meaningful data; error JSON schema must be defined before automation relies on it.
- Stable exit-code contract, proposed: 0 success; 2 CLI usage/validation; 3 authentication; 4 authorization denied; 5 resource not found/conflict (distinguish by structured error code); 6 connectivity/service unavailable; 7 other server/contract failures. Freeze exact mapping and JSON envelopes in CLI foundation PR tests.
- Pagination, filtering, sorting, and list bounds must mirror actual API support; never silently fetch unbounded results or invent server filters.
- Destructive commands require interactive confirmation unless `--yes` is supplied. In noninteractive contexts, refuse a destructive command without `--yes`. `--yes` does not bypass server authorization.
- Help/completion and error messages must be deterministic and usable without an active MTMF service.

## Testing and acceptance

1. Unit/CLI-runner tests for nested parsing, UUID validation, profile precedence, output formats, exit codes, confirmation, noninteractive behavior, and redaction.
2. Mocked HTTP client contract tests for request mapping, pagination, timeouts, failure classification, no secret leakage, and no privileged bypass.
3. Build/install the CLI wheel in a clean environment without workspace editable assumptions; verify `mtmf --help` and shell completion.
4. Real deployed acceptance for each exposed management mutation: valid administrator, unauthenticated, unauthorized, wrong-Tenant, invalid actor propagation, conflict/retry, audit verification, and noninteractive JSON/exit-code behavior.
5. Existing QA, security, Rust, PostgreSQL, and deployed gates remain applicable to the monorepo; no tests are marked passed without execution.

## Delivery plan and dependency gates

- **CLI-1 — Foundation:** packaging, Typer hierarchy, Rich output, profile/config resolution, secure authentication integration **only for supported flows**, typed client context, stable errors/exit codes, help/completion, install and unit/contract tests. No invented management APIs.
- **CLI-2 — Existing management API coverage:** implement commands backed by currently available authenticated HTTP endpoints, with real deployed authorization/audit acceptance. The initial endpoint inventory must be verified against the then-current service and client.
- **CLI-3 — Expanded management:** Tenant, Organization, Group, Role, Application/subscription, and invitation commands incrementally as PR 21–26 or subsequent authorized management APIs are delivered. This is a staged scope, not a commitment that all APIs already exist.

CLI work is parallel to and **not a prerequisite** for onboarding PRs 21–26. CLI-3's individual commands depend on their HTTP API contracts. No unplanned separate security-audit PRs: each implementing PR owns the relevant adversarial and audit acceptance.

## Compatibility and change control

Once released, command paths, option names, exit codes, JSON schemas, and noninteractive behavior are public automation contracts. Incompatible changes require explicit release notes and versioning review under `VERSIONING.md`. This document may be refined in implementation PRs only with explicit rationale and updated acceptance tests.
