# MTMF Versioning and Release Policy

## 1. Scope and authority

This document governs versioning, Git releases, Python distributions, the public HTTP API, and reproducible consumption of MTMF from independently deployed applications such as ATI and Digr. It is the normative release policy; examples are illustrative until corresponding versions/tags have actually been published. No release is created merely by merging this document.

## 2. Distinct version dimensions

| Dimension | Example | Contract |
| --- | --- | --- |
| Repository release | `v0.1.0a1` | Tested, immutable snapshot of the MTMF monorepo |
| Python distribution | `mtmf-client==0.1.0a1` | Installable client code and its Python API |
| HTTP wire API | `/v1/authorization/evaluate` | Versioned service request/response and authorization semantics |
| Consumer release | ATI's own version | Independently versioned deployment and dependency lock |

A repository tag does not substitute for the Python distribution's declared `[project].version`. The HTTP API major version is not inferred from either Python or Git version numbers. A compatible client package update does not automatically require a new HTTP API major version.

## 3. Initial coordinated Python package versioning

For MTMF v0.1, use a **coordinated release version** for the four distributions (`mtmf-api`, `mtmf-core`, `mtmf-client`, and `mtmf-service`) and any other independently versioned MTMF release artifacts included in the same release. Each Python distribution declares its own matching PEP 440 `[project].version`. Do not assume the current repository already has this policy applied; verify and update package metadata when cutting the first coordinated release.

Independent per-package versioning is deferred until an explicit policy change, including new tag naming and compatibility rules. The public client remains independently installable even while version numbers are coordinated.

Use PEP 440-compatible prerelease identifiers, for example `0.1.0a1`, `0.1.0a2`, `0.1.0b1`, `0.1.0rc1`, and `0.1.0`. Repository release tags add the `v` prefix: `v0.1.0a1`, etc. These are examples, not claims of existing releases.

## 4. Immutable Git release tags

A release tag MUST identify a specific commit that has passed the required quality, security, packaging, and applicable integration gates. Create an annotated tag only after updating distribution versions and verifying the exact release candidate. Never force-update, delete-and-recreate, or repurpose a published release tag. If a release is defective, publish a new version and tag.

Example, after validating the target commit:

```bash
git tag -a v0.1.0a1 -m "MTMF v0.1.0a1"
git push origin v0.1.0a1
```

Moving branches (`main`, feature branches) and mutable symbolic references are not accepted as normal consumer release pins. A temporary development-only commit-SHA pin is permitted when no release tag exists, but must be explicitly identified as provisional and replaced by a tested release tag before declaring the consumer integration release-ready.

## 5. Consumer installation with uv

An external application MUST consume MTMF over its authenticated versioned HTTP API. Python consumers install **only** the official `mtmf-client` distribution, not `mtmf-core`, `mtmf-service`, MTMF database adapters, or the private Rust engine. The client package must build/install from its monorepo subdirectory in a clean environment without editable workspace assumptions or runtime dependencies on sibling MTMF distributions.

Illustrative consumer `pyproject.toml` for a published `v0.1.0a1` tag:

```toml
[project]
dependencies = [
    "mtmf-client==0.1.0a1",
]

[tool.uv.sources]
mtmf-client = {
    git = "https://github.com/yduchesne/mtmf.git",
    tag = "v0.1.0a1",
    subdirectory = "packages/mtmf-client",
}
```

The declared package version MUST match the selected tagged source. The consumer MUST commit both `pyproject.toml` and `uv.lock`. Resolve and verify the lock with:

```bash
uv lock
uv sync --locked
```

CI and deployed builds MUST use the committed lockfile and fail if it is stale; use `uv sync --frozen` only where deliberately accepting no lock freshness check is justified. `uv.lock` captures the resolved Git revision for reproducibility; retain the tag in `pyproject.toml` for readable release intent. Treat access to GitHub and VCS dependency integrity as part of the build supply-chain policy.

For a new release, change both the dependency version and the source tag, regenerate the lockfile, run the consumer's contract/integration gates, and commit both files together. Do not change the tag alone or the version requirement alone.

## 6. HTTP API compatibility

The MTMF service exposes a separately versioned `/v1` HTTP contract. The `mtmf-client` version does not guarantee compatibility with every deployed MTMF service version: document and test the supported client/service release combinations.

Within `/v1`, additive fields/endpoints may be introduced only when existing clients can safely ignore or handle them. Changes to authentication requirements, required request fields, response meanings, authorization decisions, security invariants, or error semantics require explicit compatibility analysis and tests. A breaking wire contract requires a new API version or a separately approved, documented migration; do not silently repurpose `/v1`.

Consumers MUST fail closed on unsupported or malformed authorization responses and must not substitute an embedded policy engine for the remote service.

## 7. Release procedure

1. Select a release candidate commit; confirm approved scope and no unresolved security/release gates for the release's claimed readiness.
2. Set the coordinated PEP 440 version in each distribution; verify `mtmf-client` has no forbidden sibling/runtime dependency.
3. Run repository QA, security, Rust, PostgreSQL integration, client wheel/install, HTTP contract, and deployed acceptance gates appropriate to the release. Record results and any explicitly excluded optional gates.
4. Build release artifacts from the same commit, inspect distribution metadata, and verify clean-environment installation of `mtmf-client` directly from its Git subdirectory.
5. Create and push the annotated immutable `v<package-version>` tag; optionally publish corresponding GitHub release notes and artifacts. No PyPI publication is required for Git-source consumption.
6. Record the service/client compatibility range, migration requirements, known limitations, and any production-readiness exclusions. In particular, a prerelease tag does not imply production root recovery or onboarding release gates have been met.
7. Upgrade each consumer by changing its pinned tag/version and committing the refreshed `uv.lock` after its integration tests pass.

## 8. Fixes, maintenance, and security

Never patch an existing tag in place. Release fixes as a new PEP 440 version and immutable tag (e.g. the next prerelease or `0.1.1` after `0.1.0`). Treat security-sensitive behavior and API compatibility as release acceptance criteria. Do not promise indefinite maintenance of prereleases; document supported versions and upgrade expectations in release notes.

## 9. Ownership and future changes

MTMF owns the HTTP API, client distribution, tags, compatibility matrix, and release notes. ATI, Digr, and other consumers own their dependency pins, lockfiles, local security-reference projections, and integration validation. A move to PyPI, independent distribution versioning, or a new HTTP major version requires an explicit documented decision rather than an implicit packaging change.
