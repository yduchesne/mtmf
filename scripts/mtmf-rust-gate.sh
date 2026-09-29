#!/usr/bin/env bash
# Pre-commit wrapper for the deterministic MTMF Rust/native gate.
#
# Pre-commit runs hooks in the ambient commit environment, whose PATH does
# not necessarily include the rustup toolchain: rustup installs into
# `~/.cargo/bin`, but profiles/shells do not always source `~/.cargo/env`.
# Resolve cargo from the rustup default location before delegating to the
# canonical gate so the hook works regardless of the ambient PATH.
#
# This wrapper performs no policy or build logic of its own: it only
# ensures the canonical `./build.sh --rust` gate can find the Rust
# toolchain, exactly as that gate requires.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

if ! command -v cargo >/dev/null 2>&1 && [ -x "${HOME}/.cargo/bin/cargo" ]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: --rust requires the Rust toolchain (cargo) on PATH." >&2
    echo "       Install it with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
    exit 1
fi

exec "${REPO_ROOT}/build.sh" --rust