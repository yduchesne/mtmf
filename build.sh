#!/usr/bin/env bash
#
# Canonical MTMF quality gates.
#
# Usage:
#   ./build.sh --qa
#   ./build.sh --sec
#   ./build.sh --rust
#   ./build.sh --integration
#
# --qa runs the default quality gate, in order and failing fast:
#   1. Ruff formatting check
#   2. Ruff lint
#   3. strict Mypy
#   4. unit tests with a hard >= 85% coverage gate
#
# --sec runs the security scan, in order and failing fast:
#   1. Bandit (Python security linter) over packages/ and tests/
#   2. Semgrep (static analysis) over packages/ and tests/
#
# --rust runs the deterministic Rust/native gate for the private
#   mtmf-permission-engine crate (PR 8A), in order and failing fast:
#   1. cargo fmt --check
#   2. cargo clippy --all-targets --all-features -- -D warnings
#   3. cargo test
#   4. maturin develop (native build + development install)
#   5. focused Python native-boundary tests
#   The Rust gate never uses Podman, PostgreSQL, MTMF_POSTGRES_*,
#   --integration resources, network services, or external credentials.
#
# --integration runs the real-PostgreSQL migration/schema/constraint
#   integration suite against the explicitly configured MTMF database
#   (MTMF_* variables). Start it first with:
#       uv run python scripts/mtmf-postgres.py up
#   The integration suite never runs as part of --qa; it fails closed
#   when MTMF database configuration is missing or ambiguous.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

MODE="${1:-}"

case "${MODE}" in
    --qa)
        echo "==> Running formatting check with ruff (format --check)"
        uv run ruff format --check .

        echo "==> Running lint with ruff (ruff check)"
        uv run ruff check .

        echo "==> Running static analysis with mypy (strict mode)"
        uv run mypy packages

        echo "==> Running unit tests with pytest (coverage gate >= 85%)"
        uv run pytest tests/unit
        ;;
    --sec)
        echo "==> Running security lint with bandit (Medium/High severity gate)"
        # The default Low threshold reports test-only noise (e.g. B101
        # asserts in tests); fail on Medium/High findings instead.
        uv run bandit -r packages tests -ll

        echo "==> Running static analysis with semgrep (registry rules)"
        uv run semgrep scan --config=auto packages tests
        ;;
    --rust)
        RUST_CRATE_DIR="${SCRIPT_DIR}/packages/mtmf-permission-engine"

        if ! command -v cargo >/dev/null 2>&1; then
            echo "ERROR: --rust requires the Rust toolchain (cargo) on PATH." >&2
            echo "       Install it with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
            exit 1
        fi

        # Pin the interpreter used by PyO3/maturin to the canonical
        # uv-managed venv so builds are deterministic regardless of the
        # ambient PATH.
        PYO3_PYTHON="$(uv run python -c 'import sys; print(sys.executable)')"
        export PYO3_PYTHON

        echo "==> Running Rust formatting check (cargo fmt --check)"
        (cd "${RUST_CRATE_DIR}" && cargo fmt --check)

        echo "==> Running Clippy with warnings denied (cargo clippy -- -D warnings)"
        (cd "${RUST_CRATE_DIR}" && cargo clippy --all-targets --all-features -- -D warnings)

        echo "==> Running native tests (cargo test)"
        (cd "${RUST_CRATE_DIR}" && cargo test)

        echo "==> Building and installing the private native module (maturin develop)"
        uv run maturin develop --manifest-path "${RUST_CRATE_DIR}/Cargo.toml"

        echo "==> Running focused Python native-boundary tests"
        # Focused on the 8A native boundary; the full coverage gate stays
        # with --qa.
        uv run pytest tests/unit/authorization/test_rust_engine.py --no-cov
        ;;
    --integration)
        echo "==> Running PostgreSQL integration tests (MTMF-owned database only)"
        echo "    Requires the MTMF PostgreSQL service; start it with:"
        echo "        uv run python scripts/mtmf-postgres.py up"
        echo "    Tests FAIL CLOSED when MTMF_* database configuration is missing."
        uv run pytest tests/integration/postgres --no-cov
        ;;
    *)
        echo "usage: $0 --qa | --sec | --rust | --integration" >&2
        exit 2
        ;;
esac