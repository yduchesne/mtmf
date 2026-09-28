#!/usr/bin/env bash
#
# Canonical MTMF Python quality gate.
#
# Usage:
#   ./build.sh --qa
#   ./build.sh --sec
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
    *)
        echo "usage: $0 --qa | --sec" >&2
        exit 2
        ;;
esac