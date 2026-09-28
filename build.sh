#!/usr/bin/env bash
#
# Canonical MTMF Python quality gate.
#
# Usage:
#   ./build.sh --qa
#
# Runs, in order and failing fast:
#   1. Ruff formatting check
#   2. Ruff lint
#   3. strict Mypy
#   4. unit tests with a hard >= 85% coverage gate
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ "${1:-}" != "--qa" ]]; then
    echo "usage: $0 --qa" >&2
    exit 2
fi

echo "==> ruff format --check"
uv run ruff format --check .

echo "==> ruff check"
uv run ruff check .

echo "==> mypy (strict)"
uv run mypy packages

echo "==> pytest unit suite (coverage >= 85%)"
uv run pytest tests/unit