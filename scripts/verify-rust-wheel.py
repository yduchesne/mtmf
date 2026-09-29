#!/usr/bin/env python3
"""Verify a clean wheel build/install of the private Rust permission engine.

PR 8E package verification (Workstream B): ``maturin develop`` is not
package proof, so this script builds a real wheel from the canonical
crate configuration, installs it into a freshly created temporary
virtual environment that uses the same Python version as the canonical
interpreter, and proves the installed module:

- imports as the private ``_mtmf_permission_engine`` module;
- exposes the capability surface (``engine_version``, ``match_permission``,
  ``evaluate``);
- evaluates at least one valid policy correctly;
- fails explicitly on malformed input (never a policy decision).

The temporary environment and wheel artifacts are removed when the
script exits (``--keep`` retains them for debugging). Global Python is
never mutated, no PostgreSQL/Podman/network service or credential is
used, and nothing here evaluates authorization context.

Example (canonical usage):

    uv run --no-sync python scripts/verify-rust-wheel.py \\
        --interpreter "$(uv run --no-sync python -c 'import sys; print(sys.executable)')"
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CRATE_DIR = REPO_ROOT / "packages" / "mtmf-permission-engine"

# The module must stay private: the public ``mtmf_api`` package must
# never import or expose it. The clean environment normally cannot
# install ``mtmf-api`` (this verification installs only the wheel), so
# the check runs defensively when the package happens to be present.
_VERIFY_CODE = r"""
import sys

import _mtmf_permission_engine as native

required = ("engine_version", "match_permission", "evaluate")
missing = [name for name in required if not callable(getattr(native, name, None))]
if missing:
    raise SystemExit("installed module is missing required callables: %r" % (missing,))

version = native.engine_version()
if not isinstance(version, str) or not version:
    raise SystemExit("invalid engine_version response: %r" % (version,))

action = "urn:mtmf:iam:actions:system:principal:set-active"
wildcard = "urn:mtmf:iam:permissions:system:principal:set-*"

# Capability smoke (deterministic).
assert native.engine_version() == version

# A valid evaluation returns the documented primitive result.
decision, specificity, matched_allow, matched_deny, reason = native.evaluate(
    action, [("allow", [wildcard])]
)
if (decision, specificity, matched_allow, matched_deny, reason) != (
    "allow",
    "qualifier-wildcard",
    True,
    False,
    None,
):
    raise SystemExit(
        "unexpected valid evaluation result: %r"
        % ((decision, specificity, matched_allow, matched_deny, reason),)
    )

# A malformed evaluation fails explicitly and can never become a decision.
try:
    native.evaluate(action, [("allow", ["not-a-urn"])])
except ValueError:
    pass
else:
    raise SystemExit("malformed evaluation must fail explicitly, not yield a decision")

# Private-module boundary: mtmf-api must never import the native module.
try:
    import mtmf_api  # noqa: F401
except ImportError:
    pass
else:
    if "_mtmf_permission_engine" in sys.modules:
        raise SystemExit("mtmf_api must not import the private native module")

print("installed wheel OK (engine_version=%r)" % (version,))
"""


def _run(command: list[object], *, cwd: Path | None = None) -> None:
    """Run one verified subprocess and fail loudly on any error."""
    print("+", shlex.join(str(part) for part in command))
    subprocess.run([str(part) for part in command], cwd=cwd, check=True)


def _build_wheel(interpreter: Path, out_dir: Path) -> Path:
    """Build the wheel through the pinned maturin (canonical config)."""
    _run(
        [
            sys.executable,
            "-m",
            "maturin",
            "build",
            "--manifest-path",
            str(CRATE_DIR / "Cargo.toml"),
            "--interpreter",
            str(interpreter),
            "--out",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
    )
    wheels = sorted(out_dir.glob("mtmf_permission_engine-*.whl"))
    if not wheels:
        raise SystemExit(f"maturin produced no wheel in {out_dir}")
    return wheels[-1]


def _verify_wheel_in_clean_venv(interpreter: Path, wheel: Path, root: Path) -> None:
    """Install the wheel in a fresh venv and run the capability probe."""
    venv_dir = root / "venv"
    _run([str(interpreter), "-m", "venv", str(venv_dir)])
    venv_python = venv_dir / "bin" / "python"
    _run([str(venv_python), "-m", "pip", "install", "--quiet", str(wheel)])
    _run([str(venv_python), "-c", _VERIFY_CODE])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--interpreter",
        default=sys.executable,
        help="canonical Python interpreter the wheel is built/verified for "
        "(defaults to the interpreter running this script)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the temporary environment and wheel directory for debugging",
    )
    args = parser.parse_args()

    interpreter = Path(args.interpreter).resolve()
    if not interpreter.is_file():
        raise SystemExit(f"interpreter not found: {interpreter}")

    with tempfile.TemporaryDirectory(
        prefix="mtmf-wheel-verify-", delete=not args.keep
    ) as temp_text:
        root = Path(temp_text)
        out_dir = root / "wheels"
        out_dir.mkdir()
        wheel = _build_wheel(interpreter, out_dir)
        _verify_wheel_in_clean_venv(interpreter, wheel, root)
        for entry in sorted(root.iterdir()):
            print(f"artifact: {entry}")
        if args.keep:
            print(f"temporary artifacts retained at: {root}")
    print("clean wheel build/install/import/use verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
