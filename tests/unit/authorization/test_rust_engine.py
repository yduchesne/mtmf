"""PR 8A native-boundary tests for the private Rust permission engine.

The matrix covered here mirrors the 8A plan:

- PYO3: the private ``_mtmf_permission_engine`` module imports after the
  canonical ``./build.sh --rust`` build, the smoke API is deterministic,
  the adapter reaches the capability without public leakage, ``mtmf_api``
  never exposes or imports the module, the module is unrelated to
  persistence infrastructure, and no PostgreSQL environment is required.
- AUTH-REG: current authorization behavior is unchanged and independent
  of native-extension availability, and no active authorization path
  imports Rust.

Tests that genuinely require the built native module skip when it is not
installed (for example in plain ``./build.sh --qa`` on a machine that has
not run ``./build.sh --rust``). No test here starts PostgreSQL, Podman,
or any external service.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import mtmf_core.authorization as authorization
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    engine_version,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

NATIVE_MODULE = "_mtmf_permission_engine"

# The exact deterministic capability value produced by the crate
# (packages/mtmf-permission-engine, ENGINE_VERSION constant).
EXPECTED_ENGINE_VERSION = "0.1.0"

# Runs the settled PR 4 evaluation example: exact Action
# principal:set-active against a Role whose PermissionSet ALLOWs
# principal:set-*; the decision must be ALLOW and must not depend on the
# native module's presence. The ``{poison}`` slot either leaves the
# native module untouched or registers a None sentinel so any import
# raises ImportError (simulating absence).
_EVALUATION_CODE = """
import sys
{poison}
from mtmf_core import (
    Action,
    ActionUrn,
    DomainId,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Role,
    RoleUrn,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator

urn_text = "urn:mtmf:iam:roles:system:example"
specifier = PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*")
set_id = DomainId.generate()
role = Role(
    urn=RoleUrn(urn_text),
    name="example",
    permission_sets=(
        PermissionSet(
            id=set_id,
            role_urn=RoleUrn(urn_text),
            effect=PermissionEffect.ALLOW,
            permissions=(
                Permission(
                    id=DomainId.generate(),
                    permission_set_id=set_id,
                    urn=specifier,
                ),
            ),
        ),
    ),
)
action = Action(ActionUrn("urn:mtmf:iam:actions:system:principal:set-active"))
decision = PermissionEvaluator().evaluate(action, (role,))
print(repr(decision))
if not decision.allowed:
    raise SystemExit("expected ALLOW")
"""


def _run_python(code: str, *, drop_mtmf_postgres: bool = False) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if drop_mtmf_postgres:
        env = {key: value for key, value in env.items() if not key.startswith("MTMF_POSTGRES_")}
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def _native() -> ModuleType:
    return pytest.importorskip(NATIVE_MODULE)


# --- PYO3 boundary ---------------------------------------------------------


def test_pyo3_private_module_imports_after_canonical_build() -> None:
    native = _native()
    assert callable(native.engine_version)


def test_pyo3_smoke_api_returns_deterministic_expected_value() -> None:
    native = _native()
    first = native.engine_version()
    second = native.engine_version()
    assert first == second
    assert first == EXPECTED_ENGINE_VERSION


def test_pyo3_adapter_reaches_capability_through_private_module() -> None:
    native = _native()
    assert engine_version() == native.engine_version() == EXPECTED_ENGINE_VERSION


def test_pyo3_adapter_is_private_to_the_authorization_package() -> None:
    assert "rust_engine" not in authorization.__all__
    assert "engine_version" not in authorization.__all__
    assert not hasattr(authorization, "engine_version")
    assert not hasattr(authorization, "RustEngineUnavailableError")


def test_pyo3_native_module_not_exposed_through_mtmf_api() -> None:
    code = f"import sys\nimport mtmf_api\nsys.exit(1 if {NATIVE_MODULE!r} in sys.modules else 0)\n"
    result = _run_python(code)
    assert result.returncode == 0, result.stderr


def test_pyo3_native_module_unrelated_to_persistence_infrastructure() -> None:
    _native()
    code = (
        "import sys\n"
        f"import {NATIVE_MODULE}\n"
        "banned = ('psycopg', 'alembic', 'mtmf_core', 'mtmf_api')\n"
        "sys.exit(1 if any(name in sys.modules for name in banned) else 0)\n"
    )
    result = _run_python(code)
    assert result.returncode == 0, result.stderr


def test_pyo3_native_capability_requires_no_postgres_environment() -> None:
    _native()
    code = (
        "import sys, os\n"
        f"import {NATIVE_MODULE} as native\n"
        "assert not any(name.startswith('MTMF_POSTGRES_') for name in os.environ)\n"
        "assert native.engine_version()\n"
    )
    result = _run_python(code, drop_mtmf_postgres=True)
    assert result.returncode == 0, result.stderr


# --- Hermetic adapter behavior --------------------------------------------


def test_adapter_fails_closed_when_native_module_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A None sentinel in sys.modules makes any import of the native
    # module raise ImportError: this simulates an environment without the
    # canonical native build. The adapter must fail explicitly, never
    # silently.
    monkeypatch.setitem(sys.modules, NATIVE_MODULE, None)
    with pytest.raises(RustEngineUnavailableError):
        engine_version()


def test_adapter_rejects_invalid_native_capability_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(engine_version=lambda: 123),  # type: ignore[return-value]
    )
    with pytest.raises(RustEngineCapabilityError):
        engine_version()


def test_adapter_reads_capability_from_compatible_native_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(engine_version=lambda: EXPECTED_ENGINE_VERSION),
    )
    assert engine_version() == EXPECTED_ENGINE_VERSION


# --- AUTH-REG: authorization behavior is unchanged -------------------------


def test_authreg_evaluation_is_identical_with_and_without_native_module() -> None:
    plain = _run_python(_EVALUATION_CODE.format(poison=""))
    poisoned = _run_python(
        _EVALUATION_CODE.format(poison=f"sys.modules[{NATIVE_MODULE!r}] = None\n")
    )
    assert plain.returncode == 0, plain.stderr
    assert poisoned.returncode == 0, poisoned.stderr
    assert plain.stdout.strip() == poisoned.stdout.strip()
    assert "ALLOW" in plain.stdout


def test_authreg_no_active_authorization_path_imports_rust() -> None:
    code = (
        "import sys\n"
        "from mtmf_core import authorization, Authorizer, PermissionEvaluator\n"
        f"sys.exit(1 if {NATIVE_MODULE!r} in sys.modules else 0)\n"
    )
    result = _run_python(code)
    assert result.returncode == 0, result.stderr
