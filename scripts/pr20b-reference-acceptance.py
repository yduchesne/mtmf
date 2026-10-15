#!/usr/bin/env python3
"""PR 20B isolated deployed conformance orchestrator (follow-up 01).

This is the prescribed launcher for PR 20B. It **reuses** the canonical PR 20A
topology creator (`scripts/pr20a-reference-acceptance.py`) rather than
duplicating it and adds only:

- the PR 20B extra fixture documents through the existing fixture loader;
- the approved metadata-read Action/Role/assignments through the privileged
  ``scripts/pr20b_metadata_fixture.py`` helper;
- a dedicated, CA-signed internal TLS fault fronting component
  (``compose.pr20b-fault-acceptance.yaml`` + ``scripts/pr20b-fault-proxy.py``)
  on a distinct hostname, applied on every ``up()``;
- execution of the PR 20B black-box conformance suite in addition to the PR 20A
  L01-L05 regression;
- cold / repeat / recreate cycles and a default-stack inventory check.

Subcommands::

    preflight    read-only ownership/dependency/certificate/mode validation
    up           PR 20A up + PR 20B fixtures + fault overlay
    test         PR 20A L01-L05 + PR 20B conformance
    down         stop the acceptance project (overlay first)
    recreate     destructive acceptance-only recreate
    acceptance   cold -> PR20A+PR20B -> repeat -> recreate -> PR20A+PR20B

No secret is printed or placed on a command line.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

#: The PR 20B extra fixture documents. Deterministic and non-secret.
PR20B_BATCH_DOCUMENT_ID = "d0c0a1e0-0004-4000-8000-000000000004"
PR20B_BATCH_TITLE = "Batch Reference Document"
PR20B_BATCH_BODY = "reference-app-batch-body-v1"

PR20B_LIVE_TEST = "tests/e2e/reference_app/test_pr20b_live_conformance.py"

#: Fault overlay constants.
FAULT_OVERLAY = "compose.pr20b-fault-acceptance.yaml"
FAULT_HOSTNAME = "mtmf-fault.mtmf.test"
FAULT_PROXY_CONTAINER = "mtmf-pr20a-acceptance_pr20b-fault-proxy_1"
FAULT_BASE_URL = f"https://{FAULT_HOSTNAME}:29501"
FAULT_ROOT = Path("/tmp/mtmf-pr20b-acceptance-faults")
FAULT_CONTROL_DIR = FAULT_ROOT / "control"
FAULT_EVIDENCE_DIR = FAULT_ROOT / "evidence"
FAULT_CONTROL_FILE = FAULT_CONTROL_DIR / "mode"
FAULT_EVIDENCE_FILE = FAULT_EVIDENCE_DIR / "evidence.jsonl"
KNOWN_FAULT_MODES = frozenset(
    {
        "none",
        "refuse",
        "delay",
        "http_502",
        "http_503",
        "non_json",
        "malformed_json",
        "mismatch",
    }
)

#: The genuine Keycloak fixture user with no server-side subject mapping (S08).
PR20B_UNMAPPED_USERNAME = "mtmf-user-carol"


def _load_base() -> Any:
    """Load the canonical PR 20A orchestrator as the topology creator."""
    spec = importlib.util.spec_from_file_location(
        "pr20b_pr20a_acceptance", _SCRIPTS / "pr20a-reference-acceptance.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("the PR 20A acceptance orchestrator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr20b_pr20a_acceptance"] = module
    spec.loader.exec_module(module)
    return module


base = _load_base()


class Pr20bAcceptanceError(RuntimeError):
    """A bounded PR 20B acceptance failure; never contains a secret."""


def _fault_leaf_cert() -> Path:
    return base.ACCEPTANCE_CA_DIR / "mtmf-fault.crt"


def _fault_leaf_key() -> Path:
    return base.ACCEPTANCE_CA_DIR / "mtmf-fault.key"


def _overlay_compose(*args: str, env: dict[str, str] | None = None, check: bool = True) -> Any:
    command = [
        "podman-compose",
        "-p",
        base.ACCEPTANCE_PROJECT,
        "-f",
        base.COMPOSE_FILE,
        "-f",
        FAULT_OVERLAY,
        *args,
    ]
    return base._run(command, env=env, check=check)


def _leaf_san_is_approved(cert: Path) -> bool:
    result = base._run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
        check=False,
    )
    return f"DNS:{FAULT_HOSTNAME}" in result.stdout


def _prepare_fault_leaf() -> None:
    """Generate/validate the dedicated PR 20B fault leaf (distinct SAN)."""
    cert = _fault_leaf_cert()
    key = _fault_leaf_key()
    if cert.is_file() and key.is_file():
        if not _leaf_san_is_approved(cert):
            raise Pr20bAcceptanceError(
                "the existing fault leaf does not have the approved SAN; refusing to reuse it"
            )
        return
    with tempfile.TemporaryDirectory(prefix="mtmf-pr20b-leaf-") as work:
        csr = Path(work) / "fault.csr"
        ext = Path(work) / "fault-ext.cnf"
        ext.write_text(
            "\n".join(
                [
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    f"subjectAltName=DNS:{FAULT_HOSTNAME}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        base._run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={FAULT_HOSTNAME}",
            ]
        )
        base._run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(base.ACCEPTANCE_CA_DIR / "dev-ca.crt"),
                "-CAkey",
                str(base.ACCEPTANCE_CA_DIR / "dev-ca.key"),
                "-CAcreateserial",
                "-out",
                str(cert),
                "-days",
                "825",
                "-sha256",
                "-extfile",
                str(ext),
            ]
        )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)


def preflight() -> int:
    """Delegate to PR 20A preflight and validate PR 20B-specific configuration."""
    base.preflight()
    if _fault_leaf_cert().is_file() and not _leaf_san_is_approved(_fault_leaf_cert()):
        raise Pr20bAcceptanceError("the existing fault leaf SAN is not the approved value")
    if FAULT_CONTROL_FILE.is_file():
        mode = FAULT_CONTROL_FILE.read_text(encoding="utf-8").strip()
        if mode not in KNOWN_FAULT_MODES:
            raise Pr20bAcceptanceError(f"the fault control file names an unknown mode {mode!r}")
    print("PR 20B acceptance preflight passed", flush=True)
    return 0


def _reset_fault() -> None:
    """Reset the fault mode to clean pass-through and start fresh evidence."""
    FAULT_CONTROL_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    FAULT_EVIDENCE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    FAULT_CONTROL_FILE.write_text("none", encoding="utf-8")
    if FAULT_EVIDENCE_FILE.exists():
        FAULT_EVIDENCE_FILE.unlink()


def _seed_batch_document(env: dict[str, str]) -> None:
    mapping_path = base.ACCEPTANCE_FIXTURE_DIR / "reference-app-fixture.json"
    if not mapping_path.is_file():
        raise Pr20bAcceptanceError("the reference-app fixture mapping was not generated")
    tenant_id = str(json.loads(mapping_path.read_text(encoding="utf-8"))["tenant_id"])
    manifest = {
        "documents": [
            {
                "document_id": PR20B_BATCH_DOCUMENT_ID,
                "tenant_id": tenant_id,
                "title": PR20B_BATCH_TITLE,
                "body": PR20B_BATCH_BODY,
            }
        ]
    }
    manifest_path = base.ACCEPTANCE_FIXTURE_DIR / "pr20b-documents.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    container = base._reference_app_container()
    result = subprocess.run(
        [
            "podman",
            "exec",
            container,
            "python",
            "-m",
            "mtmf_reference_app.fixture_loader",
            "--manifest",
            "/run/fixtures/pr20b-documents.json",
            "--sqlite",
            "/data/reference-app.db",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = base._redact((result.stderr or result.stdout).strip())
        raise Pr20bAcceptanceError(f"the PR 20B fixture seed failed: {detail[-200:]}")


def _provision_metadata(env: dict[str, str]) -> None:
    """Provision the approved metadata Action/Role/assignments (idempotent)."""
    run_env = dict(env)
    run_env["MTMF_PR20B_ACCEPTANCE_DB"] = "mtmf"
    # The metadata helper connects as the migrator using the component
    # variables; remove the URL form so the configuration source is unambiguous.
    run_env.pop("MTMF_MIGRATOR_DATABASE_URL", None)
    run_env.pop("MTMF_RUNTIME_DATABASE_URL", None)
    result = subprocess.run(
        [sys.executable, str(_SCRIPTS / "pr20b_metadata_fixture.py")],
        cwd=REPO_ROOT,
        env=run_env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = base._redact((result.stderr or result.stdout).strip())
        raise Pr20bAcceptanceError(f"the metadata fixture provisioning failed: {detail[-300:]}")


def _verify_reference_targets_fault() -> None:
    container = base._reference_app_container()
    payload = json.loads(base._run(["podman", "inspect", container]).stdout)[0]
    environment = (payload.get("Config") or {}).get("Env") or []
    expected = f"MTMF_REFERENCE_APP_MTMF_BASE_URL={FAULT_BASE_URL}"
    if expected not in environment:
        raise Pr20bAcceptanceError("the reference app is not targeting the fault proxy")
    resolved = base._run(
        ["podman", "exec", container, "getent", "hosts", FAULT_HOSTNAME], check=False
    )
    if FAULT_HOSTNAME not in resolved.stdout:
        raise Pr20bAcceptanceError("the fault hostname does not resolve inside the reference app")
    proxy = base._run(
        ["podman", "ps", "--filter", f"name={FAULT_PROXY_CONTAINER}", "--format", "{{.Names}}"],
        check=False,
    )
    if FAULT_PROXY_CONTAINER not in proxy.stdout:
        raise Pr20bAcceptanceError("the fault proxy container is not running")


def _apply_fault_overlay(env: dict[str, str]) -> None:
    _prepare_fault_leaf()
    _reset_fault()
    overlay_env = dict(env)
    overlay_env["MTMF_PR20B_CONTROL_DIR"] = str(FAULT_CONTROL_DIR)
    overlay_env["MTMF_PR20B_EVIDENCE_DIR"] = str(FAULT_EVIDENCE_DIR)
    _overlay_compose(
        "up",
        "-d",
        "--no-deps",
        "--force-recreate",
        "pr20b-fault-proxy",
        "reference-app",
        env=overlay_env,
    )
    base._wait_http(f"{base.ACCEPTANCE_REFERENCE_BASE}/health/ready", timeout=120.0)
    _verify_reference_targets_fault()


def up() -> int:
    """Bring up the canonical PR 20A stack, PR 20B fixtures, and fault overlay."""
    base.up()
    env = base._build_env(base._stage_secrets(), base._read_dotenv())
    env["MTMF_PR20B_ACCEPTANCE_DB"] = "mtmf"
    _seed_batch_document(env)
    _provision_metadata(env)
    _apply_fault_overlay(env)
    print("PR 20B fixture documents, metadata policy, and fault overlay ready", flush=True)
    return 0


def _pr20b_test_env() -> dict[str, str]:
    env = base._test_env()
    env["MTMF_PR20B_LIVE"] = "1"
    env["MTMF_PR20B_ACCEPTANCE_DB"] = "mtmf"
    env["MTMF_PR20B_BATCH_DOCUMENT_ID"] = PR20B_BATCH_DOCUMENT_ID
    env["MTMF_PR20B_BATCH_TITLE"] = PR20B_BATCH_TITLE
    env["MTMF_PR20B_BATCH_BODY"] = PR20B_BATCH_BODY
    env["MTMF_PR20B_FAULT_CONTAINER"] = FAULT_PROXY_CONTAINER
    env["MTMF_PR20B_CONTROL_FILE"] = str(FAULT_CONTROL_FILE)
    env["MTMF_PR20B_EVIDENCE_FILE"] = str(FAULT_EVIDENCE_FILE)
    env["MTMF_PR20B_UNMAPPED_USERNAME"] = PR20B_UNMAPPED_USERNAME
    return env


def _run_pr20b_suite() -> None:
    base._assert_owned()
    base._verify_deployed_reference_app()
    env = _pr20b_test_env()
    result = subprocess.run(
        [
            "uv",
            "run",
            "--no-sync",
            "pytest",
            PR20B_LIVE_TEST,
            "-q",
            "--no-cov",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = base._redact((result.stdout or "") + (result.stderr or ""))
    print(output.rstrip()[-8000:], flush=True)
    if result.returncode != 0:
        raise Pr20bAcceptanceError("the PR 20B live conformance suite failed")
    if re.search(r"\bskipped|\bxfailed|\bxpassed|\bfailed|\berror", output):
        raise Pr20bAcceptanceError("the PR 20B suite reported skips, xfails or failures")


def test() -> int:
    """Run the PR 20A regression and the PR 20B conformance suite."""
    base.test()
    _run_pr20b_suite()
    print("PR 20A L01-L05 and PR 20B conformance passed", flush=True)
    return 0


def down() -> int:
    env = base._build_env(base._stage_secrets(), base._read_dotenv())
    overlay_env = dict(env)
    overlay_env["MTMF_PR20B_CONTROL_DIR"] = str(FAULT_CONTROL_DIR)
    overlay_env["MTMF_PR20B_EVIDENCE_DIR"] = str(FAULT_EVIDENCE_DIR)
    _overlay_compose("down", env=overlay_env, check=False)
    return int(base.down())


def recreate() -> int:
    env = base._build_env(base._stage_secrets(), base._read_dotenv())
    overlay_env = dict(env)
    overlay_env["MTMF_PR20B_CONTROL_DIR"] = str(FAULT_CONTROL_DIR)
    overlay_env["MTMF_PR20B_EVIDENCE_DIR"] = str(FAULT_EVIDENCE_DIR)
    _overlay_compose("down", "-v", env=overlay_env, check=False)
    base.recreate()
    shutil.rmtree(FAULT_ROOT, ignore_errors=True)
    return 0


def acceptance() -> int:
    """Run cold / repeat / recreate cycles and verify the default stack."""
    before = base._default_inventory()
    recreate()
    up()
    test()
    print("COLD-01 PASS", flush=True)
    up()
    test()
    print("REPEAT-01 PASS", flush=True)
    recreate()
    up()
    test()
    print("RECREATE-01 PASS", flush=True)
    after = base._default_inventory()
    if before != after:
        raise Pr20bAcceptanceError("default stack inventory changed during acceptance")
    print("default stack inventory unchanged", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 20B isolated conformance orchestrator")
    parser.add_argument(
        "command",
        choices=("preflight", "up", "test", "down", "recreate", "acceptance"),
    )
    args = parser.parse_args(argv)
    try:
        return {
            "preflight": preflight,
            "up": up,
            "test": test,
            "down": down,
            "recreate": recreate,
            "acceptance": acceptance,
        }[args.command]()
    except base.AcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1
    except Pr20bAcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
