#!/usr/bin/env python3
"""Run the proven bootstrap/JB provisioning scripts from Liter8 resources."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard, run


BOOTSTRAP_SHA256 = "8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb"
SSHRD_PAYLOAD_SHA256 = "ddfa230acd2789c7e61ddb0d2ec3df9a6c741f2ddcab58fc1a826d278be1d74d"

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_runtime(context: Context) -> Path:
    """Create a persistent mutable copy while keeping installed resources clean."""
    source = context.resources / "device"
    if not source.is_dir():
        raise WorkflowError(f"device workflow resources are missing: {source}")
    bootstrap = source / "bootstrap_1900.tar.zst"
    if not bootstrap.is_file() or sha256_file(bootstrap) != BOOTSTRAP_SHA256:
        raise WorkflowError("bundled bootstrap archive failed its SHA-256 check")

    root = context.state / "device-runtime"
    workflow = root / "workflow"
    workflow.mkdir(parents=True, exist_ok=True)

    # Refresh source-controlled inputs on every invocation, while leaving
    # payload/, boot/work and other generated state intact for resumability.
    shutil.copytree(source, workflow, dirs_exist_ok=True)

    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    for source_tool in (context.resources / "tools").iterdir():
        if not source_tool.is_file() or source_tool.name == "README.md":
            continue
        destination = tools / source_tool.name
        destination.unlink(missing_ok=True)
        destination.symlink_to(source_tool)

    # The old provisioning scripts expect this reviewed archive beside them.
    ssh_payload = context.resources / "payloads/ssh.tar.gz"
    if not ssh_payload.is_file() or sha256_file(ssh_payload) != SSHRD_PAYLOAD_SHA256:
        raise WorkflowError("bundled SSHRD payload failed its SHA-256 check")
    runtime_payload = workflow / "ssh.tar.gz"
    runtime_payload.unlink(missing_ok=True)
    runtime_payload.symlink_to(ssh_payload)

    # Homebrew exposes GNU timeout as gtimeout on macOS. Give the proven shell
    # script the name it expects without modifying the host installation.
    timeout_link = tools / "timeout"
    if timeout_link.is_symlink() and not timeout_link.exists():
        timeout_link.unlink()
    if not timeout_link.exists():
        timeout = shutil.which("timeout") or shutil.which("gtimeout")
        if timeout:
            timeout_link.symlink_to(Path(timeout).resolve())
    return workflow


def execute(script: Path, *, check_only: bool, environment: dict[str, str]) -> None:
    arguments: list[object] = [script]
    if check_only:
        arguments.append("--check")
    run(arguments, environment=environment)


def prepared_rootfs(context: Context, environment: dict[str, str]) -> Path:
    """Resolve a deliberate override or the exact mount verified by Liter8."""
    explicit_rootfs = environment.get("IPSW_ROOT")
    if explicit_rootfs:
        return Path(explicit_rootfs).resolve()

    state_path = context.state / "rootfs" / "rootfs.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError) as error:
        raise WorkflowError(
            "verified root filesystem state is missing; run fw prepare-rootfs"
        ) from error

    expected_image = (context.state / "rootfs" / "OS.dmg").resolve()
    recorded_image = Path(str(state.get("image", ""))).resolve()
    expected_identity = {
        "schema": 1,
        "profileID": context.profile_id,
        "productVersion": context.product_version,
        "build": context.build,
        "launchdSHA256": environment.get("LITER8_LAUNCHD_SHA"),
    }
    if any(state.get(key) != value for key, value in expected_identity.items()):
        raise WorkflowError("root filesystem state belongs to another firmware profile")
    if recorded_image != expected_image:
        raise WorkflowError("root filesystem state names an unexpected decrypted image")

    mountpoint = state.get("mountpoint")
    if not isinstance(mountpoint, str) or not mountpoint.startswith("/"):
        raise WorkflowError("root filesystem state has no valid mountpoint")
    return Path(mountpoint).resolve()


def provision() -> None:
    context = Context.load()
    action = os.environ.get("LITER8_FW_ACTION")
    if action not in {"bootstrap", "provision", "finalize", "setup-shell"}:
        raise WorkflowError(f"unexpected provisioning action: {action}")
    workflow = prepare_runtime(context)
    check_only = os.environ.get("LITER8_CHECK_ONLY") == "1"

    environment = dict(os.environ)
    environment["PATH"] = f"{workflow.parent / 'tools'}:{environment.get('PATH', '')}"

    if action == "bootstrap":
        execute(workflow / "install_bootstrap.sh", check_only=check_only, environment=environment)
        return

    if action == "setup-shell":
        execute(workflow / "setup_shell.sh", check_only=check_only, environment=environment)
        return

    if action == "finalize":
        execute(workflow / "finalize.sh", check_only=check_only, environment=environment)
        return

    # Swift owns firmware selection and exports this value from the exact
    # IPSW workflow profile. Python must never guess it from a filename.
    if not environment.get("LITER8_LAUNCHD_SHA"):
        raise WorkflowError("Liter8 did not provide the reviewed launchd identity")

    # --rootfs remains an explicit research override.  Normally prepare-rootfs
    # records the path selected by macOS Disk Arbitration; that /Volumes path
    # is dynamic and must not be reconstructed from the work directory.
    rootfs = prepared_rootfs(context, environment)
    environment["IPSW_ROOT"] = str(rootfs)

    if check_only:
        execute(workflow / "install_dropbear.sh", check_only=True, environment=environment)
        execute(workflow / "sshrd_provision.sh", check_only=True, environment=environment)
        return

    if not (rootfs / "sbin/launchd").is_file():
        raise WorkflowError(
            f"mounted root filesystem is missing at {rootfs}; "
            "run fw prepare-rootfs or pass --rootfs <directory>"
        )

    # Build/download reproducible payloads before entering the SSHRD mutation
    # phase. The script pins upstream versions and verifies complete hashes.
    execute(workflow / "fetch_payloads.sh", check_only=False, environment=environment)
    execute(workflow / "install_dropbear.sh", check_only=False, environment=environment)
    execute(workflow / "sshrd_provision.sh", check_only=False, environment=environment)


if __name__ == "__main__":
    main_guard(provision)
