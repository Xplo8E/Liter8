#!/usr/bin/env python3
"""Send a Liter8-generated normal or SSHRD boot chain to the device."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard, run


# The order and pauses come from the beta-4 sequence that was reliable on the
# iPhone 11. Artifact names are Liter8's stable interface; source IPSW names
# remain selected from BuildManifest by the preceding get-boot/get-rd action.
FIRMWARE_SEQUENCE = [
    ("RestoreLogo.img4", "setpicture 0x1", 0),
    ("ANE.img4", "firmware", 0),
    ("AOP.img4", "firmware", 0),
    ("AVE.img4", "firmware", 1),
    ("SPTM.img4", "firmware", 3),
    ("TXM.img4", "firmware", 0),
    ("GFX.img4", "firmware", 0),
    ("ISP.img4", "firmware", 1),
    ("PMP.img4", "firmware", 0),
    ("RestoreTrustCache.img4", "firmware", 0),
    ("SIO.img4", "firmware", 0),
    ("WCH.img4", "firmware", 0),
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_executable(value: str | None, *, name: str, path_fallback: bool) -> str:
    """Resolve an explicitly selected transport without hiding substitutions."""
    if value:
        path = Path(value).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise WorkflowError(f"{name} is not executable: {path}")
    if path_fallback:
        found = shutil.which(name)
        if found:
            return found
    raise WorkflowError(f"{name} is required")


def validate_boot_set(context: Context, expected_mode: str) -> Path:
    """Reject stale, incomplete, wrong-profile, or wrong-mode Ramdisk output."""
    root = context.work / "Ramdisk"
    manifest_path = root / "liter8-boot.json"
    if not manifest_path.is_file():
        raise WorkflowError(
            f"Ramdisk has no Liter8 boot manifest; rerun fw get-{('rd' if expected_mode == 'restore' else 'boot')}"
        )
    document = json.loads(manifest_path.read_text())
    if document.get("schema") != 1:
        raise WorkflowError("unsupported Ramdisk boot manifest")
    if document.get("profileID") != context.profile_id:
        raise WorkflowError("Ramdisk artifacts belong to another firmware profile")
    if document.get("mode") != expected_mode:
        raise WorkflowError(
            f"Ramdisk contains {document.get('mode')} artifacts, expected {expected_mode}"
        )

    required = ["iBSS.raw", "iBEC.img4", "DeviceTree.img4", "SEP.img4", "Kernelcache.img4"]
    required += [name for name, _, _ in FIRMWARE_SEQUENCE]
    if expected_mode == "restore":
        required.append("RestoreRamdisk.img4")
    records = document.get("artifacts", {})
    for name in required:
        path = root / name
        record = records.get(name)
        if not path.is_file() or not isinstance(record, dict):
            raise WorkflowError(f"boot artifact is missing: {name}")
        if path.stat().st_size != record.get("bytes") or sha256_file(path) != record.get("sha256"):
            raise WorkflowError(f"boot artifact changed after generation: {name}")
    return root


def send(irecovery: str, root: Path, name: str, command: str) -> None:
    """Upload one artifact, then require iBoot to accept its load command."""
    print(f"  {name:<24} uploading", flush=True)
    run([irecovery, "-f", root / name])
    run([irecovery, "-c", command])
    print(f"  {name:<24} accepted ({command})", flush=True)


def boot() -> None:
    context = Context.load()
    action = os.environ.get("LITER8_FW_ACTION")
    mode = {"boot": "normal", "boot-rd": "restore"}.get(action)
    if mode is None:
        raise WorkflowError(f"unexpected device boot action: {action}")
    root = validate_boot_set(context, mode)

    # The project-specific irecovery source is not selected yet. Requiring an
    # explicit path prevents accidental use of the official system binary.
    irecovery = require_executable(
        os.environ.get("LITER8_IRECOVERY"), name="irecovery", path_fallback=False
    )
    usbliter8ctl = require_executable(None, name="usbliter8ctl", path_fallback=True)

    print("[*] stage 1: raw iBSS through the RP2350 transport", flush=True)
    result = subprocess.run([usbliter8ctl, "boot", str(root / "iBSS.raw")])
    if result.returncode:
        # usbliter8ctl sends CUSTOM_BOOT and then DFU_ABORT. Once CUSTOM_BOOT
        # succeeds, the USB handle disappears and that final abort can fail.
        # iBEC upload below is the definitive transition check.
        print("  usbliter8ctl returned after the expected USB transition", flush=True)
    time.sleep(3)

    print("[*] stage 2: iBEC", flush=True)
    send(irecovery, root, "iBEC.img4", "go")
    time.sleep(2)

    print("[*] stage 3: display and firmware", flush=True)
    run([irecovery, "-c", "bgcolor 0 191 255"])
    for name, command, pause_after in FIRMWARE_SEQUENCE:
        send(irecovery, root, name, command)
        if pause_after:
            time.sleep(pause_after)

    if mode == "restore":
        print("[*] stage 4: restore ramdisk", flush=True)
        send(irecovery, root, "RestoreRamdisk.img4", "ramdisk")

    print("[*] stage 5: DeviceTree, SEP and kernel", flush=True)
    time.sleep(2)
    send(irecovery, root, "DeviceTree.img4", "devicetree")
    send(irecovery, root, "SEP.img4", "rsepfirmware")
    print(f"  {'Kernelcache.img4':<24} uploading", flush=True)
    run([irecovery, "-f", root / "Kernelcache.img4"])

    # bootx normally tears down the recovery USB connection before irecovery
    # receives a reply. Report its status, but do not misclassify disconnect as
    # a failed boot.
    print("[*] stage 6: bootx", flush=True)
    result = subprocess.run([irecovery, "-c", "bootx"])
    if result.returncode:
        print("  recovery USB disconnected during bootx (expected)", flush=True)
    print(f"[+] {mode} boot chain sent", flush=True)


if __name__ == "__main__":
    main_guard(boot)
