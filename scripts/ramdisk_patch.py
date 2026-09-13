#!/usr/bin/env python3
"""Patch and re-sign userland binaries inside the restore ramdisk."""

import os
import re
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard, run


# These paths and identifiers are stable semantic interfaces inside Apple's
# restore ramdisk. Firmware component filenames still come from BuildManifest.
TARGETS = [
    ("usr/local/bin/restored_external", "restored-fdr", "com.apple.restored_external"),
    ("usr/sbin/asr", "asr", "com.apple.asr"),
]


def attach(dmg: Path) -> tuple[str, Path]:
    result = run(["/usr/bin/hdiutil", "attach", "-nobrowse", dmg], capture=True)
    device = next((line.split()[0] for line in result.stdout.splitlines()
                   if line.startswith("/dev/")), None)
    mount = next((re.search(r"(/Volumes/\S.*)$", line).group(1)
                  for line in result.stdout.splitlines() if "/Volumes/" in line), None)
    if not device or not mount:
        raise WorkflowError("could not parse hdiutil attach output")
    return device, Path(mount.strip())


def signing_identifier(path: Path) -> str | None:
    result = subprocess.run(
        ["/usr/bin/codesign", "-dv", str(path)], text=True, capture_output=True
    )
    match = re.search(r"^Identifier=(.*)$", result.stderr, re.MULTILINE)
    return match.group(1) if match else None


def entitlement_size(ldid: str, path: Path) -> int:
    """Use byte length as a loss detector without logging entitlement data."""
    result = subprocess.run([ldid, "-e", str(path)], capture_output=True)
    if result.returncode:
        raise WorkflowError(f"could not read entitlements from {path.name}")
    return len(result.stdout)


def detach(device: str) -> None:
    result = subprocess.run(["/usr/bin/hdiutil", "detach", device])
    if result.returncode:
        result = subprocess.run(["/usr/bin/hdiutil", "detach", "-force", device])
    if result.returncode:
        raise WorkflowError(f"could not detach restore ramdisk device {device}")


def patch_ramdisk() -> None:
    context = Context.load()
    if len(sys.argv) != 2:
        raise WorkflowError("usage: ramdisk_patch.py <restore-ramdisk.im4p>")
    container = Path(sys.argv[1]).resolve()
    pristine = context.backup(container)
    raw = context.state / "restore-ramdisk.dmg"
    context.extract_im4p(pristine, raw)

    # Liter8 ships the reviewed public-workflow binary under its original name.
    ldid = shutil.which("ldid") or shutil.which("ldid_macosx_arm64")
    if not ldid:
        raise WorkflowError("ldid is required; install it or place it in Liter8's tools directory")

    device, mount = attach(raw)
    try:
        for relative, plan, identifier in TARGETS:
            installed = mount / relative
            if not installed.is_file():
                raise WorkflowError(f"restore ramdisk is missing {relative}")
            before = installed.stat()
            before_entitlements = entitlement_size(ldid, installed)
            with tempfile.TemporaryDirectory() as directory:
                staged = Path(directory) / installed.name
                shutil.copy2(installed, staged)
                context.apply("userland", plan, staged, record_name=f"ramdisk-{plan}")
                run([ldid, f"-I{identifier}", "-S", "-M", "-Cadhoc", staged])
                if signing_identifier(staged) != identifier:
                    raise WorkflowError(f"ldid did not preserve identifier {identifier}")
                if entitlement_size(ldid, staged) != before_entitlements:
                    raise WorkflowError(f"ldid changed entitlements for {relative}")

                # Replace bytes through the original inode. A rename on the
                # mounted image would change its uid/gid to the host user.
                with installed.open("r+b") as output:
                    output.write(staged.read_bytes())
                    output.truncate()
            after = installed.stat()
            if (after.st_ino, after.st_uid, after.st_gid, after.st_mode) != (
                before.st_ino, before.st_uid, before.st_gid, before.st_mode
            ):
                raise WorkflowError(f"metadata changed while patching {relative}")
    finally:
        detach(device)

    with tempfile.NamedTemporaryFile(
        prefix=f".{container.name}.liter8-", dir=container.parent, delete=False
    ) as temporary:
        output = Path(temporary.name)
    try:
        context.repack_im4p(pristine, raw, output)
        os.replace(output, container)
    finally:
        output.unlink(missing_ok=True)
    context.record_hash(container, "restore-ramdisk")


if __name__ == "__main__":
    main_guard(patch_ramdisk)
