"""Create the SSH restore ramdisk used by `liter8 fw get-rd`."""

from __future__ import annotations

import os
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from liter8_workflow import Context, WorkflowError, run


REVIEWED_PAYLOAD_SHA256 = "ddfa230acd2789c7e61ddb0d2ec3df9a6c741f2ddcab58fc1a826d278be1d74d"


def sha256_file(path: Path) -> str:
    """Hash a large payload without reading the whole archive into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hdiutil(arguments: list[object], *, capture: bool = False):
    return run(["/usr/bin/hdiutil", *arguments], capture=capture)


def attach(image: Path, *, readonly: bool) -> tuple[str, Path]:
    arguments: list[object] = ["attach", "-nobrowse", "-owners", "off"]
    if readonly:
        arguments.append("-readonly")
    arguments.append(image)
    result = hdiutil(arguments, capture=True)
    device = next((line.split()[0] for line in result.stdout.splitlines()
                   if line.startswith("/dev/")), None)
    mount = next((re.search(r"(/Volumes/\S.*)$", line).group(1)
                  for line in result.stdout.splitlines() if "/Volumes/" in line), None)
    if not device or not mount:
        raise WorkflowError("could not parse hdiutil attach output")
    return device, Path(mount.strip())


def detach(device: str) -> None:
    result = subprocess.run(["/usr/bin/hdiutil", "detach", device])
    if result.returncode:
        result = subprocess.run(["/usr/bin/hdiutil", "detach", "-force", device])
    if result.returncode:
        raise WorkflowError(f"could not detach {device}")


def privileged(arguments: list[object]) -> None:
    """Run a filesystem operation as root, prompting in the operator's terminal."""
    command = [str(argument) for argument in arguments]
    if os.geteuid() == 0:
        run(command)
        return

    # Do not preflight with `sudo -n`: that turns an ordinary authentication
    # request into a confusing failure. Liter8 is attached to the operator's
    # terminal, so normal sudo can show the password or Touch ID prompt here.
    # macOS caches the successful authorization, therefore the remaining
    # privileged image operations normally continue without prompting again.
    run(["/usr/bin/sudo", *command])


def build_sshrd(context: Context, ticket: Path, output: Path) -> None:
    payload = Path(os.environ.get(
        "LITER8_SSHRD_PAYLOAD",
        context.resources / "payloads" / "ssh.tar.gz",
    )).resolve()
    entitlements = context.resources / "payloads" / "sftp_server_ents.plist"
    # The public workflow names its reviewed arm64 binary explicitly. Prefer a
    # conventional ldid when supplied by the operator, then accept that bundled
    # filename from Liter8's tools directory.
    ldid = shutil.which("ldid") or shutil.which("ldid_macosx_arm64")
    gtar = shutil.which("gtar")
    for required in (payload, entitlements):
        if not required.is_file():
            raise WorkflowError(f"missing SSHRD resource: {required}")
    payload_digest = sha256_file(payload)
    if payload_digest != REVIEWED_PAYLOAD_SHA256:
        raise WorkflowError(
            f"SSHRD payload SHA-256 is {payload_digest}, expected {REVIEWED_PAYLOAD_SHA256}"
        )
    if not ldid:
        raise WorkflowError("ldid is required for SSHRD construction")
    if not gtar:
        raise WorkflowError("GNU tar is required for SSHRD construction (brew install gnu-tar)")

    source = context.component("RestoreRamDisk")
    with tempfile.TemporaryDirectory(prefix="sshrd-", dir=context.state) as directory:
        scratch = Path(directory)
        original_dmg = scratch / "restore.dmg"
        expanded_dmg = scratch / "sshrd.dmg"
        expanded_im4p = scratch / "sshrd.im4p"
        context.extract_im4p(source, original_dmg)

        source_device, source_mount = attach(original_dmg, readonly=True)
        try:
            # Recreate the image with enough space for the SSH payload instead
            # of resizing Apple's original in place.
            privileged([
                "/usr/bin/hdiutil", "create", "-size", "254m",
                "-imagekey", "diskimage-class=CRawDiskImage",
                "-format", "UDRW", "-fs", "APFS", "-layout", "NONE",
                "-srcfolder", source_mount, "-copyuid", "root", expanded_dmg,
            ])
        finally:
            detach(source_device)

        device, mount = attach(expanded_dmg, readonly=False)
        try:
            privileged([gtar, "-x", "--no-overwrite-dir", "-f", payload, "-C", mount])
            # These large/debug helpers were carried by the historical payload
            # but are unused by the SSH restore environment.
            for relative in (
                "usr/bin/img4tool", "usr/bin/img4",
                "usr/sbin/dietappleh13camerad", "usr/sbin/dietappleh16camerad",
                "usr/local/bin/wget", "usr/local/bin/procexp",
            ):
                candidate = mount / relative
                if candidate.exists():
                    privileged(["/bin/rm", "-f", candidate])
            privileged([
                ldid, f"-S{entitlements}", "-M", "-Cadhoc",
                mount / "usr/libexec/sftp-server",
            ])
        finally:
            detach(device)

        privileged(["/usr/bin/hdiutil", "resize", "-sectors", "min", expanded_dmg])
        context.repack_im4p(source, expanded_dmg, expanded_im4p)
        from boot_artifacts import create_img4
        create_img4(context, expanded_im4p, ticket, output)
