#!/usr/bin/env python3
"""Decrypt, mount, validate, and unmount the selected IPSW System image."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard, run


AEA_MAGIC = b"AEA1"
ROOTFS_DIRECTORY = "rootfs"
IMAGE_NAME = "OS.dmg"
STATE_NAME = "rootfs.json"


def sha256_file(path: Path) -> str:
    """Hash launchd without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def executable(name: str, preferred: str | None = None) -> str:
    """Resolve one required host tool while keeping the chosen path visible."""
    if preferred:
        candidate = Path(preferred)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    if not found:
        raise WorkflowError(f"{name} is required for root filesystem preparation")
    return found


def is_aea_encrypted(path: Path) -> bool:
    """Recognize Apple's AEA1 envelope before invoking the decryptor."""
    with path.open("rb") as stream:
        return stream.read(4) == AEA_MAGIC


def mounted_images(hdiutil: str) -> list[dict]:
    """Return hdiutil's structured mount inventory, never parsed console text."""
    result = run([hdiutil, "info", "-plist"], capture=True)
    document = plistlib.loads(result.stdout.encode())
    images = document.get("images", [])
    return images if isinstance(images, list) else []


def mountpoint_for_image(hdiutil: str, image: Path) -> tuple[dict, Path] | None:
    """Find where Disk Arbitration mounted one exact decrypted image.

    Modern macOS can reject an unprivileged custom APFS mountpoint even though
    it is happy to attach the same image below /Volumes.  The image path is the
    stable identity; the automatically chosen mountpoint is intentionally not.
    """
    wanted = image.resolve()
    for record in mounted_images(hdiutil):
        raw_image_path = record.get("image-path")
        if not raw_image_path or Path(str(raw_image_path)).resolve() != wanted:
            continue
        mountpoints = [
            Path(str(entity["mount-point"]))
            for entity in record.get("system-entities", [])
            if entity.get("mount-point")
        ]
        if len(mountpoints) != 1:
            raise WorkflowError(
                f"expected one mounted filesystem for {wanted}, found {len(mountpoints)}"
            )
        return record, mountpoints[0]
    return None


def write_state(root: Path, context: Context, image: Path, mountpoint: Path,
                details: dict[str, str]) -> None:
    """Publish validated mount metadata atomically for the provisioning stage."""
    state = {
        "schema": 1,
        "profileID": context.profile_id,
        "sourceComponent": context.components["OS"],
        "image": str(image.resolve()),
        "mountpoint": str(mountpoint.resolve()),
        **details,
    }
    with tempfile.NamedTemporaryFile(
        mode="w", prefix=".rootfs-state-", dir=root, delete=False
    ) as output:
        temporary_state = Path(output.name)
        output.write(json.dumps(state, indent=2, sort_keys=True) + "\n")
    try:
        os.replace(temporary_state, root / STATE_NAME)
    finally:
        temporary_state.unlink(missing_ok=True)


def validate_rootfs(context: Context, mountpoint: Path) -> dict[str, str]:
    """Bind the mounted image to the selected build and boot-critical inputs."""
    version_path = mountpoint / "System/Library/CoreServices/SystemVersion.plist"
    launchd = mountpoint / "sbin/launchd"
    launchd_cache = mountpoint / "System/Library/xpc/launchd.plist"
    if not version_path.is_file() or not launchd.is_file() or not launchd_cache.is_file():
        raise WorkflowError(f"mounted image is not an iOS System root: {mountpoint}")

    document = plistlib.loads(version_path.read_bytes())
    version = document.get("ProductVersion")
    build = document.get("ProductBuildVersion")
    if version != context.product_version or build != context.build:
        raise WorkflowError(
            f"mounted root filesystem is iOS {version} ({build}), expected "
            f"{context.product_version} ({context.build})"
        )

    expected_launchd = os.environ.get("LITER8_LAUNCHD_SHA")
    if not expected_launchd:
        raise WorkflowError("firmware profile has no reviewed launchd identity")
    actual_launchd = sha256_file(launchd)
    if actual_launchd != expected_launchd:
        raise WorkflowError(
            f"mounted /sbin/launchd SHA-256 is {actual_launchd}, expected {expected_launchd}"
        )

    expected_cache = os.environ.get("LITER8_LAUNCHD_CACHE_SHA")
    expected_daemons_text = os.environ.get("LITER8_LAUNCHD_CACHE_DAEMONS")
    if not expected_cache or not expected_daemons_text:
        raise WorkflowError("firmware profile has no reviewed launchd cache identity")
    try:
        expected_daemons = int(expected_daemons_text)
    except ValueError as error:
        raise WorkflowError("firmware profile has an invalid launchd daemon count") from error

    actual_cache = sha256_file(launchd_cache)
    if actual_cache != expected_cache:
        raise WorkflowError(
            f"mounted launchd.plist SHA-256 is {actual_cache}, expected {expected_cache}"
        )
    try:
        cache_document = plistlib.loads(launchd_cache.read_bytes())
        launch_daemons = cache_document["LaunchDaemons"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise WorkflowError("mounted launchd.plist is not a usable service cache") from error
    if not isinstance(launch_daemons, dict) or len(launch_daemons) != expected_daemons:
        actual_daemons = len(launch_daemons) if isinstance(launch_daemons, dict) else "invalid"
        raise WorkflowError(
            f"mounted launchd.plist has {actual_daemons} daemons, expected {expected_daemons}"
        )
    return {
        "productVersion": str(version),
        "build": str(build),
        "launchdSHA256": actual_launchd,
        "launchdCacheSHA256": actual_cache,
        "launchdCacheDaemonCount": str(expected_daemons),
    }


def resolve_aea_key(ipsw: str, source: Path) -> str:
    """Ask ipsw for the public firmware key without printing it to the log."""
    result = run([ipsw, "fw", "aea", "--no-color", "--key", source], capture=True)
    key = result.stdout.strip()
    if not key.startswith("base64:") or len(key) <= len("base64:"):
        raise WorkflowError("ipsw did not return a usable AEA key for the selected OS image")
    return key


def readable_size(size: int) -> str:
    """Format a growing decrypt output without pretending it is exact progress."""
    value = float(size)
    for suffix in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or suffix == "GiB":
            return f"{value:.1f} {suffix}"
        value /= 1024
    raise AssertionError("unreachable")


def decrypt(context: Context, source: Path, image: Path) -> None:
    """Create the cached plaintext DMG atomically beside the work directory."""
    ipsw = executable("ipsw", "/opt/homebrew/bin/ipsw")
    aea = executable("aea", "/usr/bin/aea")
    if not is_aea_encrypted(source):
        raise WorkflowError(f"BuildManifest OS component is not AEA1 encrypted: {source}")

    # A truncated 8 GB cache is useless and easy to mistake for a valid rerun.
    # Reserve the encrypted image size plus headroom before starting the long job.
    free = shutil.disk_usage(image.parent).free
    required = source.stat().st_size + 512 * 1024 * 1024
    if free < required:
        raise WorkflowError(
            f"rootfs decryption needs at least {required} free bytes; only {free} available"
        )

    partial = image.with_suffix(".dmg.partial")
    partial.unlink(missing_ok=True)
    print("[*] resolving AEA key for BuildManifest component OS", flush=True)
    key = resolve_aea_key(ipsw, source)
    print(f"[*] decrypting {source.name} -> {image}", flush=True)
    key_file: Path | None = None
    try:
        # Keep the key out of argv and error messages. Although firmware AEA
        # keys are public, there is no reason to spill one into a process list.
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=".aea-key-", dir=image.parent, delete=False
        ) as output:
            key_file = Path(output.name)
            output.write(key)
        key_file.chmod(0o600)

        process = subprocess.Popen([
            aea, "decrypt", "-i", source, "-o", partial, "-key", key_file,
        ])
        started = time.monotonic()
        next_report = started + 10
        try:
            while process.poll() is None:
                time.sleep(1)
                now = time.monotonic()
                if now >= next_report:
                    written = partial.stat().st_size if partial.exists() else 0
                    elapsed = int(now - started)
                    print(
                        f"[*] AEA decrypt running: {readable_size(written)} output, "
                        f"{elapsed}s elapsed",
                        flush=True,
                    )
                    next_report = now + 10
        except BaseException:
            process.terminate()
            process.wait()
            raise
        if process.returncode:
            raise WorkflowError(f"aea decrypt exited with status {process.returncode}")
        if not partial.is_file() or partial.stat().st_size == 0:
            raise WorkflowError("AEA decryptor did not produce a root filesystem image")
        if is_aea_encrypted(partial):
            raise WorkflowError("AEA output is still encrypted")
        os.replace(partial, image)
    finally:
        if key_file is not None:
            key_file.unlink(missing_ok=True)
        partial.unlink(missing_ok=True)


def prepare(context: Context) -> None:
    root = context.state / ROOTFS_DIRECTORY
    image = root / IMAGE_NAME
    root.mkdir(exist_ok=True)
    hdiutil = executable("hdiutil", "/usr/bin/hdiutil")

    mounted = mountpoint_for_image(hdiutil, image)
    if mounted is not None:
        _, mountpoint = mounted
        details = validate_rootfs(context, mountpoint)
        write_state(root, context, image, mountpoint, details)
        print(f"[+] root filesystem already mounted and verified: {mountpoint}", flush=True)
        return

    if image.exists():
        if not image.is_file() or image.stat().st_size == 0 or is_aea_encrypted(image):
            raise WorkflowError(f"cached rootfs image is incomplete or encrypted: {image}")
        print(f"[*] reusing cached decrypted root filesystem: {image}", flush=True)
    else:
        decrypt(context, context.component("OS"), image)

    # imageinfo rejects truncated or non-DMG output before macOS tries to mount it.
    run([hdiutil, "imageinfo", image], capture=True)
    print("[*] mounting decrypted root filesystem read-only with Disk Arbitration", flush=True)
    # Do not force -mountpoint here.  A System-role APFS image mounts normally
    # below /Volumes, but macOS denies a user-owned custom mountpoint.  Let the
    # OS choose the location and discover it from hdiutil's structured state.
    run([
        hdiutil, "attach", "-readonly", "-nobrowse", "-owners", "off", image,
    ], capture=True)
    try:
        mounted = mountpoint_for_image(hdiutil, image)
        if mounted is None:
            raise WorkflowError("hdiutil attached the root filesystem without mounting it")
        _, mountpoint = mounted
        details = validate_rootfs(context, mountpoint)
    except Exception:
        # A mount that fails identity validation must not remain available for
        # a later provisioning command to consume accidentally.
        try:
            mounted = mountpoint_for_image(hdiutil, image)
            if mounted is not None:
                run([hdiutil, "detach", mounted[1]])
        except WorkflowError as detach_error:
            print(f"[!] could not detach rejected rootfs mount: {detach_error}", flush=True)
        raise

    write_state(root, context, image, mountpoint, details)
    print(f"[+] root filesystem mounted and verified: {mountpoint}", flush=True)


def unmount(context: Context) -> None:
    root = context.state / ROOTFS_DIRECTORY
    image = root / IMAGE_NAME
    hdiutil = executable("hdiutil", "/usr/bin/hdiutil")
    mounted = mountpoint_for_image(hdiutil, image)
    if mounted is None:
        print(f"[+] root filesystem is already unmounted: {image}", flush=True)
        return
    _, mountpoint = mounted
    print(f"[*] unmounting root filesystem: {mountpoint}", flush=True)
    run([hdiutil, "detach", mountpoint])
    print(f"[+] decrypted rootfs cache retained: {image}", flush=True)


def rootfs() -> None:
    context = Context.load()
    action = os.environ.get("LITER8_FW_ACTION")
    if action == "prepare-rootfs":
        prepare(context)
    elif action == "unmount-rootfs":
        unmount(context)
    else:
        raise WorkflowError(f"unexpected rootfs action: {action}")


if __name__ == "__main__":
    main_guard(rootfs)
