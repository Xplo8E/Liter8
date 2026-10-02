#!/usr/bin/env python3
"""Measure the pre-boot guards a `DeviceWorkflowProfile` needs.

The four guard values live in the encrypted root filesystem, and the only
other code that opens it, `rootfs.py`, sits behind `fw prepare-rootfs`, which
refuses without a profile. That is circular for a board being added, so this
reads the same values straight from an extracted IPSW and prints a profile to
paste. It measures and reports; it never writes to the firmware tree.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from liter8_workflow import WorkflowError
from rootfs import (
    decrypt,
    executable,
    mountpoint_for_image,
    sha256_file,
)

SETUP_APP = "Applications/Setup.app/Setup"
LAUNCHD = "sbin/launchd"
LAUNCHD_CACHE = "System/Library/xpc/launchd.plist"


def boards(manifest: dict) -> list[dict]:
    """Every distinct board an erase install of this IPSW can target.

    A dual-device IPSW lists one build identity per board and per restore
    behaviour, so the same board appears more than once.
    """
    seen: dict[tuple, dict] = {}
    for identity in manifest.get("BuildIdentities", []):
        info = identity.get("Info", {})
        if info.get("RestoreBehavior") != "Erase":
            continue
        key = (info.get("DeviceClass"), identity.get("ApChipID"), identity.get("ApBoardID"))
        seen.setdefault(key, {
            "deviceClass": info.get("DeviceClass"),
            "chipID": identity.get("ApChipID"),
            "boardID": identity.get("ApBoardID"),
            "os": identity.get("Manifest", {}).get("OS", {}).get("Info", {}).get("Path"),
        })
    return list(seen.values())


def product_type_for(manifest: dict, device_class: str) -> str:
    """Pair a board with its product type.

    `SupportedProductTypes` covers the whole archive, so on a dual-device IPSW
    it cannot say which board is which. `Ap,ProductType` is per build identity
    and does.
    """
    for identity in manifest.get("BuildIdentities", []):
        if identity.get("Info", {}).get("DeviceClass") != device_class:
            continue
        product = identity.get("Ap,ProductType")
        if product:
            return str(product)
    raise WorkflowError(f"BuildManifest has no Ap,ProductType for {device_class}")


def setup_controller_count(setup_binary: Path) -> int:
    """Count class-owned `controllerNeedsToRun` the same way the patcher does."""
    patcher = Path(__file__).resolve().parent.parent / "device" / "patch_setup.py"
    if not patcher.is_file():
        raise WorkflowError(f"patch_setup.py is missing: {patcher}")
    sys.path.insert(0, str(patcher.parent))
    import importlib.util

    spec = importlib.util.spec_from_file_location("patch_setup", patcher)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return len(module.discover_targets(setup_binary.read_bytes()))


def measure(mount: Path) -> dict[str, object]:
    launchd = mount / LAUNCHD
    cache = mount / LAUNCHD_CACHE
    setup = mount / SETUP_APP
    for path in (launchd, cache, setup):
        if not path.is_file():
            raise WorkflowError(f"mounted root filesystem has no {path.relative_to(mount)}")
    document = plistlib.loads(cache.read_bytes())
    return {
        "launchdSHA256": sha256_file(launchd),
        "launchdCacheSHA256": sha256_file(cache),
        "launchdCacheDaemonCount": len(document["LaunchDaemons"]),
        "setupControllerMethodCount": setup_controller_count(setup),
    }


def emit(manifest: dict, extracted: Path, guards: dict[str, object]) -> None:
    """Print one Swift profile per board, ready to paste into the registry."""
    version = manifest.get("ProductVersion")
    build = manifest.get("ProductBuildVersion")
    print("\nAdd to DeviceWorkflowRegistry.profiles:\n")
    for board in boards(manifest):
        device_class = board["deviceClass"]
        product = product_type_for(manifest, device_class)
        print(f"""        DeviceWorkflowProfile(
            id: "{product.lower()}-{device_class}-{build}",
            productVersion: "{version}",
            build: "{build}",
            productType: "{product}",
            deviceClass: "{device_class}",
            chipID: {board['chipID']},
            boardID: {board['boardID']},
            extractedDirectoryName: "{extracted.name}",
            validationState: .experimental,
            launchdSHA256: "{guards['launchdSHA256']}",
            launchdCacheSHA256: "{guards['launchdCacheSHA256']}",
            launchdCacheDaemonCount: {guards['launchdCacheDaemonCount']},
            setupControllerMethodCount: {guards['setupControllerMethodCount']},
            bootPlan: DeviceBootPlan(
                normalIBSSAdditionalPlans: [],
                restoreIBSSAdditionalPlans: []
            )
        ),""")
    print("\nvalidationState stays .experimental until a device run says otherwise.")
    print("bootPlan is empty: set it from the board's own display behaviour.")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: measure_guards.py <extracted-firmware-directory>", file=sys.stderr)
        return 2
    extracted = Path(argv[1]).resolve()
    manifest_path = extracted / "BuildManifest.plist"
    if not manifest_path.is_file():
        raise WorkflowError(f"no BuildManifest.plist in {extracted}")
    manifest = plistlib.loads(manifest_path.read_bytes())

    found = boards(manifest)
    if not found:
        raise WorkflowError("BuildManifest has no erase build identity")
    # One IPSW ships one OS component even when it serves several boards, so
    # the guards are measured once and apply to every board it lists.
    sources = {board["os"] for board in found if board["os"]}
    if len(sources) != 1:
        raise WorkflowError(f"expected one OS component, found {sorted(sources)}")
    source = extracted / sources.pop()
    if not source.is_file():
        raise WorkflowError(f"BuildManifest OS component is missing: {source}")

    print(f"[*] {manifest.get('ProductVersion')} ({manifest.get('ProductBuildVersion')}), "
          f"boards: {', '.join(sorted(b['deviceClass'] for b in found))}")

    hdiutil = executable("hdiutil", "/usr/bin/hdiutil")
    with tempfile.TemporaryDirectory(prefix="liter8-guards-", dir=extracted.parent) as scratch:
        image = Path(scratch) / "rootfs.dmg"
        decrypt(source, image)
        print(f"[*] attaching {image.name} read-only", flush=True)
        subprocess.run(
            [hdiutil, "attach", "-readonly", "-nobrowse", "-plist", str(image)],
            check=True, capture_output=True,
        )
        mount: Path | None = None
        try:
            located = mountpoint_for_image(hdiutil, image)
            if located is None:
                raise WorkflowError(f"could not find where {image} mounted")
            _, mount = located
            guards = measure(mount)
        finally:
            # Detach by mountpoint. `hdiutil detach` takes a mountpoint or a
            # device node, never the image path, and a failure here matters:
            # the temporary directory is about to delete the backing file, so
            # a still-attached volume becomes one nothing can clean up.
            if mount is not None:
                detached = subprocess.run(
                    [hdiutil, "detach", str(mount)], capture_output=True, text=True
                )
                if detached.returncode != 0:
                    print(f"[!] could not detach {mount}: {detached.stderr.strip()}",
                          file=sys.stderr)
                    print(f"[!] recover with: hdiutil detach '{mount}'", file=sys.stderr)
    emit(manifest, extracted, guards)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except WorkflowError as error:
        print(f"[!] {error}", file=sys.stderr)
        sys.exit(1)
