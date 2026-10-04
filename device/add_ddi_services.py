#!/usr/bin/env python3
"""Add automatic DeveloperDiskImage service registration to launchd's cache.

CoreDevice can mount a personalized DeveloperDiskImage at ``/System/Developer``
without registering the launch daemons carried by that image.  The host then
has a working RemoteXPC tunnel, but ``ddiServicesAvailable`` remains false until
the directory is bootstrapped explicitly.

This cached system job keeps a small System-volume watcher alive.  The watcher
handles both orderings: an image already mounted when it starts and the normal
later CoreDevice mount.  It then executes the same fixed system-domain
bootstrap validated manually on 24A446.  A watcher is deliberate: exact-device
testing showed that ``StartOnMount`` did not relaunch this generated-cache job.

Usage:
    ./add_ddi_services.py <launchd.plist>            # inspect only
    ./add_ddi_services.py <launchd.plist> --apply
    ./add_ddi_services.py <launchd.plist> --remove
"""

from __future__ import annotations

import argparse
import plistlib
import shutil
import sys
from pathlib import Path


CACHE_KEY = "/System/Library/LaunchDaemons/com.liter8.ddi-services.plist"
LABEL = "com.liter8.ddi-services"
DDI_WATCHER = "/usr/local/bin/ddiwatch"

DDI_SERVICES_JOB = {
    "Label": LABEL,
    "ProgramArguments": [DDI_WATCHER],
    "RunAtLoad": True,
    # The watcher normally remains alive.  Restart crashes and other abnormal
    # failures, but not the clean exit used by its single-instance lock.
    "KeepAlive": {"SuccessfulExit": False},
    "POSIXSpawnType": "Interactive",
    "EnablePressuredExit": False,
    "EnableTransactions": False,
    "ThrottleInterval": 5,
    "StandardOutPath": "/var/mobile/ddiwatch.log",
    "StandardErrorPath": "/var/mobile/ddiwatch.log",
}

KNOWN_LITER8_JOBS = {
    "/System/Library/LaunchDaemons/com.dropbear.plist",
    "/System/Library/LaunchDaemons/com.jbboot.plist",
    CACHE_KEY,
}


class JobShapeError(ValueError):
    """The launchd cache does not have the expected guarded shape."""


def load(path: Path) -> dict:
    with path.open("rb") as stream:
        return plistlib.load(stream)


def validate_document(document: dict, expected_pristine: int | None) -> dict:
    for key in ("LaunchDaemons", "AppExtensions", "SystemLibraryTreeState", "VersionNumber"):
        if key not in document:
            raise JobShapeError(f"cache is missing top-level key {key!r}")
    launch_daemons = document["LaunchDaemons"]
    if not isinstance(launch_daemons, dict):
        raise JobShapeError("cache has no usable LaunchDaemons dictionary")
    if expected_pristine is not None:
        additions = sum(key in launch_daemons for key in KNOWN_LITER8_JOBS)
        expected = expected_pristine + additions
        if len(launch_daemons) != expected:
            raise JobShapeError(
                f"cache has {len(launch_daemons)} daemons, expected {expected} "
                f"({expected_pristine} pristine plus {additions} Liter8 jobs)"
            )
    return launch_daemons


def apply_job(document: dict) -> bool:
    launch_daemons = document["LaunchDaemons"]
    current = launch_daemons.get(CACHE_KEY)
    if current == DDI_SERVICES_JOB:
        return False
    if current is not None:
        raise JobShapeError(f"{CACHE_KEY} exists with an unexpected job definition")
    launch_daemons[CACHE_KEY] = DDI_SERVICES_JOB.copy()
    launch_daemons[CACHE_KEY]["ProgramArguments"] = DDI_SERVICES_JOB["ProgramArguments"].copy()
    return True


def remove_job(document: dict) -> bool:
    launch_daemons = document["LaunchDaemons"]
    current = launch_daemons.get(CACHE_KEY)
    if current is None:
        return False
    if current != DDI_SERVICES_JOB:
        raise JobShapeError(f"{CACHE_KEY} exists with an unexpected job definition")
    del launch_daemons[CACHE_KEY]
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("cache", help="path to launchd.plist (the service cache)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true", help="add the registration job")
    action.add_argument("--remove", action="store_true", help="remove the registration job")
    parser.add_argument(
        "--expected-pristine-daemons",
        type=int,
        help="profile-owned daemon count before Liter8 adds its jobs",
    )
    arguments = parser.parse_args()

    path = Path(arguments.cache)
    if not path.is_file():
        sys.exit(f"[!] not a file: {path}")

    try:
        document = load(path)
        launch_daemons = validate_document(document, arguments.expected_pristine_daemons)
    except (OSError, plistlib.InvalidFileException, JobShapeError) as error:
        sys.exit(f"[!] {error}")

    current = launch_daemons.get(CACHE_KEY)
    state = "present" if current == DDI_SERVICES_JOB else "absent"
    if current is not None and current != DDI_SERVICES_JOB:
        state = "MISMATCH"
    print(f"[*] {path}")
    print(f"    LaunchDaemons  {len(launch_daemons)}")
    print(f"    {LABEL}  {state}")

    if not (arguments.apply or arguments.remove):
        print("[dry-run] pass --apply or --remove to change anything")
        return 0

    try:
        changed = apply_job(document) if arguments.apply else remove_job(document)
        if not changed:
            print("[=] requested state is already present")
            return 0
        backup = path.with_suffix(path.suffix + ".bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        with path.open("wb") as stream:
            plistlib.dump(document, stream, fmt=plistlib.FMT_BINARY)
        written = load(path)
        expected = DDI_SERVICES_JOB if arguments.apply else None
        if written["LaunchDaemons"].get(CACHE_KEY) != expected:
            raise JobShapeError("written cache did not reach the requested state")
    except (OSError, plistlib.InvalidFileException, JobShapeError) as error:
        sys.exit(f"[!] {error}")

    print(f"[+] {LABEL} {'added' if arguments.apply else 'removed'}")
    print(f"[+] source backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
