#!/usr/bin/env python3
"""Disable watchdogd's automatic crash loop in launchd's service cache.

The Liter8 normal boot intentionally uses ``wdt=-1``. On 24A446, watchdogd
still starts from its IOKit LaunchEvent, fails to open IOWatchdog, exits via an
intentional trap, and is restarted because unsuccessful exits are kept alive.
launchd's private PanicOnConsecutiveCrash policy then turns that daemon loop
into a kernel panic.

This patch removes only those three policy fields from the existing job:

* LaunchEvents
* KeepAlive
* _PanicOnCrash

MachServices and every other job field remain present. An explicit Mach-service
request can therefore still launch watchdogd, but one failure will not be
automatically restarted or escalated into a system panic.

Usage:
    ./patch_watchdogd_job.py <launchd.plist>            # inspect only
    ./patch_watchdogd_job.py <launchd.plist> --apply
    ./patch_watchdogd_job.py <launchd.plist> --remove
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import plistlib
import shutil
import sys
from pathlib import Path


CACHE_KEY = "/System/Library/LaunchDaemons/com.apple.watchdogd.plist"
LABEL = "com.apple.watchdogd"

EXPECTED_IDENTITY = {
    "Label": LABEL,
    "ProgramArguments": ["/usr/libexec/watchdogd"],
}

EXPECTED_MACH_SERVICES = {
    "com.apple.unblock": True,
    "com.apple.watchdogd.optin.registration": True,
}

REMOVED_POLICY = {
    "_PanicOnCrash": {
        "PanicOnConsecutiveCrash": True,
    },
    "KeepAlive": {
        "SuccessfulExit": False,
    },
    "LaunchEvents": {
        "com.apple.iokit.matching": {
            "com.apple.driver.watchdog": {
                "IOMatchLaunchStream": True,
                "IOProviderClass": "IOWatchdog",
            },
        },
    },
}

LITER8_ADDED_JOBS = {
    "/System/Library/LaunchDaemons/com.dropbear.plist",
    "/System/Library/LaunchDaemons/com.jbboot.plist",
    "/System/Library/LaunchDaemons/com.liter8.ddi-services.plist",
}


class JobShapeError(ValueError):
    """The cache does not contain the reviewed watchdogd job shape."""


def load(path: Path) -> dict:
    with path.open("rb") as stream:
        return plistlib.load(stream)


def watchdogd_job(document: dict) -> dict:
    try:
        job = document["LaunchDaemons"][CACHE_KEY]
    except (KeyError, TypeError) as error:
        raise JobShapeError(f"cache is missing {CACHE_KEY}") from error
    if not isinstance(job, dict):
        raise JobShapeError("watchdogd cache entry is not a dictionary")
    return job


def validate_identity(job: dict) -> None:
    for key, expected in EXPECTED_IDENTITY.items():
        if job.get(key) != expected:
            raise JobShapeError(
                f"watchdogd {key} is {job.get(key)!r}, expected {expected!r}"
            )

    services = job.get("MachServices")
    if not isinstance(services, dict):
        raise JobShapeError("watchdogd MachServices is missing or malformed")
    for name, expected in EXPECTED_MACH_SERVICES.items():
        if services.get(name) != expected:
            raise JobShapeError(
                f"watchdogd MachServices[{name!r}] is {services.get(name)!r}, "
                f"expected {expected!r}"
            )


def policy_state(job: dict) -> str:
    """Return stock, mitigated, or mixed for the three reviewed fields."""
    matches = [job.get(key) == expected for key, expected in REMOVED_POLICY.items()]
    absent = [key not in job for key in REMOVED_POLICY]
    if all(matches):
        return "stock"
    if all(absent):
        return "mitigated"
    return "mixed"


def watchdogd_job_is_mitigated(document: dict) -> bool:
    try:
        job = watchdogd_job(document)
        validate_identity(job)
    except JobShapeError:
        return False
    return policy_state(job) == "mitigated"


def apply_mitigation(document: dict) -> bool:
    job = watchdogd_job(document)
    validate_identity(job)
    state = policy_state(job)
    if state == "mitigated":
        return False
    if state != "stock":
        raise JobShapeError(
            "watchdogd trigger/restart/panic policy is neither reviewed stock nor mitigated"
        )
    for key in REMOVED_POLICY:
        del job[key]
    return True


def remove_mitigation(document: dict) -> bool:
    job = watchdogd_job(document)
    validate_identity(job)
    state = policy_state(job)
    if state == "stock":
        return False
    if state != "mitigated":
        raise JobShapeError(
            "watchdogd trigger/restart/panic policy is neither reviewed stock nor mitigated"
        )
    job.update(copy.deepcopy(REMOVED_POLICY))
    return True


def validate_daemon_count(document: dict, expected_pristine: int | None) -> None:
    if expected_pristine is None:
        return
    launch_daemons = document.get("LaunchDaemons")
    if not isinstance(launch_daemons, dict):
        raise JobShapeError("cache has no usable LaunchDaemons dictionary")
    additions = sum(key in launch_daemons for key in LITER8_ADDED_JOBS)
    expected = expected_pristine + additions
    if len(launch_daemons) != expected:
        raise JobShapeError(
            f"cache has {len(launch_daemons)} daemons, expected {expected} "
            f"({expected_pristine} pristine plus {additions} Liter8 jobs)"
        )


def write_verified(path: Path, document: dict) -> Path:
    source_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    backup = path.with_name(f"{path.name}.watchdogd.{source_digest[:16]}.bak")
    if not backup.exists():
        shutil.copy2(path, backup)

    temporary = path.with_name(f"{path.name}.watchdogd.{os.getpid()}.tmp")
    if temporary.exists():
        raise JobShapeError(f"temporary output already exists: {temporary}")
    try:
        with temporary.open("xb") as stream:
            plistlib.dump(document, stream, fmt=plistlib.FMT_BINARY)
        if load(temporary) != document:
            raise JobShapeError("written cache did not round-trip exactly")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return backup


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("cache", help="path to launchd.plist (the service cache)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true", help="apply the mitigation")
    action.add_argument("--remove", action="store_true", help="restore the reviewed policy")
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
        validate_daemon_count(document, arguments.expected_pristine_daemons)
        before_job = copy.deepcopy(watchdogd_job(document))
        validate_identity(before_job)
        before_state = policy_state(before_job)
        if before_state == "mixed":
            raise JobShapeError(
                "watchdogd trigger/restart/panic policy is neither reviewed stock nor mitigated"
            )
    except (OSError, plistlib.InvalidFileException, JobShapeError) as error:
        sys.exit(f"[!] {error}")

    print(f"[*] {path}")
    print(f"    LaunchDaemons  {len(document['LaunchDaemons'])}")
    print(f"    watchdogd      {before_state}")
    print(f"    MachServices   {sorted(before_job['MachServices'])}")

    if not (arguments.apply or arguments.remove):
        print("[dry-run] pass --apply or --remove to change anything")
        return 0

    try:
        changed = (
            apply_mitigation(document)
            if arguments.apply
            else remove_mitigation(document)
        )
        if not changed:
            print("[=] requested state is already present")
            return 0

        after_job = watchdogd_job(document)
        if after_job.get("MachServices") != before_job.get("MachServices"):
            raise JobShapeError("watchdogd MachServices changed unexpectedly")
        backup = write_verified(path, document)
        written = load(path)
        if written != document:
            raise JobShapeError("on-disk cache differs after verified write")
        expected_state = "mitigated" if arguments.apply else "stock"
        if policy_state(watchdogd_job(written)) != expected_state:
            raise JobShapeError(f"watchdogd did not reach {expected_state} state")
    except (OSError, plistlib.InvalidFileException, JobShapeError) as error:
        sys.exit(f"[!] {error}")

    print(f"[+] watchdogd {expected_state}")
    print(f"[+] source backup: {backup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
