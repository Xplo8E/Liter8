#!/usr/bin/env python3
"""Verify that the CFW still contains the artifacts produced by Liter8."""

import hashlib
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify() -> None:
    context = Context.load()
    targets = {
        "ibss-restore": context.work / "Ramdisk/iBSS.raw",
        "ibec-restore": context.component("iBEC", in_cfw=True),
        "devicetree-restore": context.component("RestoreDeviceTree", in_cfw=True),
        "txm-restore": context.component("Ap,RestoreTrustedExecutionMonitor", in_cfw=True),
        "kernel-restore": context.component("RestoreKernelCache", in_cfw=True),
        "restore-ramdisk": context.component("RestoreRamDisk", in_cfw=True),
    }

    failures: list[str] = []
    for name, artifact in targets.items():
        marker = context.state / "artifact-hashes" / f"{name}.sha256"
        if not artifact.is_file():
            failures.append(f"{name}: artifact is missing: {artifact}")
            continue
        if not marker.is_file():
            failures.append(f"{name}: build record is missing")
            continue
        expected = marker.read_text().strip()
        actual = sha256(artifact)
        if actual != expected:
            failures.append(f"{name}: SHA-256 changed ({actual}, expected {expected})")
            continue
        print(f"  PASS  {name:<24} {actual}")

    if failures:
        for failure in failures:
            print(f"  FAIL  {failure}")
        raise WorkflowError(f"CFW verification failed with {len(failures)} problem(s)")
    print("[+] every built CFW artifact matches its post-patch record")


if __name__ == "__main__":
    main_guard(verify)
