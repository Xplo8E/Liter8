#!/usr/bin/env python3
"""Build the restore CFW using BuildManifest-selected component paths."""

import sys
from pathlib import Path

from liter8_workflow import Context, WorkflowError, main_guard, run


def build() -> None:
    context = Context.load()
    context.prepare_cfw()
    ramdisk = context.work / "Ramdisk"
    ramdisk.mkdir(exist_ok=True)

    # iBSS is consumed as a raw payload by usbliter8ctl, rather than from CFW.
    print("[*] CFW component 1/6: restore iBSS", flush=True)
    ibss_container = context.backup(context.component("iBSS", in_cfw=True))
    ibss_raw = ramdisk / "iBSS.raw"
    context.extract_im4p(ibss_container, ibss_raw)
    context.apply("iboot", "ibss-restore", ibss_raw, record_name="ibss-restore")

    # The other boot-chain components remain IM4Ps. Liter8 preserves their
    # fourcc, description, and PAYP metadata while replacing the payload.
    print("[*] CFW component 2/6: restore iBEC", flush=True)
    ibec = context.component("iBEC", in_cfw=True)
    context.reset_to_pristine(ibec)
    context.apply("iboot", "ibss-restore", ibec, record_name="ibec-restore")

    print("[*] CFW component 3/6: restore DeviceTree", flush=True)
    devicetree = context.component("RestoreDeviceTree", in_cfw=True)
    context.reset_to_pristine(devicetree)
    context.apply(
        "devicetree", "restore", devicetree,
        record_name="devicetree-restore", capture_records=False,
    )

    print("[*] CFW component 4/6: restore TXM", flush=True)
    txm = context.component("Ap,RestoreTrustedExecutionMonitor", in_cfw=True)
    context.reset_to_pristine(txm)
    context.apply("txm", "restore", txm, record_name="txm-restore")

    print("[*] CFW component 5/6: restore kernelcache", flush=True)
    kernel = context.component("RestoreKernelCache", in_cfw=True)
    context.reset_to_pristine(kernel)
    context.apply("kernel", "restore", kernel, record_name="kernel-restore")

    # RestoreRamDisk contains Mach-O files and needs a writable DMG mount plus
    # ldid. Keep that host-specific operation in one generic helper.
    print("[*] CFW component 6/6: restore ramdisk", flush=True)
    restore_ramdisk = context.component("RestoreRamDisk", in_cfw=True)
    context.backup(restore_ramdisk)
    helper = context.resources / "scripts" / "ramdisk_patch.py"
    if not helper.is_file():
        raise WorkflowError(f"missing workflow helper: {helper}")
    run([Path(sys.executable), helper, restore_ramdisk])

    verifier = context.resources / "scripts" / "verify_cfw.py"
    if not verifier.is_file():
        raise WorkflowError(f"missing workflow verifier: {verifier}")
    print("[*] verifying completed CFW artifacts", flush=True)
    run([Path(sys.executable), verifier])
    print("[+] CFW patching and verification complete", flush=True)


if __name__ == "__main__":
    main_guard(build)
