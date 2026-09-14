"""Build normal-boot artifacts from semantic BuildManifest components."""

from __future__ import annotations

import os
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from liter8_workflow import Context, WorkflowError, run


# Output names are the stable interface consumed by the device boot command.
# Source filenames are intentionally absent; BuildManifest supplies them.
PASSTHROUGH_IMG4 = [
    ("RestoreLogo", "RestoreLogo.img4", "rlgo"),
    ("ANE", "ANE.img4", "anef"),
    ("AOP", "AOP.img4", "aopf"),
    ("AVE", "AVE.img4", "avef"),
    ("Ap,SecurePageTableMonitor", "SPTM.img4", "sptm"),
    ("GFX", "GFX.img4", "gfxf"),
    ("ISP", "ISP.img4", "ispf"),
    ("PMP", "PMP.img4", "pmpf"),
    ("RestoreTrustCache", "RestoreTrustCache.img4", "rtsc"),
    ("SIO", "SIO.img4", "siof"),
    ("WCHFirmwareUpdater", "WCH.img4", "wchf"),
    ("SEP", "SEP.img4", "rsep"),
]


def ticket_from_environment() -> Path:
    value = os.environ.get("LITER8_AP_TICKET")
    if not value:
        raise WorkflowError("get-boot requires --ticket <apticket.im4m>")
    ticket = Path(value).resolve()
    if not ticket.is_file():
        raise WorkflowError(f"AP ticket does not exist: {ticket}")
    return ticket


def create_img4(
    context: Context,
    im4p: Path,
    ticket: Path,
    output: Path,
    *,
    fourcc: str | None = None,
) -> None:
    print(f"[*] signing IMG4: {output.name}", flush=True)
    command: list[object] = [context.liter8, "img4", "create", im4p, ticket, output]
    if fourcc:
        command += ["--fourcc", fourcc]
    run(command)


def publish_directory(staging: Path, destination: Path) -> None:
    """Replace the previous output only after the new set is complete."""
    # The destination's parent is already the selected Liter8 work directory.
    # Keep rollback state beside it instead of creating work-dir/.liter8 again.
    previous = destination.parent / ".Ramdisk.previous"
    if previous.exists():
        shutil.rmtree(previous)
    if destination.exists():
        os.replace(destination, previous)
    try:
        os.replace(staging, destination)
    except Exception:
        if previous.exists() and not destination.exists():
            os.replace(previous, destination)
        raise
    if previous.exists():
        shutil.rmtree(previous)


def write_boot_manifest(context: Context, staging: Path, mode: str) -> None:
    """Bind a device command to the exact artifact family it is about to send."""
    artifacts = {}
    for path in sorted(staging.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        artifacts[path.name] = {
            "bytes": path.stat().st_size,
            "sha256": digest.hexdigest(),
        }
    (staging / "liter8-boot.json").write_text(json.dumps({
        "schema": 1,
        "profileID": context.profile_id,
        "mode": mode,
        "artifacts": artifacts,
    }, indent=2, sort_keys=True) + "\n")


def build_normal_boot() -> None:
    context = Context.load()
    ticket = ticket_from_environment()

    # Build beside .liter8 first. A failed resolver or signing step leaves the
    # operator's previous Ramdisk directory intact.
    with tempfile.TemporaryDirectory(prefix="boot-staging-", dir=context.state) as directory:
        staging = Path(directory)

        print("[*] normal boot: patching iBSS", flush=True)
        ibss = staging / "iBSS.raw"
        context.extract_im4p(context.component("iBSS"), ibss)
        context.apply("iboot", "ibss-normal", ibss, record_name="boot-ibss-normal")
        for plan in context.normal_ibss_additional_plans:
            context.apply("iboot", plan, ibss, record_name=f"boot-{plan}")

        # iBEC needs a patched IM4P before the device ticket is attached.
        print("[*] normal boot: patching and signing iBEC", flush=True)
        ibec_raw = staging / ".iBEC.raw"
        ibec_im4p = staging / ".iBEC.im4p"
        ibec_source = context.component("iBEC")
        context.extract_im4p(ibec_source, ibec_raw)
        context.apply("iboot", "ibss-normal", ibec_raw, record_name="boot-ibec")
        context.repack_im4p(ibec_source, ibec_raw, ibec_im4p)
        create_img4(context, ibec_im4p, ticket, staging / "iBEC.img4")

        # LLB and iBoot remain raw because the downstream USB boot sequence
        # sends these payloads in that representation.
        print("[*] normal boot: extracting LLB and iBoot", flush=True)
        context.extract_im4p(context.component("LLB"), staging / "LLB.raw")
        context.extract_im4p(context.component("iBoot"), staging / "iBoot.raw")

        print("[*] normal boot: signing firmware payloads", flush=True)
        for component, output_name, fourcc in PASSTHROUGH_IMG4:
            create_img4(
                context,
                context.component(component),
                ticket,
                staging / output_name,
                fourcc=fourcc,
            )

        print("[*] normal boot: patching TXM", flush=True)
        txm = staging / ".TXM.im4p"
        shutil.copy2(context.component("Ap,TrustedExecutionMonitor"), txm)
        context.apply("txm", "boot", txm, record_name="boot-txm")
        create_img4(context, txm, ticket, staging / "TXM.img4")

        print("[*] normal boot: patching DeviceTree", flush=True)
        devicetree = staging / ".DeviceTree.im4p"
        shutil.copy2(context.component("DeviceTree"), devicetree)
        context.apply(
            "devicetree", "normal", devicetree,
            record_name="boot-devicetree", capture_records=False,
        )
        create_img4(
            context, devicetree, ticket, staging / "DeviceTree.img4", fourcc="rdtr"
        )

        print("[*] normal boot: patching kernelcache", flush=True)
        kernel = staging / ".Kernelcache.im4p"
        shutil.copy2(context.component("KernelCache"), kernel)
        context.apply("kernel", "boot-public", kernel, record_name="boot-kernel")
        create_img4(
            context, kernel, ticket, staging / "Kernelcache.img4", fourcc="rkrn"
        )

        # Dot-prefixed intermediates are not part of the public boot artifact set.
        for intermediate in staging.glob(".*"):
            intermediate.unlink()
        write_boot_manifest(context, staging, "normal")
        publish_directory(staging, context.work / "Ramdisk")

    print("[+] normal boot artifacts are ready in Ramdisk", flush=True)


def build_restore_boot() -> None:
    """Build the ticketed SSH restore-ramdisk artifact set."""
    context = Context.load()
    ticket = ticket_from_environment()

    with tempfile.TemporaryDirectory(prefix="rd-staging-", dir=context.state) as directory:
        staging = Path(directory)

        print("[*] SSHRD: patching iBSS", flush=True)
        ibss = staging / "iBSS.raw"
        context.extract_im4p(context.component("iBSS"), ibss)
        context.apply("iboot", "ibss-ramdisk", ibss, record_name="rd-ibss")
        # The selected profile may add a board-specific display handoff (n104
        # currently does). Extra plans are intentionally applied only to iBSS;
        # iBEC must retain its own display initialization behavior.
        for plan in context.restore_ibss_additional_plans:
            context.apply("iboot", plan, ibss, record_name=f"rd-{plan}")

        print("[*] SSHRD: patching and signing iBEC", flush=True)
        ibec_raw = staging / ".iBEC.raw"
        ibec_im4p = staging / ".iBEC.im4p"
        ibec_source = context.component("iBEC")
        context.extract_im4p(ibec_source, ibec_raw)
        context.apply("iboot", "ibss-ramdisk", ibec_raw, record_name="rd-ibec")
        context.repack_im4p(ibec_source, ibec_raw, ibec_im4p)
        create_img4(context, ibec_im4p, ticket, staging / "iBEC.img4")

        print("[*] SSHRD: signing firmware payloads", flush=True)
        for component, output_name, fourcc in PASSTHROUGH_IMG4:
            create_img4(
                context,
                context.component(component),
                ticket,
                staging / output_name,
                fourcc=fourcc,
            )

        print("[*] SSHRD: patching TXM", flush=True)
        txm = staging / ".TXM.im4p"
        shutil.copy2(context.component("Ap,RestoreTrustedExecutionMonitor"), txm)
        context.apply("txm", "restore", txm, record_name="rd-txm")
        create_img4(context, txm, ticket, staging / "TXM.img4")

        print("[*] SSHRD: patching DeviceTree", flush=True)
        devicetree = staging / ".DeviceTree.im4p"
        shutil.copy2(context.component("RestoreDeviceTree"), devicetree)
        context.apply(
            "devicetree", "restore", devicetree,
            record_name="rd-devicetree", capture_records=False,
        )
        create_img4(
            context, devicetree, ticket, staging / "DeviceTree.img4", fourcc="rdtr"
        )

        print("[*] SSHRD: patching kernelcache", flush=True)
        kernel = staging / ".Kernelcache.im4p"
        shutil.copy2(context.component("RestoreKernelCache"), kernel)
        context.apply("kernel", "restore", kernel, record_name="rd-kernel")
        create_img4(
            context, kernel, ticket, staging / "Kernelcache.img4", fourcc="rkrn"
        )

        print("[*] SSHRD: building and signing restore ramdisk", flush=True)
        from sshrd import build_sshrd
        build_sshrd(context, ticket, staging / "RestoreRamdisk.img4")

        for intermediate in staging.glob(".*"):
            intermediate.unlink()
        write_boot_manifest(context, staging, "restore")
        publish_directory(staging, context.work / "Ramdisk")

    print("[+] SSH restore boot artifacts are ready in Ramdisk", flush=True)
