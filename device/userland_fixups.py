#!/usr/bin/env python3
"""Build and verify the post-restore userland fixes used during provisioning.

This helper deliberately contains no firmware offsets. Liter8's Swift resolvers
discover every instruction from the pristine binary pulled from the phone. The
Python code owns only the file-format chores around that operation: retaining
the original entitlements and code-signing identifier, then producing a stable
ad-hoc-signed artifact that the SSHRD workflow can deploy and read back.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import subprocess
from pathlib import Path


SCREEN_TIME_LABELS = (
    "com.apple.ScreenTimeAgent",
    "com.apple.ScreenTimeSettingsAgent",
    "com.apple.FamilyControlsAgent",
    "com.apple.familycircled",
    "com.apple.familynotificationd",
)


def run(arguments: list[object], *, capture: bool = False) -> subprocess.CompletedProcess[bytes]:
    """Run one tool without a shell so paths and signing arguments stay literal."""
    result = subprocess.run(
        [str(argument) for argument in arguments],
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip() if capture else ""
        suffix = f": {detail}" if detail else ""
        raise SystemExit(f"[!] command failed ({result.returncode}): {arguments[0]}{suffix}")
    return result


def signing_identifier(binary: Path) -> str:
    """Read Apple's existing identifier instead of guessing it from a filename."""
    result = run(["/usr/bin/codesign", "-d", "--verbose=4", binary], capture=True)
    for line in result.stderr.decode(errors="replace").splitlines():
        if line.startswith("Identifier="):
            identifier = line.partition("=")[2].strip()
            if identifier:
                return identifier
    raise SystemExit(f"[!] codesign did not report an identifier for {binary}")


def entitlements(ldid: Path, binary: Path) -> bytes:
    """Return the complete entitlement plist emitted by ldid."""
    return run([ldid, "-e", binary], capture=True).stdout


def build_binary(
    *,
    liter8: Path,
    ldid: Path,
    plan: str,
    pristine: Path,
    output: Path,
    records: Path,
) -> None:
    """Resolve, patch and re-sign one daemon from an untouched device copy."""
    if not pristine.is_file() or pristine.stat().st_size == 0:
        raise SystemExit(f"[!] pristine userland binary is missing: {pristine}")

    # Save the semantic resolver output beside the built artifact. Besides
    # documenting the selected sites, this makes a future failure answerable
    # without repeating a device session.
    resolved = run(
        [liter8, "resolve", "userland", plan, pristine, "--json"],
        capture=True,
    ).stdout
    records.parent.mkdir(parents=True, exist_ok=True)
    records.write_bytes(resolved)

    output.parent.mkdir(parents=True, exist_ok=True)
    run([liter8, "apply", "userland", plan, pristine, output])

    original_identifier = signing_identifier(pristine)
    original_entitlements = entitlements(ldid, pristine)
    entitlement_file = output.with_suffix(output.suffix + ".entitlements.plist")
    entitlement_file.write_bytes(original_entitlements)

    # ldid otherwise derives the identifier from the temporary filename. That
    # is survivable for some daemons but rejected for others, and previously
    # produced a misleading second failure after the instruction fix worked.
    run([
        ldid,
        f"-I{original_identifier}",
        f"-S{entitlement_file}",
        "-Cadhoc",
        output,
    ])
    run(["/usr/bin/codesign", "-v", output], capture=True)

    if signing_identifier(output) != original_identifier:
        raise SystemExit(f"[!] signing identifier changed while patching {plan}")
    if entitlements(ldid, output) != original_entitlements:
        raise SystemExit(f"[!] entitlements changed while patching {plan}")

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}\n")
    print(f"[+] {plan}: patched, entitlement-preserving signature verified ({digest})")


def load_plist(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        document = plistlib.load(stream)
    if not isinstance(document, dict):
        raise SystemExit(f"[!] {path} is not a dictionary plist")
    return document


def screen_time(path: Path, *, verify_only: bool) -> None:
    """Set or verify launchd's five fail-fast ScreenTime overrides."""
    if path.exists():
        document = load_plist(path)
    elif verify_only:
        raise SystemExit(f"[!] ScreenTime override is missing: {path}")
    else:
        document = {}

    missing = [label for label in SCREEN_TIME_LABELS if document.get(label) is not True]
    if verify_only:
        if missing:
            raise SystemExit(f"[!] ScreenTime overrides missing: {', '.join(missing)}")
        print(f"[+] all {len(SCREEN_TIME_LABELS)} ScreenTime overrides are enabled")
        return

    for label in SCREEN_TIME_LABELS:
        document[label] = True
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        # launchd reads this particular override database as a binary plist.
        plistlib.dump(document, stream, fmt=plistlib.FMT_BINARY, sort_keys=True)
    screen_time(path, verify_only=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)

    binary = subcommands.add_parser("binary")
    binary.add_argument("plan", choices=("coreauthd", "mobileactivationd", "ctkd"))
    binary.add_argument("pristine", type=Path)
    binary.add_argument("output", type=Path)
    binary.add_argument("records", type=Path)
    binary.add_argument("--liter8", type=Path, default=Path(os.environ.get("LITER8_SELF", "")))
    binary.add_argument("--ldid", type=Path, required=True)

    overrides = subcommands.add_parser("screen-time")
    overrides.add_argument("plist", type=Path)
    overrides.add_argument("--verify", action="store_true")

    arguments = parser.parse_args()
    if arguments.command == "binary":
        if not arguments.liter8.is_file():
            raise SystemExit("[!] Liter8 executable was not supplied")
        build_binary(
            liter8=arguments.liter8,
            ldid=arguments.ldid,
            plan=arguments.plan,
            pristine=arguments.pristine,
            output=arguments.output,
            records=arguments.records,
        )
    else:
        screen_time(arguments.plist, verify_only=arguments.verify)


if __name__ == "__main__":
    main()
