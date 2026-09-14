#!/usr/bin/env python3
"""Check one-pass apply output against beta-4 and 24A435 fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


PACKAGE = Path(__file__).resolve().parent.parent
PRIVATE_ROOT = Path(os.environ.get("LITER8_FIXTURE_ROOT", PACKAGE.parent)).resolve()
LITER8 = PACKAGE / ".build/release/liter8"


def patch_identity(records: list[dict[str, object]]) -> list[tuple[object, ...]]:
    """Keep fields shared by PatchRecord and FixtureManifest.ExpectedPatch."""
    return [
        (
            record["id"],
            record["offset"],
            record["originalBytes"],
            record["replacementBytes"],
        )
        for record in records
    ]


def run(*arguments: object, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(argument) for argument in arguments],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def verify_case(
    name: str,
    source: Path,
    fixture_path: Path,
    temporary: Path,
) -> None:
    fixture = json.loads(fixture_path.read_text())
    output = temporary / f"{name}.patched"
    records_path = temporary / f"{name}.json"

    applied = run(
        LITER8, "apply", "userland", "coreauthd", source, output,
        "--records-out", records_path,
    )
    if "coreauthd.dto-ratchet.start-controller" not in applied.stdout:
        raise AssertionError(f"{name}: human-readable patch output disappeared")

    # The old two-command path remains a useful compatibility oracle in this
    # test. Production workflows no longer execute it.
    separately_resolved = json.loads(
        run(LITER8, "resolve", "userland", "coreauthd", source, "--json").stdout
    )
    one_pass_records = json.loads(records_path.read_text())
    if one_pass_records != separately_resolved:
        raise AssertionError(f"{name}: one-pass records differ from resolve --json")
    if patch_identity(one_pass_records) != patch_identity(fixture["expectedPatches"]):
        raise AssertionError(f"{name}: one-pass records differ from the fixture")

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    if digest != fixture["expectedOutputSHA256"]:
        raise AssertionError(f"{name}: patched output hash differs from the fixture")
    print(f"[pass] {name}: one-pass records and output match the fixture")


def verify_failure_is_atomic(temporary: Path) -> None:
    source = temporary / "invalid.bin"
    output = temporary / "existing-output.bin"
    records = temporary / "failed-records.json"
    source.write_bytes(b"not a supported binary")
    output.write_bytes(b"previous output")

    result = run(
        LITER8, "apply", "userland", "coreauthd", source, output,
        "--records-out", records, check=False,
    )
    if result.returncode == 0:
        raise AssertionError("invalid input unexpectedly patched")
    if output.read_bytes() != b"previous output":
        raise AssertionError("failed apply replaced the previous output")
    if records.exists():
        raise AssertionError("failed apply published records")
    print("[pass] failed apply preserves output and publishes no records")


def main() -> None:
    cases = [
        (
            "beta4",
            PRIVATE_ROOT / "offsets/userland/coreauthd",
            PACKAGE / "fixtures/24A5390f/n104ap/coreauthd-n104-24A5390f.json",
        ),
        (
            "24A435",
            PRIVATE_ROOT / "offsets/24A435/coreauthd",
            PACKAGE / "fixtures/24A435/n104ap/coreauthd-n104-24A435.json",
        ),
    ]
    missing = [str(source) for _, source, _ in cases if not source.is_file()]
    if missing:
        print("[skip] one-pass fixture inputs are absent:")
        for path in missing:
            print(f"       {path}")
        return
    if not LITER8.is_file():
        raise SystemExit(f"release Liter8 binary is missing: {LITER8}")

    with tempfile.TemporaryDirectory(prefix="liter8-apply-records-") as directory:
        temporary = Path(directory)
        for name, source, fixture in cases:
            verify_case(name, source, fixture, temporary)
        verify_failure_is_atomic(temporary)


if __name__ == "__main__":
    main()
