#!/usr/bin/env python3
"""Integration tests for Liter8's Swift-to-7-Zip boundary.

Python only manufactures unusual ZIP fixtures here. The executable under test
owns selection and staging in Swift and delegates ZIP decoding to 7-Zip.
"""

import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path


CLI = Path(sys.argv[1] if len(sys.argv) > 1 else ".build/debug/liter8").resolve()
warnings.filterwarnings("ignore", message="Duplicate name:")
FINAL_NAME = "iPhone12,1_27.0_24A5390f_Restore"
MANIFEST = plistlib.dumps({
    "ProductVersion": "27.0",
    "ProductBuildVersion": "24A5390f",
    "SupportedProductTypes": ["iPhone12,1"],
    "BuildIdentities": [{
        "ApBoardID": "0x04",
        "ApChipID": "0x8030",
        "Info": {"DeviceClass": "n104ap"},
    }],
})


def make_archive(root: Path, name: str, entries=()) -> Path:
    archive_path = root / f"{name}.ipsw"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("BuildManifest.plist", MANIFEST)
        for entry in entries:
            if isinstance(entry, zipfile.ZipInfo):
                archive.writestr(entry, b"../../outside")
                continue
            path, data, *compression = entry
            archive.writestr(
                path,
                data,
                compress_type=compression[0] if compression else zipfile.ZIP_DEFLATED,
            )
    return archive_path


def prepare(archive: Path, work: Path) -> subprocess.CompletedProcess[str]:
    work.mkdir()
    return subprocess.run(
        [str(CLI), "fw", "prepare", "--file", str(archive), "--work-dir", str(work)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def replace_stored_byte(archive_path: Path, member: str, index: int, replacement: int) -> None:
    """Mutate stored member data while leaving its recorded CRC untouched."""
    with zipfile.ZipFile(archive_path) as archive:
        info = archive.getinfo(member)
    with archive_path.open("r+b") as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
        name_length, extra_length = struct.unpack_from("<HH", header, 26)
        stream.seek(info.header_offset + 30 + name_length + extra_length + index)
        stream.write(bytes([replacement]))


def expect_failure(case: str, archive: Path, work: Path) -> None:
    result = prepare(archive, work)
    assert result.returncode != 0, f"{case} unexpectedly succeeded\n{result.stdout}"
    assert not (work / FINAL_NAME).exists(), f"{case} published a final firmware tree"
    assert not list(work.glob(".liter8-extract-*")), f"{case} left staging data"
    print(f"[pass] {case}")


def main() -> None:
    assert CLI.is_file(), f"Liter8 executable not found: {CLI}"
    with tempfile.TemporaryDirectory(prefix="liter8-ipsw-tests-") as temporary:
        root = Path(temporary)

        valid = make_archive(root, "valid", [
            ("Firmware/nested.bin", b"A" * 1024 * 1024),
            ("empty.bin", b""),
        ])
        valid_work = root / "work-valid"
        result = prepare(valid, valid_work)
        assert result.returncode == 0, result.stdout
        payload = valid_work / FINAL_NAME / "Firmware/nested.bin"
        assert payload.stat().st_size == 1024 * 1024
        print("[pass] valid nested extraction")

        payload.unlink()
        payload.symlink_to(root / "outside-target")
        result = subprocess.run(
            [str(CLI), "fw", "prepare", "--file", str(valid), "--work-dir", str(valid_work)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        assert result.returncode != 0, result.stdout
        payload.unlink()
        print("[pass] cached symlink replacement")

        # A completion marker is only a cache hint. The current archive inventory
        # must still expose a deleted or truncated firmware member.
        result = subprocess.run(
            [str(CLI), "fw", "prepare", "--file", str(valid), "--work-dir", str(valid_work)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        assert result.returncode != 0, result.stdout
        print("[pass] stale completion marker")

        absolute_escape = root / "absolute-escape"
        # Reject path forms that could be interpreted outside the staging tree.
        # Preflight behavior stays independent of extractor path handling.
        attacks = {
            "parent traversal": "../escaped",
            "absolute path": str(absolute_escape),
            "backslash traversal": "..\\escaped",
        }
        for index, (case, path) in enumerate(attacks.items()):
            attack_work = root / f"work-attack-{index}"
            expect_failure(
                case,
                make_archive(root, f"attack-{index}", [(path, b"bad")]),
                attack_work,
            )
            assert not (root / "escaped").exists()
            assert not absolute_escape.exists()
        assert not absolute_escape.exists()

        link = zipfile.ZipInfo("Firmware/dfu/iBEC.n104.RELEASE.im4p")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        expect_failure("symbolic link", make_archive(root, "symlink", [link]), root / "work-symlink")

        expect_failure(
            "duplicate path",
            make_archive(root, "duplicate", [("same", b"one"), ("same", b"two")]),
            root / "work-duplicate",
        )

        # Corrupt a stored member without updating its central-directory CRC.
        # This exact shape previously reached the final directory unnoticed.
        corrupt = make_archive(root, "bad-crc", [("payload.bin", b"correct-data", zipfile.ZIP_STORED)])
        replace_stored_byte(corrupt, "payload.bin", 0, ord("X"))
        expect_failure("stored-member CRC mismatch", corrupt, root / "work-crc")

        # Changing XML whitespace keeps the plist semantically valid. The
        # manifest reader must still reject it based on the archive CRC.
        corrupt_manifest = root / "bad-manifest-crc.ipsw"
        with zipfile.ZipFile(corrupt_manifest, "w") as archive:
            archive.writestr("BuildManifest.plist", MANIFEST, compress_type=zipfile.ZIP_STORED)
        newline = MANIFEST.index(b"\n")
        replace_stored_byte(corrupt_manifest, "BuildManifest.plist", newline, ord(" "))
        result = prepare(corrupt_manifest, root / "work-manifest-crc")
        assert result.returncode != 0 and "CRC" in result.stdout, result.stdout
        print("[pass] manifest CRC mismatch")

        truncated = root / "truncated.ipsw"
        truncated.write_bytes(valid.read_bytes()[:100])
        expect_failure("truncated archive", truncated, root / "work-truncated")

        missing_manifest = root / "missing-manifest.ipsw"
        with zipfile.ZipFile(missing_manifest, "w") as archive:
            archive.writestr("payload", b"x")
        expect_failure("missing manifest", missing_manifest, root / "work-missing")

        # A hard-killed previous run is reported instead of silently creating
        # another large staging directory beside it.
        interrupted_work = root / "work-interrupted"
        interrupted_work.mkdir()
        (interrupted_work / ".liter8-extract-old").mkdir()
        result = subprocess.run(
            [str(CLI), "fw", "prepare", "--file", str(valid), "--work-dir", str(interrupted_work)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        assert result.returncode != 0 and "stale Liter8 extraction" in result.stdout
        print("[pass] interrupted staging detection")

        # Archive-controlled control characters must be sanitized before an
        # error reaches the operator's terminal.
        terminal = make_archive(root, "terminal", [("Firmware/evil\x1b[31m.bin", b"x")])
        terminal_result = prepare(terminal, root / "work-terminal")
        assert terminal_result.returncode != 0, terminal_result.stdout
        assert "\x1b" not in terminal_result.stdout
        print("[pass] terminal-safe diagnostics")

    print("IPSW robustness integration: passed")


if __name__ == "__main__":
    main()
