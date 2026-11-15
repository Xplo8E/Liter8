#!/usr/bin/env python3
"""Opt-in, host-side pre-erase backup and post-boot file staging for Liter8."""

import argparse
import hashlib
import json
import os
import plistlib
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from backup_common import (
    backup_encrypted,
    load_plist,
    private_mkdir,
    read_rows,
    require_file,
    source_file,
    state_lock,
    write_json,
)
from backup_preflight import preflight_encrypted_backup
from backup_recovery import REMOTE_ROOT, parse_categories, validate_ssh

DEFAULT_ROOT = Path.home() / "Liter8Backups"
DEFAULT_CATEGORIES = "photos,videos,voice,documents,app_documents"
UDID_PATTERN = re.compile(r"[A-Za-z0-9-]{10,64}\Z")


def ask_choice(message, choices, default):
    display = "/".join(f"{x.upper() if x == default else x}" for x in choices)
    while True:
        result = input(f"{message} [{display}]: ").lower().strip() or default
        if result in choices:
            return result
        print("Choose one of:", ", ".join(choices))


def run_cmd(args):
    return subprocess.run(args, check=True)


def get_devices():
    if not shutil.which("idevice_id"):
        raise RuntimeError("Install libimobiledevice: idevice_id not found.")
    result = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, check=True)
    return list(
        dict.fromkeys(
            line.strip()
            for line in result.stdout.splitlines()
            if UDID_PATTERN.fullmatch(line.strip())
        )
    )


def select_udid(preferred=None):
    devices = get_devices()
    if preferred:
        if preferred not in devices:
            raise RuntimeError("The specified device is not connected in normal mode.")
        return preferred
    if len(devices) == 1:
        return devices[0]
    if not devices:
        raise RuntimeError(
            "No iPhone found. Unlock it and trust this computer."
        )
    print("Connected devices:")
    for i, name in enumerate(devices, 1):
        print(f" {i}. {name}")
    index = input("Device number: ").strip()
    if not index.isascii() or not index.isdigit() or not 1 <= int(index) <= len(devices):
        raise RuntimeError("No device selected.")
    return devices[int(index) - 1]


def get_encryption_state(udid):
    if not shutil.which("ideviceinfo"):
        raise RuntimeError("ideviceinfo is required to check backup encryption.")
    result = subprocess.run(
        ["ideviceinfo", "-u", udid, "-q", "com.apple.mobile.backup", "-k", "WillEncrypt"],
        text=True,
        capture_output=True,
        check=True,
    )
    value = result.stdout.strip().lower()
    if value not in ("true", "false"):
        raise RuntimeError(f"Could not determine backup encryption: {value!r}")
    return value == "true"


def set_encryption(udid, desired):
    if get_encryption_state(udid) == desired:
        return
    print("Changing encryption affects future local iPhone backups.")
    if not desired:
        print("An unencrypted backup excludes some protected data.")
        if input("Type DISABLE to turn off backup encryption: ").strip() != "DISABLE":
            raise RuntimeError("Encryption change cancelled.")
    print("Enter the backup password when idevicebackup2 prompts. It is not saved.")
    # encryption on|off [PASSWORD] takes no backup directory argument.
    run_cmd(["idevicebackup2", "-i", "-u", udid, "encryption", "on" if desired else "off"])
    if get_encryption_state(udid) != desired:
        raise RuntimeError("Backup encryption setting did not change.")


def validate_backup(path, encrypted):
    path = Path(path)
    required = ("Manifest.plist", "Manifest.db", "Status.plist")
    if any((path / name).is_symlink() or not (path / name).is_file() for name in required):
        raise RuntimeError(f"Backup incomplete: missing regular file from {required}.")
    try:
        if backup_encrypted(path) != encrypted:
            raise RuntimeError("Backup encryption does not match the selected mode.")
        status = load_plist(path / "Status.plist")
        if status.get("SnapshotState") != "finished":
            raise RuntimeError("Backup is not finished (SnapshotState != finished).")
        size = (path / "Manifest.db").stat().st_size
        if size == 0:
            raise RuntimeError("Manifest.db is empty.")
        if encrypted:
            # Ciphertext cannot be integrity-checked without the existing password.
            if size % 16:
                raise RuntimeError("Encrypted Manifest.db is truncated (length is not a multiple of 16).")
        else:
            rows = read_rows(path)
            for fid, _, _ in rows:
                source_file(path, fid)
    except (OSError, ValueError, sqlite3.Error, plistlib.InvalidFileException) as exc:
        raise RuntimeError(f"Backup validation failed: {exc}") from exc
    return True


def backup_fingerprint(backup):
    """Detect changes to the backup manifests between before and after."""
    digest = hashlib.sha256()
    for name in ("Manifest.plist", "Manifest.db", "Status.plist"):
        digest.update(name.encode("ascii") + b"\\0")
        with require_file(Path(backup) / name).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def validate_state(data):
    message = "Invalid or unsupported session state."
    if (
        not isinstance(data, dict)
        or type(data.get("schema")) is not int
        or data["schema"] != 1
        or data.get("post_action") not in ("auto", "manual", "none")
        or data.get("status") not in ("skipped", "backup_verified", "staged", "empty")
    ):
        raise RuntimeError(message)
    if data["status"] == "skipped":
        if data["post_action"] != "none" or data.get("backup_dir") is not None:
            raise RuntimeError(message)
        return data
    backup = data.get("backup_dir")
    if (
        not isinstance(backup, str)
        or not backup
        or "\x00" in backup
        or not Path(backup).is_absolute()
        or type(data.get("encrypted")) is not bool
    ):
        raise RuntimeError(message)
    if data["post_action"] == "auto":
        try:
            parse_categories(data.get("categories"))
        except ValueError as exc:
            raise RuntimeError(message) from exc
    fingerprint = data.get("backup_fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
    ):
        raise RuntimeError(message)
    preflight = data.get("preflight")
    if preflight is not None and (
        not isinstance(preflight, dict)
        or preflight.get("mode") != "full_selected_decryption"
        or type(preflight.get("selected_files")) is not int
        or type(preflight.get("verified_files")) is not int
        or preflight["selected_files"] < 0
        or preflight["selected_files"] != preflight["verified_files"]
    ):
        raise RuntimeError(message)
    return data


def write_state(path, data, *, replace=True):
    validate_state(data)
    write_json(path, data, replace=replace)


def read_state(path):
    with require_file(path).open(encoding="utf-8") as handle:
        return validate_state(json.load(handle))


def before(args):
    args.state = args.state.expanduser().absolute()
    with state_lock(args.state):
        if args.state.exists() or args.state.is_symlink():
            raise RuntimeError(
                "Session state already exists. Use a new --state path."
            )
        _before(args)


def _before(args):
    print("Liter8 Backup Wizard: run before erasing, on normal iOS (not DFU).")
    mode = args.mode or ask_choice(
        "Backup mode: encrypted, plain, skip?", ("encrypted", "plain", "skip"), "encrypted"
    )
    if mode == "skip":
        if input("No backup will be made. Type NO BACKUP to confirm: ").strip() != "NO BACKUP":
            raise RuntimeError("Cancelled: no backup created.")
        write_state(
            args.state,
            {"schema": 1, "post_action": "none", "backup_dir": None, "status": "skipped"},
            replace=False,
        )
        print("Backup skipped. Erasing the device is still risky.")
        return
    action = args.post_action or ask_choice(
        "After boot: auto (SSH staging), manual, none?", ("auto", "manual", "none"), "manual"
    )
    if not shutil.which("idevicebackup2"):
        raise RuntimeError("Install libimobiledevice (idevicebackup2).")
    root = args.backup_root.expanduser().absolute()
    if root.is_symlink():
        raise RuntimeError("Backup directory cannot be a symbolic link.")
    private_mkdir(root)
    root = root.resolve()
    # Reserve writable storage before changing any setting on the phone.
    dest = Path(
        tempfile.mkdtemp(
            prefix="backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=root
        )
    )
    udid = select_udid(args.udid)
    if not UDID_PATTERN.fullmatch(udid):
        raise RuntimeError("Invalid device identifier.")
    encrypted = mode == "encrypted"
    set_encryption(udid, encrypted)
    print("Creating a full local backup. Keep the device connected.")
    try:
        run_cmd(["idevicebackup2", "-u", udid, "backup", "--full", str(dest)])
        backup_dir = dest / udid
        validate_backup(backup_dir, encrypted)
        preflight = (
            preflight_encrypted_backup(backup_dir, DEFAULT_CATEGORIES.split(","))
            if encrypted
            else None
        )
        if encrypted and action == "auto" and preflight["selected_files"] == 0:
            raise RuntimeError(
                "No files selected for automatic recovery; refusing to arm auto mode."
            )
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
        print(f"Backup not verified. Remaining files: {dest}", file=sys.stderr)
        raise
    data = {
        "schema": 1,
        "backup_dir": str(backup_dir),
        "encrypted": encrypted,
        "post_action": action,
        "status": "backup_verified",
        "udid": udid,
        "categories": DEFAULT_CATEGORIES,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_fingerprint": backup_fingerprint(backup_dir),
    }
    if preflight is not None:
        data["preflight"] = preflight
    write_state(args.state, data, replace=False)
    print(f"Backup completed and checked: {backup_dir}")
    if encrypted:
        print(
            "Password accepted. Selected files decrypted: "
            f"{preflight['verified_files']}/{preflight['selected_files']}. "
            "This does not verify app restoration or iOS integrity."
        )
    print(f"Post-boot action: {action}; session: {args.state}")
    print("This helper does not install firmware or erase the phone.")


def after(args):
    args.state = args.state.expanduser().absolute()
    require_file(args.state)
    with state_lock(args.state):
        _after(args)


def _after(args):
    data = read_state(args.state)
    if data["status"] == "skipped" or data["post_action"] == "none":
        print("Automatic staging is disabled.")
        return
    if data["status"] in ("staged", "empty"):
        print(
            "Files already staged."
            if data["status"] == "staged"
            else "No matching files in the backup."
        )
        return
    backup = Path(data["backup_dir"])
    validate_backup(backup, data["encrypted"])
    if data.get("backup_fingerprint") is not None:
        if backup_fingerprint(backup) != data["backup_fingerprint"]:
            raise RuntimeError("Backup manifests changed since preflight; transfer blocked.")
    if data["encrypted"] and data["post_action"] == "auto":
        proof = data.get("preflight")
        if not proof or proof.get("mode") != "full_selected_decryption":
            raise RuntimeError("Missing encrypted preflight proof; transfer blocked.")
    if data["post_action"] == "manual":
        print("Manual mode. Backup remains on this computer:", backup)
        command = [
            sys.executable,
            str(Path(__file__).with_name("backup_recovery.py")),
            "--backup",
            str(backup),
            "--extract",
        ]
        print("To extract files manually:", shlex.join(command))
        return
    validate_ssh(args.ssh_host, args.ssh_port, args.ssh_user)
    print("Staging selected files only. This is NOT a full iOS restore.")
    script = require_file(Path(__file__).with_name("backup_recovery.py"))
    with tempfile.TemporaryDirectory(prefix="Liter8TempRecovery-") as temp:
        target = Path(temp) / ("Liter8Recovery-" + os.path.basename(temp))
        run_cmd(
            [
                sys.executable,
                str(script),
                "--backup",
                str(backup),
                "--categories",
                data["categories"],
                "--upload",
                "--confirmed-upload",
                "--output",
                str(target),
                "--ssh-host",
                args.ssh_host,
                "--ssh-port",
                str(args.ssh_port),
                "--ssh-user",
                args.ssh_user,
            ]
        )
        with require_file(target / "report.json").open(encoding="utf-8") as handle:
            report = json.load(handle)
        if (
            not isinstance(report, dict)
            or type(report.get("extracted")) is not int
            or type(report.get("selected_files")) is not int
            or report.get("failed_count") != 0
            or report["extracted"] < 0
            or report["extracted"] != report["selected_files"]
        ):
            raise RuntimeError("Invalid transfer receipt. Session state unchanged.")
        if report["extracted"] == 0 and report.get("upload_status") == "empty":
            data["status"] = "empty"
        elif (
            report["extracted"] > 0
            and report.get("upload_status") == "complete"
            and report.get("remote_directory") == REMOTE_ROOT + "/" + target.name
        ):
            data["status"] = "staged"
            data["staged_at"] = datetime.now(timezone.utc).isoformat()
            data["transfer"] = {
                "host": args.ssh_host,
                "port": args.ssh_port,
                "user": args.ssh_user,
                "remote_directory": report["remote_directory"],
                "extracted": report["extracted"],
            }
        else:
            raise RuntimeError("Transfer not confirmed. Session state unchanged.")
    write_state(args.state, data)
    if data["status"] == "empty":
        print("No matching files. Nothing sent over SSH.")
    else:
        print("Files staged on the iPhone. Native apps have not imported them.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pre-erase backup and post-boot SSH file staging for Liter8"
    )
    sub = parser.add_subparsers(dest="phase", required=True)
    before_parser = sub.add_parser(
        "before", help="Run in normal paired iOS, before ANY destructive restore"
    )
    before_parser.add_argument("--state", type=Path, default=DEFAULT_ROOT / "last-session.json")
    before_parser.add_argument("--backup-root", type=Path, default=DEFAULT_ROOT)
    before_parser.add_argument("--udid")
    before_parser.add_argument("--mode", choices=("encrypted", "plain", "skip"))
    before_parser.add_argument("--post-action", choices=("auto", "manual", "none"))
    after_parser = sub.add_parser("after", help="Run when iOS is up and SSH is reachable")
    after_parser.add_argument("--state", type=Path, default=DEFAULT_ROOT / "last-session.json")
    after_parser.add_argument("--ssh-host", default="127.0.0.1")
    after_parser.add_argument("--ssh-port", type=int, default=2222)
    after_parser.add_argument("--ssh-user", default="root")
    args = parser.parse_args(argv)
    try:
        if args.phase == "before":
            before(args)
        else:
            after(args)
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.CalledProcessError,
        plistlib.InvalidFileException,
        EOFError,
    ) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "\nCancelled.\n")


if __name__ == "__main__":
    main()
