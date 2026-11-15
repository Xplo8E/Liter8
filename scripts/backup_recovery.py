#!/usr/bin/env python3
"""Selectively extract a local iOS backup and optionally stage files over SSH."""

import argparse
import getpass
import hashlib
import ipaddress
import os
import plistlib
import re
import shlex
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path, PurePosixPath, PureWindowsPath
from uuid import uuid4

from backup_common import (
    FILE_ID,
    backup_encrypted,
    open_source,
    private_mkdir,
    read_rows,
    require_file,
    source_file,
    write_json,
)

PHOTO = {
    ".jpg",
    ".jpeg",
    ".heic",
    ".heif",
    ".png",
    ".gif",
    ".dng",
    ".tif",
    ".tiff",
    ".aae",
    ".webp",
    ".raw",
}
VIDEO = {".mov", ".mp4", ".m4v", ".avi", ".3gp"}
VOICE = {".m4a", ".caf", ".wav", ".mp3", ".aac"}
CATEGORIES = (
    "photos",
    "videos",
    "voice",
    "documents",
    "app_documents",
    "contacts",
    "messages",
    "notes",
)
REMOTE_ROOT = "/var/mobile/Media/Liter8Recovery"
BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
DATABASES = ("addressbook.sqlitedb", "sms.db", "notestore.sqlite", "notes.sqlite")
ENCRYPTED_VERSION = "0.11.2"


def parse_categories(value):
    if not isinstance(value, str):
        raise ValueError("Categories must be a comma-separated string")
    cats = {part.strip() for part in value.split(",") if part.strip()}
    if not cats or not cats <= set(CATEGORIES):
        raise ValueError("Unknown categories; choose from " + ", ".join(CATEGORIES))
    return cats


def category_for(domain, rel):
    if not isinstance(domain, str) or not isinstance(rel, str):
        return None
    rl, d = rel.replace("\\", "/").lower(), domain.lower()
    suffix = PurePosixPath(rl).suffix
    camera = d in ("camerarolldomain", "mediadomain") and rl.startswith(("media/dcim/", "dcim/"))
    if camera and suffix in PHOTO:
        return "photos"
    if camera and suffix in VIDEO:
        return "videos"
    if (
        rl.startswith(("recordings/", "media/recordings/", "library/recordings/"))
        or "voicememos" in d
    ) and suffix in VOICE:
        return "voice"
    base = PurePosixPath(rl).name
    if base in tuple("addressbook.sqlitedb" + ext for ext in ("", "-wal", "-shm")):
        return "contacts"
    if base in tuple("sms.db" + ext for ext in ("", "-wal", "-shm")) and (
        "sms" in rl or "sms" in d
    ):
        return "messages"
    if base in tuple(
        name + ext for name in ("notestore.sqlite", "notes.sqlite") for ext in ("", "-wal", "-shm")
    ):
        return "notes"
    if d.startswith(("appdomain-", "appdomaingroup-")) and rl.startswith("documents/"):
        return "app_documents"
    if d in ("homedomain", "mediadomain") and rl.startswith(("documents/", "media/documents/")):
        return "documents"
    return None


def safe_component(value):
    clean = BAD.sub("_", value).strip().rstrip(". ")
    if re.fullmatch(
        r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³]",
        clean.split(".")[0],
        re.IGNORECASE,
    ):
        clean = "_" + clean
    if clean in ("", ".", ".."):
        return "_"
    # Leave room for a full identifier prefix on filesystems with 255-byte names.
    if len(clean.encode("utf-8")) > 150:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
        stem, suffix = os.path.splitext(clean)
        suffix = suffix if len(suffix.encode("utf-8")) <= 20 else ""
        clean = stem.encode("utf-8")[:100].decode("utf-8", errors="ignore") + "-" + digest + suffix
    return clean


def safe_dest(root, cat, domain, rel, file_id):
    if (
        cat not in CATEGORIES
        or not isinstance(domain, str)
        or not domain
        or not isinstance(rel, str)
        or not isinstance(file_id, str)
        or not FILE_ID.fullmatch(file_id)
    ):
        return None
    rel = rel.replace("\\", "/")
    posix = PurePosixPath(rel)
    if (
        PureWindowsPath(rel).drive
        or posix.is_absolute()
        or ".." in posix.parts
        or not posix.parts
        or "\x00" in rel
    ):
        return None
    parts = [safe_component(part) for part in posix.parts]
    # Keep SQLite databases and their WAL/SHM sidecars under the same prefix.
    base = posix.name
    db_name = base[:-4] if base.lower().endswith(("-wal", "-shm")) else base
    identity = file_id.lower()
    if db_name.lower() in DATABASES:
        db_path = str(posix.with_name(db_name))
        identity = hashlib.sha1((domain + "-" + db_path).encode("utf-8")).hexdigest()
    parts[-1] = identity + "_" + parts[-1]
    return Path(root) / cat / safe_component(domain) / Path(*parts)


def select_rows(rows, cats, output_dir):
    selected = []
    destinations = set()
    for file_id, domain, rel in rows:
        cat = category_for(domain, rel)
        if cat not in cats:
            continue
        dest = safe_dest(output_dir, cat, domain, rel, file_id)
        if dest is None:
            raise ValueError(f"Unsafe selected backup path: {rel!r}")
        key = str(dest).casefold()
        if key in destinations:
            raise ValueError(f"Conflicting output paths in backup: {rel!r}")
        destinations.add(key)
        selected.append((file_id, domain, rel, cat, dest))
    return selected


def prepare_output(out):
    if out.is_symlink():
        raise ValueError("Output must not be a symbolic link")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("Output folder is not empty. Pick a fresh folder to avoid overwrites.")
    private_mkdir(out)
    os.chmod(out, 0o700)


def extract_files(backup_dir, encrypted_obj, entries, output_dir):
    completed = set()
    # All intermediate directories and temporary files are private. Commit each
    # completed file by rename; a failed copy/decryption never looks complete.
    pending = None
    extraction_error = None
    if not entries:
        return 0, []

    def finish_pending():
        nonlocal pending
        if pending is not None:
            fid, rel, temp, dest = pending
            require_file(temp)
            if dest.exists() or dest.is_symlink():
                raise ValueError("Refusing to overwrite an extracted file")
            os.chmod(temp, 0o600)
            os.replace(temp, dest)
            completed.add((fid, rel))
            pending = None

    def allocate(entry):
        fid, domain, rel, cat, dest = entry
        if dest != safe_dest(output_dir, cat, domain, rel, fid):
            raise ValueError("Extraction destination does not match the selected backup path")
        private_mkdir(dest.parent)
        fd, filename = tempfile.mkstemp(prefix=".extract-", dir=dest.parent)
        os.close(fd)
        return Path(filename), dest

    if encrypted_obj is not None:
        lookup = {tuple(entry[:3]): entry for entry in entries}

        def selected_callback(*, file_id, domain, relative_path, **_):
            nonlocal pending
            finish_pending()
            entry = lookup.get((file_id, domain, relative_path))
            if entry is None:
                return False
            source_file(backup_dir, file_id)  # Never let the library follow a payload symlink.
            temp, dest = allocate(entry)
            pending = (file_id, relative_path, temp, dest)
            return str(temp)

        try:
            encrypted_obj.extract_files(
                relative_paths_like="%",
                domain_like="%",
                output_folder=str(output_dir),
                filter_callback=selected_callback,
            )
            finish_pending()
        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
            KeyError,
            TypeError,
            IndexError,
            struct.error,
        ) as exc:
            extraction_error = str(exc)
            print(f"WARN: encrypted extraction stopped: {exc}", file=sys.stderr)
        finally:
            if pending is not None:
                pending[2].unlink(missing_ok=True)
    else:
        for i, entry in enumerate(entries, 1):
            fid, domain, rel, cat, dest = entry
            temp = None
            try:
                source = source_file(backup_dir, fid)
                temp, dest = allocate(entry)
                with open_source(source) as infile, temp.open("wb") as outfile:
                    shutil.copyfileobj(infile, outfile, length=1024 * 1024)
                os.utime(temp, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
                pending = (fid, rel, temp, dest)
                finish_pending()
            except (OSError, ValueError) as exc:
                pending = None
                print(f"WARN: {rel!r}: {exc}", file=sys.stderr)
            finally:
                if temp is not None:
                    temp.unlink(missing_ok=True)
            if i % 500 == 0:
                print(f"Processed {i}/{len(entries)} entries...")
    failures = [(fid, rel) for fid, _, rel, _, _ in entries if (fid, rel) not in completed]
    if extraction_error and not failures:
        failures.append(("", "Encrypted extraction error: " + extraction_error))
    return len(completed), failures


def validate_ssh(host, port, user):
    if (
        not isinstance(host, str)
        or not isinstance(user, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", user)
        or type(port) is not int
        or not 1 <= port <= 65535
    ):
        raise ValueError("Invalid SSH host, port or user")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(bare)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", bare):
            raise ValueError("Invalid SSH hostname") from None
        return bare, bare
    return str(address), "[" + str(address) + "]" if address.version == 6 else str(address)


def ssh_upload(out_dir, host, port, user, confirmed=False):
    host, scp_host = validate_ssh(host, port, user)
    out_dir = Path(out_dir).absolute()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", out_dir.name):
        raise ValueError("Unsafe output directory name")
    if out_dir.is_symlink() or not out_dir.is_dir():
        raise ValueError("Missing regular upload directory")
    for path in out_dir.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("Upload tree contains a link or special file")
    if not shutil.which("ssh") or not shutil.which("scp"):
        raise RuntimeError("ssh and scp (OpenSSH) must be installed")
    target = f"{user}@{host}"
    remote_child = REMOTE_ROOT + "/" + out_dir.name
    print(f"Upload destination: {target}:{remote_child}/")
    choice = (
        "UPLOAD"
        if confirmed
        else input("Type UPLOAD to transfer files (no changes to system databases): ").strip()
    )
    if choice != "UPLOAD":
        print("Transfer cancelled; local extracted files remain untouched.")
        return False
    options = [
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]
    root, child = shlex.quote(REMOTE_ROOT), shlex.quote(remote_child)
    # Atomic reservation prevents two uploads from merging. No existing child,
    # even a dangling link, is reused. Keep a partial remote tree after failure.
    subprocess.run(
        [
            "ssh",
            *options,
            "-p",
            str(port),
            target,
            f"umask 077 && test ! -L {root} && mkdir -p {root} && "
            f"chown mobile:mobile {root} && chmod 700 {root} && mkdir {child}",
        ],
        check=True,
    )
    subprocess.run(
        [
            "scp",
            *options,
            "-P",
            str(port),
            "-r",
            "./" + out_dir.name + "/.",
            f"{user}@{scp_host}:{remote_child}/",
        ],
        cwd=str(out_dir.parent),
        check=True,
    )
    subprocess.run(
        [
            "ssh",
            *options,
            "-p",
            str(port),
            target,
            f"chown -R mobile:mobile {child} && chmod -R go-rwx {child}",
        ],
        check=True,
    )
    return True


def perform(args, out, backup, encrypted_obj, cats, encrypted):
    rows = read_rows(backup, encrypted_obj)
    selected = select_rows(rows, cats, out)
    stats = Counter(cat for _, _, _, cat, _ in selected)
    print(f"Backup: {backup}\nEncrypted: {encrypted}\nIndexed entries: {len(rows)}\n")
    print("Selected files:")
    for cat in CATEGORIES:
        if cat in cats:
            print(f"  {cat:<18} {stats[cat]}")
    print(f"Total: {len(selected)}")
    if not (args.extract or args.upload):
        print("\nSCAN only: nothing extracted or uploaded. Add --extract or --upload.")
        return 0
    prepare_output(out)
    successes, failures = extract_files(backup, encrypted_obj, selected, out)
    report = {
        "source_backup": str(backup),
        "encrypted": encrypted,
        "selected_files": len(selected),
        "extracted": successes,
        "categories": dict(stats),
        "failed_count": len(failures),
        "failed": failures[:1000],
        "upload_status": "not_requested",
        "note": "Staged files only. No native iOS app databases have been modified.",
    }
    report_path = out / "report.json"
    write_json(report_path, report, replace=False)
    print(
        f"Extracted: {successes}/{len(selected)}; failures: {len(failures)}; report: {report_path}"
    )
    if failures:
        print("Extraction incomplete; upload blocked. Inspect report.json.", file=sys.stderr)
        return 2
    if args.upload:
        report["upload_status"] = "empty" if not selected else "failed"
        try:
            if selected:
                uploaded = ssh_upload(
                    out,
                    args.ssh_host,
                    args.ssh_port,
                    args.ssh_user,
                    confirmed=args.confirmed_upload,
                )
                report["upload_status"] = "complete" if uploaded else "cancelled"
                if uploaded:
                    report["remote_directory"] = REMOTE_ROOT + "/" + out.name
                    print(
                        "Copied to an iPhone staging folder. Native apps have NOT imported these files."
                    )
        finally:
            write_json(report_path, report)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Selective backup recovery; stages files, never patches iOS databases."
    )
    parser.add_argument(
        "--backup",
        required=True,
        type=Path,
        help="Folder containing Manifest.db and Manifest.plist",
    )
    parser.add_argument("--categories", default="photos,videos,voice,documents,app_documents")
    parser.add_argument("--extract", action="store_true", help="Extract selected files locally")
    parser.add_argument("--upload", action="store_true", help="Extract, then confirm SSH staging")
    parser.add_argument(
        "--confirmed-upload", action="store_true", help="Wizard auto-upload after advance opt-in"
    )
    parser.add_argument(
        "--output", type=Path, help="New or empty output directory, separate from the backup"
    )
    parser.add_argument("--ssh-host", default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-user", default="root")
    args = parser.parse_args(argv)
    if args.confirmed_upload and not args.upload:
        parser.error("--confirmed-upload requires --upload")
    cats = parse_categories(args.categories)
    validate_ssh(args.ssh_host, args.ssh_port, args.ssh_user)
    backup = args.backup.expanduser().resolve()
    require_file(backup / "Manifest.db")
    encrypted = backup_encrypted(backup)
    candidate = (
        args.output.expanduser().absolute()
        if args.output
        else Path.cwd()
        / (
            "Liter8Recovery-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
            + uuid4().hex[:12]
        )
    )
    if candidate.is_symlink():
        parser.error("Output must not be a symbolic link")
    out = candidate.resolve()
    if backup == out or backup in out.parents or out in backup.parents:
        parser.error("Output must be separate from backup directory")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", out.name):
        parser.error(
            "Output name must start with an ASCII letter/digit and contain only letters/digits/._-"
        )
    if not encrypted:
        return perform(args, out, backup, None, cats, False)
    try:
        from iphone_backup_decrypt import EncryptedBackup
    except ImportError as exc:
        raise RuntimeError(
            "Install encrypted support: python -m pip install -r requirements-encrypted.txt"
        ) from exc
    if version("iphone_backup_decrypt") != ENCRYPTED_VERSION:
        raise RuntimeError(
            "Use the tested dependency: python -m pip install -r requirements-encrypted.txt"
        )
    secret = getpass.getpass("Backup encryption password (stays local): ")
    encrypted_obj = EncryptedBackup(backup_directory=str(backup), passphrase=secret)
    del secret
    try:
        return perform(args, out, backup, encrypted_obj, cats, True)
    except (KeyError, TypeError, IndexError, struct.error) as exc:
        raise ValueError("Malformed encrypted backup metadata") from exc
    finally:
        # 0.11.2 has no public close/context manager. Clean up the decrypted
        # manifest deterministically, including wrong-password/error paths.
        encrypted_obj._cleanup()
        encrypted_obj._temp_manifest_db_conn = None
        encrypted_obj._temporary_folder = None
        encrypted_obj._temp_decrypted_manifest_db_path = None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        sqlite3.Error,
        ValueError,
        RuntimeError,
        subprocess.CalledProcessError,
        plistlib.InvalidFileException,
        EOFError,
    ) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
