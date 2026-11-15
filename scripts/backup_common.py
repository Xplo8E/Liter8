"""Shared filesystem and backup validation for the host-side helpers."""

import json
import os
import plistlib
import re
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from xml.parsers.expat import ExpatError

FILE_ID = re.compile(r"[0-9a-fA-F]{40}\Z")


def private_mkdir(path):
    """Create missing parents privately, without chmod-ing unrelated directories."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Symbolic link is not allowed: {path}")
    if not path.exists():
        private_mkdir(path.parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"Not a regular directory: {path}")


def require_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing or non-regular file: {path}")
    return path


def load_plist(path):
    try:
        with require_file(path).open("rb") as handle:
            data = plistlib.load(handle)
    except (plistlib.InvalidFileException, ExpatError, TypeError, OverflowError) as exc:
        raise ValueError(f"Malformed plist: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected a plist dictionary: {path}")
    return data


def backup_encrypted(backup):
    data = load_plist(Path(backup) / "Manifest.plist")
    if type(data.get("IsEncrypted")) is not bool:
        raise ValueError("Manifest.plist: IsEncrypted must be a boolean")
    return data["IsEncrypted"]


def validate_rows(rows):
    ids, paths = set(), set()
    for row in rows:
        if len(row) != 3 or any(not isinstance(x, str) or not x for x in row):
            raise ValueError("Manifest.db contains an invalid file record")
        fid, domain, rel = row
        if not FILE_ID.fullmatch(fid) or "\x00" in domain or "\x00" in rel:
            raise ValueError("Manifest.db contains an invalid file ID or path")
        if fid.lower() in ids or (domain, rel) in paths:
            raise ValueError("Manifest.db contains duplicate file IDs or paths")
        ids.add(fid.lower())
        paths.add((domain, rel))
    return rows


def read_rows(backup, encrypted_obj=None):
    query = (
        "SELECT fileID, domain, relativePath FROM Files WHERE flags=1 ORDER BY domain, relativePath"
    )
    if encrypted_obj is not None:
        with encrypted_obj.manifest_db_cursor() as cursor:
            cursor.execute("PRAGMA quick_check")
            if cursor.fetchall() != [("ok",)]:
                raise ValueError("Manifest.db failed SQLite integrity checking")
            cursor.execute(query)
            return validate_rows(cursor.fetchall())
    db = require_file(Path(backup) / "Manifest.db")
    # A completed Apple backup has a checkpointed index. Do not silently ignore
    # a live WAL or let SQLite create sidecars in the original backup directory.
    wal = db.with_name("Manifest.db-wal")
    if wal.is_symlink() or (wal.exists() and wal.stat().st_size):
        raise ValueError("Manifest.db has an uncheckpointed WAL; use a completed backup")
    connection = sqlite3.connect(db.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("Manifest.db failed SQLite integrity checking")
        return validate_rows(connection.execute(query).fetchall())
    finally:
        connection.close()


def source_file(backup, file_id):
    if not isinstance(file_id, str) or not FILE_ID.fullmatch(file_id):
        raise ValueError("Invalid backup file ID")
    backup = Path(backup)
    shard = backup / file_id[:2]
    if shard.is_symlink():
        raise ValueError("Backup file shard must not be a symbolic link")
    source = shard / file_id
    if not source.exists() and not source.is_symlink():
        source = backup / file_id  # Older flat backups.
    return require_file(source)


@contextmanager
def open_source(path):
    """Refuse links and special files, including a swapped final component."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"Not a regular backup payload: {path}")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            yield handle
    finally:
        if fd is not None:
            os.close(fd)


def write_json(path, data, *, replace=True):
    """Atomically publish a private file; create-only mode never overwrites."""
    path = Path(path)
    private_mkdir(path.parent)
    if path.is_symlink():
        raise ValueError("JSON destination must not be a symbolic link")
    fd, name = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def state_lock(path):
    """Serialize sessions; an interrupted process leaves a visible stale lock."""
    path = Path(path)
    private_mkdir(path.parent)
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(
            f"Session is locked: {lock}. If no wizard is running, remove this stale lock."
        ) from exc
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(str(os.getpid()) + "\n")
        yield
    finally:
        lock.unlink(missing_ok=True)
