"""Synthetic fixtures only; no device identifiers or user backup data."""

import hashlib
import plistlib
import sqlite3
import struct
from pathlib import Path


def make_manifest_db(root):
    connection = sqlite3.connect(Path(root) / "Manifest.db")
    try:
        connection.execute(
            "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)"
        )
        connection.commit()
    finally:
        connection.close()


def make_backup(root, entries=()):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    (root / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
    make_manifest_db(root)
    connection = sqlite3.connect(root / "Manifest.db")
    try:
        for domain, rel, content in entries:
            fid = hashlib.sha1((domain + "-" + rel).encode()).hexdigest()
            (root / fid[:2]).mkdir(exist_ok=True)
            (root / fid[:2] / fid).write_bytes(content)
            connection.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (fid, domain, rel, 1, None))
        connection.commit()
    finally:
        connection.close()
    return root


def make_encrypted_backup(root, entries):
    """Build a tiny real AES/keybag backup with deliberately cheap test KDFs."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    root = make_backup(root)
    password = "synthetic-test-password"
    salt, dp_salt = b"s" * 20, b"d" * 20
    intermediate = hashlib.pbkdf2_hmac("sha256", password.encode(), dp_salt, 1, 32)
    password_key = hashlib.pbkdf2_hmac("sha1", intermediate, salt, 1, 32)
    class_key, manifest_key = b"c" * 32, b"m" * 32

    def wrap(outer, inner):
        return AES.new(outer, AES.MODE_KW).seal(inner)

    def encrypt(key, data):
        return AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(pad(data, 16))

    def tlv(tag, value):
        data = struct.pack(">I", value) if isinstance(value, int) else value
        return tag + struct.pack(">I", len(data)) + data

    fields = [
        (b"TYPE", 1),
        (b"UUID", b"g" * 16),
        (b"WRAP", 2),
        (b"DPIC", 1),
        (b"DPSL", dp_salt),
        (b"ITER", 1),
        (b"SALT", salt),
        (b"UUID", b"u" * 16),
        (b"CLAS", 4),
        (b"WRAP", 2),
        (b"WPKY", wrap(password_key, class_key)),
    ]
    connection = sqlite3.connect(root / "Manifest.db")
    try:
        for index, (domain, rel, content) in enumerate(entries):
            fid = hashlib.sha1((domain + "-" + rel).encode()).hexdigest()
            key = hashlib.sha256(str(index).encode()).digest()
            (root / fid[:2]).mkdir(exist_ok=True)
            (root / fid[:2] / fid).write_bytes(encrypt(key, content))
            metadata = {
                "$objects": [
                    "$null",
                    {"Size": len(content), "ProtectionClass": 4, "EncryptionKey": plistlib.UID(2)},
                    {"NS.data": struct.pack("<I", 4) + wrap(class_key, key)},
                ],
                "$top": {"root": plistlib.UID(1)},
            }
            connection.execute(
                "INSERT INTO Files VALUES (?,?,?,?,?)",
                (fid, domain, rel, 1, plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY)),
            )
        connection.commit()
    finally:
        connection.close()
    db = root / "Manifest.db"
    db.write_bytes(encrypt(manifest_key, db.read_bytes()))
    (root / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {
                "IsEncrypted": True,
                "BackupKeyBag": b"".join(tlv(tag, value) for tag, value in fields),
                "ManifestKey": struct.pack("<I", 4) + wrap(class_key, manifest_key),
            }
        )
    )
    return root, password
