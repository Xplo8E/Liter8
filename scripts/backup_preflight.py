"""Fail-closed encrypted-backup preflight before a destructive iOS restore.

Only eligible files selected for later SSH staging are decrypted. The scratch
directory holds at most one decrypted file at a time. This is NOT a full native
iOS backup restore test and AES-CBC does not authenticate every byte.
"""

import getpass
import tempfile
from importlib.metadata import version
from pathlib import Path

from backup_common import read_rows, require_file, source_file
from backup_recovery import ENCRYPTED_VERSION, select_rows


def preflight_encrypted_backup(backup_dir, categories):
    """Unlock index and decrypt every selected file without retaining plaintext."""
    try:
        from iphone_backup_decrypt import EncryptedBackup
    except ImportError as exc:
        raise RuntimeError(
            "Install encrypted support before a restore: "
            "python3 -m pip install -r requirements-encrypted.txt"
        ) from exc
    if version("iphone_backup_decrypt") != ENCRYPTED_VERSION:
        raise RuntimeError(
            "Unsupported encryption library version; install requirements-encrypted.txt"
        )

    backup = Path(backup_dir).resolve()
    secret = getpass.getpass("Confirm the existing backup password for pre-erase verification: ")
    if not secret:
        raise ValueError("Backup password is required; restore is NOT safe to begin.")
    encrypted = EncryptedBackup(backup_directory=str(backup), passphrase=secret)
    del secret
    try:
        rows = read_rows(backup, encrypted)
        for file_id, _, _ in rows:
            source_file(backup, file_id)

        # Keep only one selected decrypted file on disk, at a private temporary
        # location outside the original backup. Even large backups are bounded
        # by the size of the largest selected file, not total selected bytes.
        with tempfile.TemporaryDirectory(prefix="Liter8Preflight-", dir=backup.parent) as temp:
            directory = Path(temp)
            selected = select_rows(rows, set(categories), directory)
            lookup = {(fid, domain, rel) for fid, domain, rel, _, _ in selected}
            checked = set()
            scratch = directory / "probe.bin"
            pending = None

            def finish_pending():
                nonlocal pending
                if pending is None:
                    return
                key, expected_size = pending
                actual = require_file(scratch).stat().st_size
                if actual != expected_size:
                    raise ValueError(
                        "Decrypted file size mismatch; backup cannot be considered verified."
                    )
                scratch.unlink()
                checked.add(key)
                pending = None

            def select(*, file_id, domain, relative_path, file_plist, **_):
                nonlocal pending
                finish_pending()
                key = (file_id, domain, relative_path)
                if key not in lookup:
                    return False
                if key in checked:
                    raise ValueError("Duplicate entry during encrypted-backup verification.")
                # The library exposes the plaintext size from the manifest
                # record; a truncated or malformed output must fail closed.
                length = file_plist.filesize
                if type(length) is not int or length < 0:
                    raise ValueError("Invalid encrypted file length in manifest.")
                pending = (key, length)
                return str(scratch)

            completed = encrypted.extract_files(
                relative_paths_like="%",
                domain_like="%",
                output_folder=str(directory),
                filter_callback=select,
            )
            finish_pending()
            if completed != len(selected) or len(checked) != len(selected):
                raise RuntimeError("Encrypted preflight incomplete; do NOT erase the iPhone.")
            return {
                "mode": "full_selected_decryption",
                "manifest_files": len(rows),
                "selected_files": len(selected),
                "verified_files": len(checked),
            }
    finally:
        # The pinned library has no public close method. Always remove the
        # temporary decrypted Manifest.db, even on an incorrect password.
        encrypted._cleanup()
        encrypted._temp_manifest_db_conn = None
        encrypted._temporary_folder = None
        encrypted._temp_decrypted_manifest_db_path = None
