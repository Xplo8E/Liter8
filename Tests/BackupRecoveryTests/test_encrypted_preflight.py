"""End-to-end synthetic AES/keybag preflight and fail-closed state tests."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backup_test_support import make_backup, make_encrypted_backup

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import backup_preflight as check
import backup_wizard as wizard


class EncryptedPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = ("CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", b"synthetic photo")
        self.backup, self.password = make_encrypted_backup(self.root / "backup", [self.entry])

    def run_preflight(self, password=None):
        with patch.object(check.getpass, "getpass", return_value=password or self.password):
            return check.preflight_encrypted_backup(self.backup, ["photos"])

    def test_unlocks_and_decrypts_selected_files_without_leftover_plaintext(self):
        before = {
            str(p.relative_to(self.backup)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.backup.rglob("*")
            if p.is_file()
        }
        result = self.run_preflight()
        self.assertEqual(result["verified_files"], 1)
        self.assertEqual(result["selected_files"], 1)
        self.assertEqual(result["manifest_files"], 1)
        after = {
            str(p.relative_to(self.backup)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.backup.rglob("*")
            if p.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(list(self.root.glob("Liter8Preflight-*")), [])

    def test_rejects_wrong_password_and_cleans_temporary_files(self):
        with patch.object(check.getpass, "getpass", return_value="incorrect-password"):
            with self.assertRaises((ValueError, RuntimeError)):
                check.preflight_encrypted_backup(self.backup, ["photos"])
        self.assertEqual(list(self.root.glob("Liter8Preflight-*")), [])

    def test_rejects_empty_password(self):
        with patch.object(check.getpass, "getpass", return_value=""):
            with self.assertRaisesRegex(ValueError, "password"):
                check.preflight_encrypted_backup(self.backup, ["photos"])

    def test_rejects_truncated_ciphertext(self):
        fid = hashlib.sha1((self.entry[0] + "-" + self.entry[1]).encode()).hexdigest()
        payload = self.backup / fid[:2] / fid
        payload.write_bytes(payload.read_bytes()[:-3])
        with self.assertRaises((RuntimeError, OSError, ValueError)):
            self.run_preflight()
        self.assertEqual(list(self.root.glob("Liter8Preflight-*")), [])

    def test_rejects_missing_payload(self):
        fid = hashlib.sha1((self.entry[0] + "-" + self.entry[1]).encode()).hexdigest()
        (self.backup / fid[:2] / fid).unlink()
        with self.assertRaises(ValueError):
            self.run_preflight()

    def test_rejects_selected_file_size_mismatch(self):
        with patch.object(check, "require_file") as require:
            require.return_value.stat.return_value.st_size = 9999
            with self.assertRaises(ValueError):
                self.run_preflight()

    def test_no_selected_files_does_not_claim_files_were_verified(self):
        with patch.object(check.getpass, "getpass", return_value=self.password):
            result = check.preflight_encrypted_backup(self.backup, ["messages"])
        self.assertEqual(result["selected_files"], 0)
        self.assertEqual(result["verified_files"], 0)

    def test_before_wrong_password_does_not_publish_session(self):
        state = self.root / "state.json"
        args = SimpleNamespace(
            state=state,
            backup_root=self.root / "backups",
            udid="device123456",
            mode="encrypted",
            post_action="auto",
        )

        def backup_to_folder(command):
            dest = Path(command[-1]) / "device123456"
            make_encrypted_backup(dest, [self.entry])

        with (
            patch.object(wizard.shutil, "which", return_value="idevicebackup2"),
            patch.object(wizard, "select_udid", return_value="device123456"),
            patch.object(wizard, "set_encryption"),
            patch.object(wizard, "run_cmd", side_effect=backup_to_folder),
            patch.object(check.getpass, "getpass", return_value="wrong-password"),
        ):
            with self.assertRaises((ValueError, RuntimeError)):
                wizard.before(args)
        self.assertFalse(state.exists())

    def test_before_valid_password_records_preflight_and_fingerprint(self):
        state = self.root / "state.json"
        args = SimpleNamespace(
            state=state,
            backup_root=self.root / "backups",
            udid="device123456",
            mode="encrypted",
            post_action="auto",
        )

        def backup_to_folder(command):
            dest = Path(command[-1]) / "device123456"
            make_encrypted_backup(dest, [self.entry])

        with (
            patch.object(wizard.shutil, "which", return_value="idevicebackup2"),
            patch.object(wizard, "select_udid", return_value="device123456"),
            patch.object(wizard, "set_encryption"),
            patch.object(wizard, "run_cmd", side_effect=backup_to_folder),
            patch.object(check.getpass, "getpass", return_value=self.password),
        ):
            wizard.before(args)
        data = wizard.read_state(state)
        self.assertEqual(data["preflight"]["verified_files"], 1)
        self.assertEqual(len(data["backup_fingerprint"]), 64)

    def test_modified_manifest_blocks_after_before_ssh(self):
        plain = make_backup(self.root / "plain", [self.entry])
        state = self.root / "plain.json"
        wizard.write_state(
            state,
            {
                "schema": 1,
                "status": "backup_verified",
                "post_action": "auto",
                "encrypted": False,
                "backup_dir": str(plain),
                "categories": "photos",
                "backup_fingerprint": wizard.backup_fingerprint(plain),
            },
        )
        # Keep the manifest valid, but alter the bytes after preflight.
        manifest = plain / "Manifest.plist"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        args = SimpleNamespace(state=state, ssh_host="127.0.0.1", ssh_port=2222, ssh_user="root")
        with patch.object(wizard, "run_cmd") as run:
            with self.assertRaisesRegex(RuntimeError, "changed"):
                wizard.after(args)
        run.assert_not_called()
