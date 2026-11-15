"""Host-side Backup Wizard checks. No real device or SSH is contacted."""

import json
import os
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backup_test_support import make_manifest_db

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import backup_wizard as wiz


class WizardTests(unittest.TestCase):
    def test_validate_backup_rejects_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                wiz.validate_backup(Path(d), False)

    def test_validate_backup_rejects_wrong_encryption_and_unfinished(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            make_manifest_db(root)
            (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
            (root / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "in_progress"}))
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                wiz.validate_backup(root, True)
            with self.assertRaisesRegex(RuntimeError, "not finished"):
                wiz.validate_backup(root, False)
            (root / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
            self.assertTrue(wiz.validate_backup(root, False))

    def test_state_file_private_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "session" / "state.json"
            data = {
                "schema": 1,
                "post_action": "manual",
                "status": "backup_verified",
                "backup_dir": str(Path(d) / "backup"),
                "encrypted": False,
            }
            wiz.write_state(state, data)
            self.assertEqual(wiz.read_state(state), data)
            if os.name == "posix":
                self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_before_skipping_requires_clear_confirmation(self):
        with tempfile.TemporaryDirectory() as d:
            args = SimpleNamespace(mode="skip", post_action="none", state=Path(d) / "state.json")
            with patch("builtins.input", return_value="no"):
                with self.assertRaisesRegex(RuntimeError, "Cancelled"):
                    wiz.before(args)
            self.assertFalse(args.state.exists())
            with patch("builtins.input", return_value="NO BACKUP"):
                wiz.before(args)
            self.assertEqual(wiz.read_state(args.state)["status"], "skipped")

    def test_before_creates_and_verifies_backup_or_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            args = SimpleNamespace(
                mode="encrypted",
                post_action="manual",
                state=root / "state.json",
                backup_root=root / "backups",
                udid="device123456",
            )

            def create_fake_backup(cmd):
                backup = Path(cmd[-1]) / "device123456"
                backup.mkdir()
                (backup / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
                (backup / "Manifest.db").write_bytes(b"x" * 16)
                (backup / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))

            with patch.object(wiz.shutil, "which", return_value="idevicebackup2"):
                with patch.object(wiz, "select_udid", return_value="device123456"):
                    with patch.object(wiz, "set_encryption") as enc:
                        with patch.object(wiz, "run_cmd", side_effect=create_fake_backup):
                            with patch.object(
                                wiz,
                                "preflight_encrypted_backup",
                                return_value={
                                    "mode": "full_selected_decryption",
                                    "manifest_files": 1,
                                    "selected_files": 1,
                                    "verified_files": 1,
                                },
                            ):
                                wiz.before(args)
            data = wiz.read_state(args.state)
            self.assertTrue(data["encrypted"])
            self.assertEqual(data["status"], "backup_verified")
            self.assertEqual(data["post_action"], "manual")
            self.assertTrue(Path(data["backup_dir"]).exists())
            enc.assert_called_once_with("device123456", True)

    def test_after_manual_does_not_contact_device(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            b = root / "backup"
            b.mkdir()
            (b / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
            make_manifest_db(b)
            (b / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
            state = root / "state.json"
            wiz.write_state(
                state,
                {
                    "schema": 1,
                    "status": "backup_verified",
                    "post_action": "manual",
                    "backup_dir": str(b),
                    "encrypted": False,
                },
            )
            args = SimpleNamespace(state=state, ssh_host=None, ssh_port=2222, ssh_user="root")
            with patch.object(wiz, "run_cmd") as cmd:
                wiz.after(args)
                cmd.assert_not_called()

    def test_after_auto_requires_valid_backup_and_marks_staged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            b = root / "backup"
            b.mkdir()
            (b / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
            make_manifest_db(b)
            (b / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
            state = root / "state.json"
            wiz.write_state(
                state,
                {
                    "schema": 1,
                    "status": "backup_verified",
                    "post_action": "auto",
                    "backup_dir": str(b),
                    "encrypted": False,
                    "categories": "photos",
                },
            )
            args = SimpleNamespace(
                state=state, ssh_host="127.0.0.1", ssh_port=2222, ssh_user="root"
            )

            def receipt(command):
                target = Path(command[command.index("--output") + 1])
                target.mkdir()
                (target / "report.json").write_text(
                    json.dumps(
                        {
                            "selected_files": 1,
                            "extracted": 1,
                            "failed_count": 0,
                            "upload_status": "complete",
                            "remote_directory": "/var/mobile/Media/Liter8Recovery/" + target.name,
                        }
                    )
                )

            with patch.object(wiz, "run_cmd", side_effect=receipt) as cmd:
                wiz.after(args)
                self.assertEqual(cmd.call_count, 1)
                self.assertIn("--confirmed-upload", cmd.call_args.args[0])
                self.assertEqual(wiz.read_state(state)["status"], "staged")
                wiz.after(args)
                self.assertEqual(cmd.call_count, 1)


if __name__ == "__main__":
    unittest.main()
