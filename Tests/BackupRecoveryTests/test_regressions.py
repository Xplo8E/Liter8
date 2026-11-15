"""Regression tests for data loss, partial success, filesystem and SSH failures."""

import hashlib
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backup_test_support import make_backup, make_encrypted_backup

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import backup_common as common
import backup_recovery as rec
import backup_wizard as wiz

PHOTO = ("CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", b"synthetic photo")


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = make_backup(self.root / "backup", [PHOTO])
        self.out = self.root / "Liter8Recovery-test"

    def cli(self, *options, cwd=None):
        return subprocess.run(
            [sys.executable, rec.__file__, "--backup", str(self.backup), *map(str, options)],
            cwd=cwd,
            text=True,
            capture_output=True,
        )

    def state(self, **changes):
        data = {
            "schema": 1,
            "status": "backup_verified",
            "post_action": "auto",
            "encrypted": False,
            "backup_dir": str(self.backup),
            "categories": "photos",
        }
        data.update(changes)
        path = self.root / "state.json"
        wiz.write_state(path, data)
        return path

    def after_args(self, state):
        return SimpleNamespace(state=state, ssh_host="127.0.0.1", ssh_port=2222, ssh_user="root")

    def test_nonempty_garbage_is_not_a_verified_backup(self):
        (self.backup / "Manifest.db").write_bytes(b"not a database")
        with self.assertRaises(RuntimeError):
            wiz.validate_backup(self.backup, False)

    def test_wrong_sqlite_schema_is_not_a_verified_backup(self):
        (self.backup / "Manifest.db").unlink()
        connection = sqlite3.connect(self.backup / "Manifest.db")
        connection.execute("CREATE TABLE Other (value TEXT)")
        connection.close()
        with self.assertRaises(RuntimeError):
            wiz.validate_backup(self.backup, False)

    def test_missing_payload_is_not_a_verified_backup(self):
        common.source_file(self.backup, rec.read_rows(self.backup)[0][0]).unlink()
        with self.assertRaises(RuntimeError):
            wiz.validate_backup(self.backup, False)

    def test_invalid_manifest_shapes_fail_cleanly(self):
        for value in ([], {"IsEncrypted": "false"}, {"IsEncrypted": 1}, {}):
            with self.subTest(value=value):
                (self.backup / "Manifest.plist").write_bytes(plistlib.dumps(value))
                result = self.cli()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_status_plist_is_not_a_verified_backup(self):
        (self.backup / "Status.plist").write_bytes(plistlib.dumps([]))
        with self.assertRaises(RuntimeError):
            wiz.validate_backup(self.backup, False)

    def test_invalid_and_duplicate_manifest_rows_fail_cleanly(self):
        rows = rec.read_rows(self.backup)
        for invalid in (
            (None, "HomeDomain", "x"),
            (b"a" * 40, "HomeDomain", "x"),
            ("z" * 40, "HomeDomain", "x"),
            rows[0],
        ):
            with self.subTest(row=invalid):
                connection = sqlite3.connect(self.backup / "Manifest.db")
                connection.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (*invalid, 1, None))
                connection.commit()
                connection.close()
                result = self.cli()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)
                connection = sqlite3.connect(self.backup / "Manifest.db")
                connection.execute("DELETE FROM Files WHERE rowid=(SELECT MAX(rowid) FROM Files)")
                connection.commit()
                connection.close()

    def test_scan_never_changes_original_backup(self):
        before = {
            str(p.relative_to(self.backup)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.backup.rglob("*")
            if p.is_file()
        }
        self.assertEqual(self.cli().returncode, 0)
        after = {
            str(p.relative_to(self.backup)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.backup.rglob("*")
            if p.is_file()
        }
        self.assertEqual(before, after)
        self.assertFalse(self.out.exists())

    def test_uncheckpointed_manifest_wal_is_refused_without_modification(self):
        wal = self.backup / "Manifest.db-wal"
        wal.write_bytes(b"incomplete WAL")
        result = self.cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(wal.read_bytes(), b"incomplete WAL")

    def test_partial_extraction_returns_failure_and_reports_it(self):
        common.source_file(self.backup, rec.read_rows(self.backup)[0][0]).unlink()
        result = self.cli("--extract", "--output", self.out)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads((self.out / "report.json").read_text())
        self.assertEqual((report["extracted"], report["failed_count"]), (0, 1))
        self.assertFalse(list(self.out.rglob(".extract-*")))

    def test_partial_copy_is_discarded_and_upload_blocked(self):
        def broken_copy(infile, outfile, **kwargs):
            outfile.write(b"partial")
            raise OSError("disk full")

        with patch.object(rec.shutil, "copyfileobj", side_effect=broken_copy):
            with patch.object(rec, "ssh_upload") as upload:
                code = rec.main(
                    ["--backup", str(self.backup), "--output", str(self.out), "--upload"]
                )
        self.assertEqual(code, 2)
        upload.assert_not_called()
        self.assertEqual([p.name for p in self.out.rglob("*") if p.is_file()], ["report.json"])
        interrupted = self.root / "Liter8Recovery-interrupted"

        def interrupted_copy(infile, outfile, **kwargs):
            outfile.write(b"partial")
            raise KeyboardInterrupt

        with patch.object(rec.shutil, "copyfileobj", side_effect=interrupted_copy):
            with self.assertRaises(KeyboardInterrupt):
                rec.main(["--backup", str(self.backup), "--output", str(interrupted), "--extract"])
        self.assertFalse([p for p in interrupted.rglob("*") if p.is_file()])

    def test_default_output_inside_backup_is_rejected(self):
        result = self.cli("--extract", cwd=self.backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.backup.glob("Liter8Recovery-*")))

    def test_confirmed_upload_is_validated_before_any_backup_access(self):
        result = subprocess.run(
            [sys.executable, rec.__file__, "--backup", "nonexistent", "--confirmed-upload"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--confirmed-upload requires --upload", result.stderr)

    def test_new_output_is_private_even_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            code = rec.main(["--backup", str(self.backup), "--output", str(self.out), "--extract"])
        finally:
            os.umask(previous)
        self.assertEqual(code, 0)
        if os.name == "posix":
            for path in [self.out, *self.out.rglob("*")]:
                self.assertEqual(path.stat().st_mode & 0o077, 0, path)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_payload_and_shard_symlinks_are_rejected(self):
        fid = rec.read_rows(self.backup)[0][0]
        source = common.source_file(self.backup, fid)
        external = self.root / "external"
        external.write_bytes(b"must not be read")
        source.unlink()
        source.symlink_to(external)
        result = self.cli("--extract", "--output", self.out)
        self.assertEqual(result.returncode, 2)
        with self.assertRaises(RuntimeError):
            wiz.validate_backup(self.backup, False)
        source.unlink()
        source.parent.rmdir()
        source.parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            common.source_file(self.backup, fid)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_output_symlink_is_rejected(self):
        external = self.root / "external"
        external.mkdir()
        self.out.symlink_to(external, target_is_directory=True)
        self.assertNotEqual(self.cli("--extract", "--output", self.out).returncode, 0)
        self.assertEqual(list(external.iterdir()), [])

    def test_backslash_traversal_and_windows_drives_are_rejected(self):
        for rel in ("../file", r"..\file", r"C:\file", "C:/file", "/absolute", r"\\server\share\a"):
            with self.subTest(rel=rel):
                self.assertIsNone(rec.safe_dest(self.out, "documents", "HomeDomain", rel, "a" * 40))

    def test_domain_cannot_escape_destination(self):
        dest = rec.safe_dest(self.out, "app_documents", "/../../outside", "Documents/a", "a" * 40)
        self.assertTrue(dest.resolve().is_relative_to(self.out.resolve()))

    def test_full_file_ids_do_not_collide_when_first_ten_characters_match(self):
        first = "a" * 10 + "b" * 30
        second = "a" * 10 + "c" * 30
        rows = [(first, "HomeDomain", "Documents/a:b"), (second, "HomeDomain", "Documents/a?b")]
        entries = rec.select_rows(rows, {"documents"}, self.out)
        self.assertNotEqual(entries[0][-1], entries[1][-1])

    def test_reserved_and_long_windows_names_are_portable(self):
        for name in ("COM2", "LPT9.txt", "CON", "NUL", ".", "..", "a/b", "a\\b"):
            clean = rec.safe_component(name)
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)
            self.assertNotIn(clean, (".", "..", "COM2", "LPT9.txt", "CON", "NUL"))
        dest = rec.safe_dest(
            self.out, "documents", "HomeDomain", "Documents/" + "é" * 400 + ".txt", "a" * 40
        )
        self.assertLessEqual(len(dest.name.encode()), 255)
        self.assertTrue(dest.name.endswith(".txt"))

    def test_notes_prefix_does_not_capture_unrelated_files(self):
        self.assertIsNone(rec.category_for("HomeDomain", "Library/Notes/notes.sqlite.backup"))

    def test_voice_memos_under_library_recordings_are_selected(self):
        self.assertEqual(rec.category_for("HomeDomain", "Library/Recordings/test.m4a"), "voice")

    def test_sqlite_wal_and_database_remain_readable_together(self):
        database = self.root / "live.db"
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("CREATE TABLE Messages (body TEXT)")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("INSERT INTO Messages VALUES ('only in WAL')")
            connection.commit()
            backup = make_backup(
                self.root / "sqlite-backup",
                [
                    ("HomeDomain", "Library/SMS/sms.db", database.read_bytes()),
                    (
                        "HomeDomain",
                        "Library/SMS/sms.db-wal",
                        database.with_name("live.db-wal").read_bytes(),
                    ),
                ],
            )
        finally:
            connection.close()
        code = rec.main(
            [
                "--backup",
                str(backup),
                "--output",
                str(self.out),
                "--categories",
                "messages",
                "--extract",
            ]
        )
        self.assertEqual(code, 0)
        exported = next(self.out.rglob("*_sms.db"))
        self.assertTrue(Path(str(exported) + "-wal").is_file())
        extracted_connection = sqlite3.connect(exported)
        try:
            self.assertEqual(
                extracted_connection.execute("SELECT body FROM Messages").fetchall(),
                [("only in WAL",)],
            )
        finally:
            extracted_connection.close()

    def test_skip_never_overwrites_existing_state_or_changes_encryption(self):
        state = self.state()
        original = state.read_bytes()
        args = SimpleNamespace(state=state, mode="skip", post_action="none")
        with patch("builtins.input") as prompt, patch.object(wiz, "set_encryption") as encrypt:
            with self.assertRaises(RuntimeError):
                wiz.before(args)
        prompt.assert_not_called()
        encrypt.assert_not_called()
        self.assertEqual(state.read_bytes(), original)

    def test_lock_blocks_a_second_before_and_after(self):
        state = self.state()
        with common.state_lock(state):
            with self.assertRaisesRegex(RuntimeError, "locked"):
                wiz.before(SimpleNamespace(state=state, mode="skip", post_action="none"))
            with self.assertRaisesRegex(RuntimeError, "locked"):
                wiz.after(self.after_args(state))
        self.assertFalse(state.with_name(state.name + ".lock").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_state_write_does_not_chmod_existing_parent(self):
        parent = self.root / "shared-parent"
        parent.mkdir(mode=0o755)
        common.write_json(parent / "state.json", {"test": True})
        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual((parent / "state.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_predictable_temp_symlink_cannot_overwrite_another_file(self):
        victim = self.root / "victim"
        victim.write_text("original")
        state = self.root / "state.json"
        state.with_name(state.name + ".tmp").symlink_to(victim)
        self.state()
        self.assertEqual(victim.read_text(), "original")

    def test_create_only_state_publication_preserves_old_file(self):
        state = self.state()
        original = state.read_bytes()
        with self.assertRaises(FileExistsError):
            common.write_json(state, {"replacement": True}, replace=False)
        self.assertEqual(state.read_bytes(), original)
        self.assertFalse(list(self.root.glob(".state.json-*")))

    def test_malformed_states_are_rejected_before_side_effects(self):
        valid = json.loads(self.state().read_text())
        invalids = [
            [],
            None,
            {},
            {**valid, "schema": True},
            {**valid, "encrypted": "false"},
            {**valid, "backup_dir": "relative"},
            {**valid, "status": "oops"},
            {**valid, "categories": "photos,unknown"},
            {**valid, "backup_dir": None},
        ]
        for data in invalids:
            with self.subTest(data=data):
                with self.assertRaises(RuntimeError):
                    wiz.validate_state(data)

    def test_encryption_command_has_no_accidental_password_argument(self):
        with patch.object(wiz, "get_encryption_state", side_effect=[False, True]):
            with patch.object(wiz, "run_cmd") as run:
                wiz.set_encryption("synthetic-device", True)
        run.assert_called_once_with(
            ["idevicebackup2", "-i", "-u", "synthetic-device", "encryption", "on"]
        )

    def test_disabling_encryption_requires_confirmation(self):
        with patch.object(wiz, "get_encryption_state", return_value=True):
            with patch("builtins.input", return_value="NO"), patch.object(wiz, "run_cmd") as run:
                with self.assertRaises(RuntimeError):
                    wiz.set_encryption("synthetic-device", False)
        run.assert_not_called()

    def test_existing_encryption_setting_is_not_changed(self):
        with patch.object(wiz, "get_encryption_state", return_value=True):
            with patch.object(wiz, "run_cmd") as run:
                wiz.set_encryption("synthetic-device", True)
        run.assert_not_called()

    def test_no_receipt_means_after_cannot_claim_success(self):
        state = self.state()
        with patch.object(wiz, "run_cmd"):
            with self.assertRaises(ValueError):
                wiz.after(self.after_args(state))
        self.assertEqual(wiz.read_state(state)["status"], "backup_verified")

    def test_empty_selection_is_not_marked_as_transferred(self):
        state = self.state(categories="messages")
        wiz.after(self.after_args(state))
        self.assertEqual(wiz.read_state(state)["status"], "empty")
        with patch.object(wiz, "run_cmd") as run:
            wiz.after(self.after_args(state))
        run.assert_not_called()

    def test_transfer_failure_does_not_advance_state(self):
        state = self.state()
        with patch.object(wiz, "run_cmd", side_effect=subprocess.CalledProcessError(1, "scp")):
            with self.assertRaises(subprocess.CalledProcessError):
                wiz.after(self.after_args(state))
        self.assertEqual(wiz.read_state(state)["status"], "backup_verified")

    def test_unsuccessful_receipts_do_not_advance_state(self):
        state = self.state()
        for status in ("failed", "cancelled", "not_requested"):

            def receipt(command, status=status):
                output = Path(command[command.index("--output") + 1])
                output.mkdir()
                (output / "report.json").write_text(
                    json.dumps(
                        {
                            "extracted": 1,
                            "selected_files": 1,
                            "failed_count": 0,
                            "upload_status": status,
                            "remote_directory": rec.REMOTE_ROOT + "/" + output.name,
                        }
                    )
                )

            with self.subTest(status=status), patch.object(wiz, "run_cmd", side_effect=receipt):
                with self.assertRaises(RuntimeError):
                    wiz.after(self.after_args(state))
            self.assertEqual(wiz.read_state(state)["status"], "backup_verified")

    def test_ssh_failure_is_saved_in_local_report(self):
        with patch.object(rec, "ssh_upload", side_effect=subprocess.CalledProcessError(1, "ssh")):
            with self.assertRaises(subprocess.CalledProcessError):
                rec.main(
                    [
                        "--backup",
                        str(self.backup),
                        "--output",
                        str(self.out),
                        "--upload",
                        "--confirmed-upload",
                    ]
                )
        report = json.loads((self.out / "report.json").read_text())
        self.assertEqual(report["upload_status"], "failed")

    @unittest.skipUnless(os.name == "posix", "POSIX remote shell simulation")
    def test_remote_chown_error_is_not_hidden_by_successful_chmod(self):
        self.out.mkdir()
        remote = self.root / "remote"
        shim = self.root / "bin"
        shim.mkdir()
        chown = shim / "chown"
        chown.write_text('#!/bin/sh\nif [ "$1" = "-R" ]; then exit 5; fi\nexit 0\n')
        chown.chmod(0o700)
        real_run = subprocess.run

        def simulate(command, **kwargs):
            if command[0] == "ssh":
                return real_run(
                    ["sh", "-c", command[-1]],
                    check=True,
                    capture_output=True,
                    env={**os.environ, "PATH": str(shim) + os.pathsep + os.environ["PATH"]},
                )
            return subprocess.CompletedProcess(command, 0)

        with patch.object(rec, "REMOTE_ROOT", str(remote)):
            with patch.object(rec.shutil, "which", return_value="/mock/tool"):
                with patch.object(rec.subprocess, "run", side_effect=simulate):
                    with self.assertRaises(subprocess.CalledProcessError) as error:
                        rec.ssh_upload(self.out, "127.0.0.1", 2222, "root", True)
        self.assertEqual(error.exception.returncode, 5)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_backup_root_link_is_rejected_before_device_settings_change(self):
        link = self.root / "backup-link"
        link.symlink_to(self.backup, target_is_directory=True)
        args = SimpleNamespace(
            state=self.root / "new-state.json",
            mode="plain",
            post_action="manual",
            backup_root=link,
            udid=None,
        )
        with patch.object(wiz.shutil, "which", return_value="/mock/tool"):
            with patch.object(wiz, "set_encryption") as encrypt:
                with self.assertRaises(RuntimeError):
                    wiz.before(args)
        encrypt.assert_not_called()
        self.assertFalse(args.state.exists())

    def test_malformed_xml_plist_has_a_clean_cli_error(self):
        (self.backup / "Manifest.plist").write_bytes(b'<?xml version="1.0"?><plist><dict>')
        result = self.cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_completed_transfer_is_idempotent_even_if_backup_moved(self):
        state = self.state(status="staged")
        shutil.rmtree(self.backup)
        with patch.object(wiz, "run_cmd") as run:
            wiz.after(self.after_args(state))
        run.assert_not_called()

    def test_ipv6_ssh_and_scp_use_correct_address_forms(self):
        self.out.mkdir()
        with patch.object(rec.shutil, "which", return_value="/mock/tool"):
            with patch.object(rec.subprocess, "run") as run:
                rec.ssh_upload(self.out, "::1", 2222, "root", confirmed=True)
        self.assertIn("root@::1", run.call_args_list[0].args[0])
        self.assertTrue(
            any(item.startswith("root@[::1]:") for item in run.call_args_list[1].args[0])
        )

    def test_invalid_ssh_inputs_are_rejected(self):
        for host, port, user in [
            ("-host", 2222, "root"),
            ("host;anything", 2222, "root"),
            ("x", 0, "root"),
            ("x", 65536, "root"),
            ("x", True, "root"),
            ("x", 22, "-root"),
            (":::bad", 22, "root"),
        ]:
            with self.subTest(host=host, port=port, user=user):
                with self.assertRaises(ValueError):
                    rec.validate_ssh(host, port, user)

    @unittest.skipUnless(os.name == "posix", "POSIX remote shell simulation")
    def test_remote_directory_reservation_is_atomic(self):
        self.out.mkdir()
        (self.out / "synthetic.txt").write_text("data")
        remote_root = self.root / "remote"
        real_run = subprocess.run
        shim = self.root / "bin"
        shim.mkdir()
        chown = shim / "chown"
        chown.write_text("#!/bin/sh\nexit 0\n")
        chown.chmod(0o700)

        def simulate(command, **kwargs):
            if command[0] == "ssh":
                return real_run(
                    ["sh", "-c", command[-1]],
                    check=True,
                    capture_output=True,
                    env={**os.environ, "PATH": str(shim) + os.pathsep + os.environ["PATH"]},
                )
            remote = Path(command[-1].split(":", 1)[1])
            for source in self.out.iterdir():
                shutil.copy2(source, remote / source.name)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(rec, "REMOTE_ROOT", str(remote_root)):
            with patch.object(rec.shutil, "which", return_value="/mock/tool"):
                with patch.object(rec.subprocess, "run", side_effect=simulate):
                    self.assertTrue(rec.ssh_upload(self.out, "127.0.0.1", 2222, "root", True))
                    with self.assertRaises(subprocess.CalledProcessError):
                        rec.ssh_upload(self.out, "127.0.0.1", 2222, "root", True)
        self.assertEqual((remote_root / self.out.name / "synthetic.txt").read_text(), "data")

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_upload_refuses_local_symlinks_before_contacting_ssh(self):
        self.out.mkdir()
        (self.out / "link").symlink_to(self.backup, target_is_directory=True)
        with patch.object(rec.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                rec.ssh_upload(self.out, "localhost", 2222, "root", True)
        run.assert_not_called()


try:
    import iphone_backup_decrypt
except ImportError:
    iphone_backup_decrypt = None


@unittest.skipUnless(
    iphone_backup_decrypt, "Install requirements-encrypted.txt for encrypted integration tests"
)
class EncryptedIntegrationTests(unittest.TestCase):
    def test_corrupt_encrypted_payload_returns_partial_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup, password = make_encrypted_backup(
                root / "encrypted",
                [
                    ("CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", b"first"),
                    ("CameraRollDomain", "Media/DCIM/100APPLE/B.HEIC", b"second"),
                ],
            )
            fid = hashlib.sha1(b"CameraRollDomain-Media/DCIM/100APPLE/B.HEIC").hexdigest()
            payload = backup / fid[:2] / fid
            payload.write_bytes(payload.read_bytes()[:-1])
            output = root / "Liter8Recovery-corrupt"
            with patch.object(rec.getpass, "getpass", return_value=password):
                self.assertEqual(
                    rec.main(["--backup", str(backup), "--output", str(output), "--extract"]), 2
                )
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["extracted"], 1)
            self.assertEqual(report["failed_count"], 1)
            self.assertFalse(list(output.rglob(".extract-*")))

    def test_untested_dependency_version_is_rejected_before_password_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            backup, _ = make_encrypted_backup(Path(temp) / "encrypted", [PHOTO])
            with patch.object(rec, "version", return_value="0.8.0"):
                with patch.object(rec.getpass, "getpass") as prompt:
                    with self.assertRaises(RuntimeError):
                        rec.main(["--backup", str(backup)])
            prompt.assert_not_called()

    def test_real_dependency_decrypts_files_and_cleans_manifest_on_success_and_failure(self):
        for correct_password in (True, False):
            with (
                self.subTest(correct_password=correct_password),
                tempfile.TemporaryDirectory() as temp,
            ):
                root = Path(temp)
                backup, password = make_encrypted_backup(
                    root / "encrypted",
                    [PHOTO, ("AppDomain-test", "Documents/a.txt", b"another file")],
                )
                out = root / "Liter8Recovery-encrypted"
                temp_root = root / "decrypted-temp"
                temp_root.mkdir()
                with patch.object(
                    rec.getpass,
                    "getpass",
                    return_value=password if correct_password else "incorrect",
                ):
                    with patch.object(tempfile, "tempdir", str(temp_root)):
                        if correct_password:
                            self.assertEqual(
                                rec.main(
                                    ["--backup", str(backup), "--extract", "--output", str(out)]
                                ),
                                0,
                            )
                            files = {
                                p.read_bytes()
                                for p in out.rglob("*")
                                if p.is_file() and p.name != "report.json"
                            }
                            self.assertEqual(files, {PHOTO[2], b"another file"})
                        else:
                            with self.assertRaises(ValueError):
                                rec.main(
                                    ["--backup", str(backup), "--extract", "--output", str(out)]
                                )
                self.assertEqual(list(temp_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
