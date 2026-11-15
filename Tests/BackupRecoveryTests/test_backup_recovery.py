import hashlib
import plistlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import backup_recovery as rec


class RecoveryTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(
            rec.category_for("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.HEIC"), "photos"
        )
        self.assertEqual(
            rec.category_for("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.MOV"), "videos"
        )
        self.assertEqual(
            rec.category_for("AppDomain-org.example", "Documents/book.pdf"), "app_documents"
        )
        self.assertEqual(rec.category_for("HomeDomain", "Library/SMS/sms.db"), "messages")
        self.assertIsNone(rec.category_for("SystemDomain", "Library/com.apple.x/test.plist"))

    def test_prevent_traversal(self):
        path = rec.safe_dest(
            Path("/tmp/export"), "documents", "HomeDomain", "../somefile", "a" * 40
        )
        self.assertIsNone(path)

    def test_reject_bad_file_ids(self):
        self.assertIsNone(
            rec.safe_dest(Path("/tmp/export"), "documents", "HomeDomain", "ok.txt", "../etc/passwd")
        )

    def test_scan_and_extract_plain_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp) / "backup"
            b.mkdir()
            (b / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
            db = sqlite3.connect(b / "Manifest.db")
            db.execute(
                "CREATE TABLE Files (fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)"
            )
            entries = [
                ("CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", b"1234"),
                ("AppDomain-a", "Documents/x.txt", b"abc"),
            ]
            for domain, rel, content in entries:
                fid = hashlib.sha1((domain + "-" + rel).encode()).hexdigest()
                (b / fid[:2]).mkdir(exist_ok=True)
                (b / fid[:2] / fid).write_bytes(content)
                db.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (fid, domain, rel, 1, None))
            db.commit()
            db.close()
            output = Path(tmp) / "Liter8Recovery-TEST"
            script = str(Path(rec.__file__))
            args = [sys.executable, script, "--backup", str(b), "--output", str(output)]
            p = subprocess.run(args, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(output.exists())
            p = subprocess.run(args + ["--extract"], text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            contents = {
                p.read_bytes() for p in output.rglob("*") if p.is_file() and p.name != "report.json"
            }
            self.assertEqual(contents, {b"1234", b"abc"})
            p = subprocess.run(args + ["--extract"], text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)

    def test_encrypted_callback_uses_selected_output_path(self):
        class FakeEncryptedBackup:
            def extract_files(
                self, *, relative_paths_like, domain_like, output_folder, filter_callback
            ):
                assert output_folder == str(out)
                selected = filter_callback(
                    file_id="a" * 40,
                    domain="CameraRollDomain",
                    relative_path="Media/DCIM/100APPLE/A.HEIC",
                )
                assert Path(selected).parent == dest.parent
                Path(selected).write_bytes(b"fake decrypted bytes")
                assert (
                    filter_callback(
                        file_id="b" * 40, domain="SystemDomain", relative_path="Library/skip.txt"
                    )
                    is False
                )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "export"
            out.mkdir()
            (Path(tmp) / "aa").mkdir()
            (Path(tmp) / "aa" / ("a" * 40)).write_bytes(b"synthetic encrypted payload")
            dest = rec.safe_dest(
                out, "photos", "CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", "a" * 40
            )
            entries = [("a" * 40, "CameraRollDomain", "Media/DCIM/100APPLE/A.HEIC", "photos", dest)]
            count, failures = rec.extract_files(Path(tmp), FakeEncryptedBackup(), entries, out)
            self.assertEqual((count, failures), (1, []))
            self.assertEqual(dest.read_bytes(), b"fake decrypted bytes")

    def test_ssh_confirmation_cancel(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "Liter8Recovery-TEST"
            out.mkdir()
            with patch("builtins.input", return_value="NO"):
                with patch.object(rec.shutil, "which", return_value="/usr/bin/mock-ssh"):
                    with patch.object(rec.subprocess, "run") as runner:
                        self.assertFalse(rec.ssh_upload(out, "127.0.0.1", 2222, "root"))
                        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
