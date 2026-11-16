#!/usr/bin/env python3
"""Host-only file safety checks using temporary files, never a device."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from liter8_workflow import Context, WorkflowError


class HostFileSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "work"
        self.source = self.root / "source"
        self.work.mkdir()
        self.source.mkdir()
        self.context = Context(
            profile_id="synthetic-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={"fixture": "fixture.bin"},
            liter8=self.root / "unused",
            resources=self.root / "unused-resources",
        )
        self.target = self.work / "fixture.bin"
        self.target.write_bytes(b"original")
        self.backup = self.target.with_name(self.target.name + ".bak")

    @staticmethod
    def interrupted_copy(source, destination, **kwargs):
        Path(destination).write_bytes(b"partial")
        raise OSError("synthetic disk-full error")

    def assert_no_partial_files(self):
        expected = {self.target, self.backup}
        self.assertFalse([p for p in self.work.iterdir() if p.is_file() and p not in expected])

    def test_interrupted_backup_does_not_leave_a_pristine_marker(self):
        with patch("liter8_workflow.shutil.copy2", side_effect=self.interrupted_copy):
            with self.assertRaises(OSError):
                self.context.backup(self.target)
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.target.read_bytes(), b"original")
        self.assert_no_partial_files()
        self.context.backup(self.target)
        self.assertEqual(self.backup.read_bytes(), b"original")

    def test_cancelled_backup_cleans_partial_output(self):
        def cancel(source, destination, **kwargs):
            Path(destination).write_bytes(b"partial")
            raise KeyboardInterrupt

        with patch("liter8_workflow.shutil.copy2", side_effect=cancel):
            with self.assertRaises(KeyboardInterrupt):
                self.context.backup(self.target)
        self.assertFalse(self.backup.exists())
        self.assert_no_partial_files()

    def test_backup_keeps_the_first_complete_copy(self):
        self.context.backup(self.target)
        self.target.write_bytes(b"changed")
        self.context.backup(self.target)
        self.assertEqual(self.backup.read_bytes(), b"original")
        self.assertEqual(self.target.read_bytes(), b"changed")
        self.backup.unlink()
        real_copy = shutil.copy2

        def competing_copy(source, destination, **kwargs):
            result = real_copy(source, destination, **kwargs)
            self.backup.write_bytes(b"first complete publication")
            return result

        with patch("liter8_workflow.shutil.copy2", side_effect=competing_copy):
            self.context.backup(self.target)
        self.assertEqual(self.backup.read_bytes(), b"first complete publication")
        self.assert_no_partial_files()

    def test_backup_does_not_publish_a_partial_file(self):
        real_copy = shutil.copy2

        def copy(source, destination, **kwargs):
            Path(destination).write_bytes(b"partial")
            self.assertFalse(self.backup.exists())
            return real_copy(source, destination, **kwargs)

        with patch("liter8_workflow.shutil.copy2", side_effect=copy):
            self.context.backup(self.target)
        self.assertEqual(self.backup.read_bytes(), b"original")
        self.assert_no_partial_files()

    def test_backup_refuses_an_existing_link(self):
        unrelated = self.root / "unrelated"
        unrelated.write_bytes(b"unrelated")
        self.backup.symlink_to(unrelated)
        with self.assertRaises(WorkflowError):
            self.context.backup(self.target)
        self.assertEqual(unrelated.read_bytes(), b"unrelated")

    def test_backup_refuses_a_dangling_link_without_creating_its_target(self):
        missing = self.root / "missing"
        self.backup.symlink_to(missing)
        with self.assertRaises(WorkflowError):
            self.context.backup(self.target)
        self.assertFalse(missing.exists())

    def test_backup_refuses_a_directory(self):
        self.backup.mkdir()
        with self.assertRaises(WorkflowError):
            self.context.backup(self.target)

    def test_backup_refuses_a_linked_source(self):
        outside = self.root / "outside"
        outside.write_bytes(b"unrelated")
        self.target.unlink()
        self.target.symlink_to(outside)
        with self.assertRaises(WorkflowError):
            self.context.backup(self.target)
        self.assertFalse(self.backup.exists())

    def test_failed_restore_preserves_current_file_and_backup(self):
        self.backup.write_bytes(b"original")
        self.target.write_bytes(b"current")
        with patch("liter8_workflow.shutil.copy2", side_effect=self.interrupted_copy):
            with self.assertRaises(OSError):
                self.context.reset_to_pristine(self.target)
        self.assertEqual(self.target.read_bytes(), b"current")
        self.assertEqual(self.backup.read_bytes(), b"original")
        self.assert_no_partial_files()

    def test_restore_recreates_a_missing_target(self):
        self.backup.write_bytes(b"original")
        self.target.unlink()
        self.context.reset_to_pristine(self.target)
        self.assertEqual(self.target.read_bytes(), b"original")

    def test_restore_refuses_a_linked_target(self):
        outside = self.root / "outside"
        outside.write_bytes(b"unrelated")
        self.backup.write_bytes(b"original")
        self.target.unlink()
        self.target.symlink_to(outside)
        with self.assertRaises(WorkflowError):
            self.context.reset_to_pristine(self.target)
        self.assertEqual(outside.read_bytes(), b"unrelated")

    def test_existing_workspace_link_is_not_a_mutable_tree(self):
        self.context.cfw.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(WorkflowError):
            self.context.component("fixture", in_cfw=True)

    def test_completion_marker_cannot_make_a_linked_workspace_trusted(self):
        (self.source / ".copy-complete").write_text(json.dumps({
            "profileID": self.context.profile_id,
            "sourceRoot": str(self.source),
        }))
        self.context.cfw.symlink_to(self.source, target_is_directory=True)
        with patch("liter8_workflow.subprocess.run") as runner:
            with self.assertRaises(WorkflowError):
                self.context.prepare_cfw()
        runner.assert_not_called()

    def test_completion_marker_must_not_be_a_link(self):
        self.context.cfw.mkdir()
        marker = self.root / "unrelated-marker"
        marker.write_text(json.dumps({
            "profileID": self.context.profile_id,
            "sourceRoot": str(self.source),
        }))
        (self.context.cfw / ".copy-complete").symlink_to(marker)
        with self.assertRaises(WorkflowError):
            self.context.prepare_cfw()


if __name__ == "__main__":
    unittest.main()
