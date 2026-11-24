#!/usr/bin/env python3
"""Host-only tests for root filesystem cleanup and state publication."""

import errno
import io
import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import measure_guards
import rootfs
from liter8_workflow import WorkflowError


class SurveyCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.extracted = self.work / "extracted"
        self.extracted.mkdir()
        (self.extracted / "fixture.img").write_bytes(b"synthetic input")
        manifest = {
            "BuildIdentities": [{
                "Info": {"DeviceClass": "fixture", "RestoreBehavior": "Erase"},
                "Manifest": {"OS": {"Info": {"Path": "fixture.img"}}},
            }],
        }
        (self.extracted / "BuildManifest.plist").write_bytes(plistlib.dumps(manifest))
        self.mountpoint = self.work / "temporary mount"
        self.guards = {"fixture": 1}
        self.images = []

    def fake_decrypt(self, source, image):
        self.images.append(image)
        image.write_bytes(b"temporary backing file")

    def run_survey(self, *, attach_error=None, detach_status=0, mount_found=True,
                   measure_error=None):
        mount = ({}, self.mountpoint) if mount_found else None
        self.stderr = io.StringIO()

        def hdiutil(command, **kwargs):
            if command[1] == "attach":
                if attach_error is not None:
                    raise attach_error
                return subprocess.CompletedProcess(command, 0)
            self.assertEqual(command, ["mock-hdiutil", "detach", str(self.mountpoint)])
            return subprocess.CompletedProcess(command, detach_status, "", "resource busy")

        with (
            patch.object(measure_guards, "executable", return_value="mock-hdiutil"),
            patch.object(measure_guards, "decrypt", side_effect=self.fake_decrypt),
            patch.object(measure_guards, "mountpoint_for_image", return_value=mount),
            patch.object(measure_guards, "measure", return_value=self.guards,
                         side_effect=measure_error),
            patch.object(measure_guards, "emit") as self.emit,
            patch.object(measure_guards.subprocess, "run", side_effect=hdiutil) as self.hdiutil,
            redirect_stdout(io.StringIO()),
            redirect_stderr(self.stderr),
        ):
            return measure_guards.main(["measure_guards.py", str(self.extracted)])

    def test_failed_detach_preserves_image_and_fails_before_emitting(self):
        with self.assertRaisesRegex(WorkflowError, "could not detach.*resource busy"):
            self.run_survey(detach_status=1)
        self.emit.assert_not_called()
        self.assertTrue(self.images[0].is_file())
        self.assertIn(str(self.images[0]), self.stderr.getvalue())
        self.assertIn(str(self.mountpoint), self.stderr.getvalue())

    def test_unresolved_mount_preserves_image_and_fails_before_emitting(self):
        with self.assertRaisesRegex(WorkflowError, "could not find where"):
            self.run_survey(mount_found=False)
        self.emit.assert_not_called()
        self.assertEqual(self.hdiutil.call_count, 1)
        self.assertTrue(self.images[0].is_file())

    def test_attach_error_preserves_image_when_mount_state_is_uncertain(self):
        for error in (
            OSError("could not read child output"),
            subprocess.CalledProcessError(1, "mock-hdiutil", stderr="attach failed"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(WorkflowError, "could not attach"):
                    self.run_survey(attach_error=error)
                self.emit.assert_not_called()
                self.assertTrue(self.images[-1].is_file())
                self.assertIn(str(self.images[-1]), self.stderr.getvalue())

    def test_successful_detach_removes_image_then_emits(self):
        self.assertEqual(self.run_survey(), 0)
        self.emit.assert_called_once()
        self.assertFalse(self.images[0].parent.exists())

    def test_measurement_failure_still_detaches_and_removes_image(self):
        with self.assertRaisesRegex(WorkflowError, "measurement failed"):
            self.run_survey(measure_error=WorkflowError("measurement failed"))
        self.emit.assert_not_called()
        self.assertEqual(self.hdiutil.call_count, 2)
        self.assertFalse(self.images[0].parent.exists())

    def test_detach_error_does_not_hide_measurement_error(self):
        with self.assertRaisesRegex(WorkflowError, "measurement failed"):
            self.run_survey(detach_status=1, measure_error=WorkflowError("measurement failed"))
        self.emit.assert_not_called()
        self.assertTrue(self.images[0].is_file())
        self.assertIn("resource busy", self.stderr.getvalue())


class RootfsCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / rootfs.ROOTFS_DIRECTORY
        self.root.mkdir()
        self.image = self.root / rootfs.IMAGE_NAME
        self.image.write_bytes(b"synthetic cached image")
        self.state = self.root / rootfs.STATE_NAME
        self.state.write_text("previous state")
        self.mountpoint = self.work / "mount"
        self.context = SimpleNamespace(
            state=self.work, profile_id="fixture", components={"OS": "fixture.img"},
        )
        self.disk_full = OSError(errno.ENOSPC, "synthetic disk full")

    def run_prepare(self, *, already_mounted=False, publish_error=None, detach_error=None):
        found = ({}, self.mountpoint)
        attach_state = [found] if already_mounted else [None, found, found]

        def hdiutil(command, **kwargs):
            if command[1] == "detach" and detach_error is not None:
                raise detach_error

        with (
            patch.object(rootfs, "executable", return_value="mock-hdiutil"),
            patch.object(rootfs, "mountpoint_for_image", side_effect=attach_state),
            patch.object(rootfs, "validate_rootfs", return_value={}),
            patch.object(rootfs, "write_state", wraps=rootfs.write_state,
                         side_effect=publish_error),
            patch.object(rootfs, "run", side_effect=hdiutil) as self.hdiutil,
            redirect_stdout(io.StringIO()),
        ):
            rootfs.prepare(self.context)

    def verbs(self):
        return [call.args[0][1] for call in self.hdiutil.call_args_list]

    def test_publication_failure_detaches_new_mount(self):
        with self.assertRaisesRegex(OSError, "synthetic disk full"):
            self.run_prepare(publish_error=self.disk_full)
        self.assertEqual(self.verbs(), ["imageinfo", "attach", "detach"])
        self.hdiutil.assert_called_with(["mock-hdiutil", "detach", self.mountpoint])
        self.assertEqual(self.state.read_text(), "previous state")

    def test_rollback_failure_preserves_publication_error(self):
        with self.assertRaisesRegex(OSError, "synthetic disk full"):
            self.run_prepare(publish_error=self.disk_full,
                             detach_error=OSError("synthetic detach error"))
        self.assertEqual(self.verbs(), ["imageinfo", "attach", "detach"])

    def test_publication_failure_leaves_existing_mount_alone(self):
        with self.assertRaisesRegex(OSError, "synthetic disk full"):
            self.run_prepare(already_mounted=True, publish_error=self.disk_full)
        self.hdiutil.assert_not_called()

    def test_successful_publication_leaves_new_mount_available(self):
        self.run_prepare()
        self.assertEqual(self.verbs(), ["imageinfo", "attach"])
        self.assertEqual(json.loads(self.state.read_text())["mountpoint"], str(self.mountpoint))

    def test_failed_write_or_close_cleans_temporary_state(self):
        original = tempfile.NamedTemporaryFile
        for failure in ("write", "close"):
            with self.subTest(failure=failure):
                @contextmanager
                def failing_file(**kwargs):
                    with original(**kwargs) as output:
                        def write(data):
                            if failure == "write":
                                output.write(data[:10])
                                raise self.disk_full
                            return output.write(data)

                        yield SimpleNamespace(name=output.name, write=write)
                        if failure == "close":
                            raise self.disk_full

                with patch.object(rootfs.tempfile, "NamedTemporaryFile", failing_file):
                    with self.assertRaisesRegex(OSError, "synthetic disk full"):
                        rootfs.write_state(self.root, self.context, self.image, self.mountpoint, {})
                self.assertFalse(list(self.root.glob(".rootfs-state-*")))
                self.assertEqual(self.state.read_text(), "previous state")

    def test_failed_replace_cleans_temporary_state(self):
        with patch.object(rootfs.os, "replace", side_effect=self.disk_full):
            with self.assertRaisesRegex(OSError, "synthetic disk full"):
                rootfs.write_state(self.root, self.context, self.image, self.mountpoint, {})
        self.assertFalse(list(self.root.glob(".rootfs-state-*")))
        self.assertEqual(self.state.read_text(), "previous state")


if __name__ == "__main__":
    unittest.main()
