#!/usr/bin/env python3
"""Focused tests for the generic Python/Swift workflow boundary."""

import copy
import json
import hashlib
import io
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from urllib.parse import quote_from_bytes
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from liter8_workflow import Context, DEFAULT_BOOT_FIRMWARE, WorkflowError, run  # noqa: E402
import measure_guards  # noqa: E402
from boot_artifacts import (  # noqa: E402
    PASSTHROUGH_IMG4,
    has_txm,
    publish_directory,
    ticket_from_environment,
    write_boot_manifest,
)
from device_boot import (  # noqa: E402
    boot as boot_device,
    selected_firmware_sequence,
    validate_boot_set,
)
from device_provision import (  # noqa: E402
    BOOTSTRAP_SHA256,
    SSHRD_PAYLOAD_SHA256,
    prepared_rootfs,
    prepare_runtime,
)
import sshrd  # noqa: E402
from sshrd import REVIEWED_PAYLOAD_SHA256, build_sshrd, sha256_file  # noqa: E402
from restore_cfw import managed_tss_proxy, restore_log_path, stage  # noqa: E402
from tss_proxy import TSSProxyHandler, TSSProxyServer, inject_euicc  # noqa: E402
from apticket import (  # noqa: E402
    capture_from_debug_log,
    ticket_from_tss_response,
    tickets_from_debug_log,
    validate_im4m,
)
import rootfs as rootfs_workflow  # noqa: E402

DEVICE = SCRIPTS.parent / "device"
sys.path.insert(0, str(DEVICE))
from userland_fixups import (  # noqa: E402
    SCREEN_TIME_LABELS,
    build_binary,
    entitlements,
    screen_time,
    signing_identifier,
)
from patch_setup import discover_targets  # noqa: E402
from patch_watchdogd_job import (  # noqa: E402
    CACHE_KEY as WATCHDOGD_CACHE_KEY,
    EXPECTED_MACH_SERVICES,
    REMOVED_POLICY,
    JobShapeError,
    apply_mitigation,
    policy_state,
    remove_mitigation,
    watchdogd_job_is_mitigated,
)
from add_ddi_services import (  # noqa: E402
    CACHE_KEY as DDI_CACHE_KEY,
    DDI_SERVICES_JOB,
    DDI_WATCHER,
    JobShapeError as DDIJobShapeError,
    apply_job as apply_ddi_job,
    remove_job as remove_ddi_job,
    validate_document as validate_ddi_document,
)


class DeveloperDiskImageJobTests(unittest.TestCase):
    def document(self):
        return {
            "VersionNumber": 7,
            "AppExtensions": {},
            "SystemLibraryTreeState": {},
            "LaunchDaemons": {
                "/System/Library/LaunchDaemons/com.apple.fixture.plist": {
                    "Label": "com.apple.fixture"
                },
            },
        }

    def test_job_bootstraps_the_fixed_system_domain_directory_on_mount(self):
        self.assertEqual(
            DDI_SERVICES_JOB["ProgramArguments"],
            [DDI_WATCHER],
        )
        self.assertTrue(DDI_SERVICES_JOB["RunAtLoad"])
        self.assertEqual(DDI_SERVICES_JOB["KeepAlive"], {"SuccessfulExit": False})
        self.assertNotIn("StartOnMount", DDI_SERVICES_JOB)

    def test_apply_and_remove_preserve_unrelated_jobs(self):
        document = self.document()
        before = copy.deepcopy(document)
        validate_ddi_document(document, expected_pristine=1)
        self.assertTrue(apply_ddi_job(document))
        self.assertEqual(document["LaunchDaemons"][DDI_CACHE_KEY], DDI_SERVICES_JOB)
        self.assertEqual(
            document["LaunchDaemons"]["/System/Library/LaunchDaemons/com.apple.fixture.plist"],
            before["LaunchDaemons"]["/System/Library/LaunchDaemons/com.apple.fixture.plist"],
        )
        validate_ddi_document(document, expected_pristine=1)
        self.assertFalse(apply_ddi_job(document))
        self.assertTrue(remove_ddi_job(document))
        self.assertEqual(document, before)

    def test_existing_modified_job_fails_closed(self):
        document = self.document()
        document["LaunchDaemons"][DDI_CACHE_KEY] = {"Label": "unexpected"}
        with self.assertRaisesRegex(DDIJobShapeError, "unexpected job definition"):
            apply_ddi_job(document)

    def test_unknown_extra_job_fails_profile_count_guard(self):
        document = self.document()
        document["LaunchDaemons"]["/tmp/unreviewed.plist"] = {"Label": "unreviewed"}
        with self.assertRaisesRegex(DDIJobShapeError, "expected 1"):
            validate_ddi_document(document, expected_pristine=1)

    def test_cache_build_and_device_verification_require_the_job(self):
        builder = (DEVICE / "fetch_payloads.sh").read_text()
        provisioner = (DEVICE / "sshrd_provision.sh").read_text()
        watcher = (DEVICE / "ddiwatch/ddiwatch.c").read_text()
        self.assertIn("./add_ddi_services.py", builder)
        self.assertIn("cd ddiwatch", builder)
        self.assertIn("LAUNCHD_CACHE_DAEMONS + 3", builder)
        self.assertIn("com.liter8.ddi-services", provisioner)
        self.assertIn("ddiwatch readback hash mismatch", provisioner)
        self.assertIn("LAUNCHD_CACHE_DAEMONS + 3", provisioner)
        self.assertIn("com.apple.coredevice.dtdeviceinfod.plist", watcher)
        self.assertIn("usleep(250000)", watcher)
        self.assertIn("services_registered()", watcher)


class WatchdogdJobPatchTests(unittest.TestCase):
    def job(self):
        return {
            "Label": "com.apple.watchdogd",
            "ProgramArguments": ["/usr/libexec/watchdogd"],
            "MachServices": {
                **EXPECTED_MACH_SERVICES,
                "com.apple.future-service": {"ResetAtClose": True},
            },
            "AlwaysSIGTERMOnShutdown": True,
            "EnablePressuredExit": False,
            "EnableTransactions": True,
            "ExitTimeOut": 15,
            "POSIXSpawnType": "Interactive",
            **copy.deepcopy(REMOVED_POLICY),
        }

    def document(self):
        return {
            "VersionNumber": 7,
            "LaunchDaemons": {
                WATCHDOGD_CACHE_KEY: self.job(),
                "/System/Library/LaunchDaemons/com.apple.logd.plist": {
                    "Label": "com.apple.logd"
                },
            },
        }

    def test_apply_removes_only_the_three_crash_loop_policies(self):
        document = self.document()
        before = copy.deepcopy(document)
        self.assertTrue(apply_mitigation(document))

        job = document["LaunchDaemons"][WATCHDOGD_CACHE_KEY]
        for key in REMOVED_POLICY:
            self.assertNotIn(key, job)
        self.assertEqual(
            job["MachServices"],
            before["LaunchDaemons"][WATCHDOGD_CACHE_KEY]["MachServices"],
        )
        self.assertEqual(
            document["LaunchDaemons"]["/System/Library/LaunchDaemons/com.apple.logd.plist"],
            before["LaunchDaemons"]["/System/Library/LaunchDaemons/com.apple.logd.plist"],
        )
        self.assertTrue(watchdogd_job_is_mitigated(document))
        self.assertFalse(apply_mitigation(document))

    def test_remove_restores_the_reviewed_stock_policy(self):
        document = self.document()
        original = copy.deepcopy(document)
        apply_mitigation(document)
        self.assertTrue(remove_mitigation(document))
        self.assertEqual(document, original)
        self.assertEqual(
            policy_state(document["LaunchDaemons"][WATCHDOGD_CACHE_KEY]), "stock"
        )

    def test_mixed_or_unknown_policy_fails_closed(self):
        document = self.document()
        del document["LaunchDaemons"][WATCHDOGD_CACHE_KEY]["KeepAlive"]
        with self.assertRaisesRegex(JobShapeError, "neither reviewed stock nor mitigated"):
            apply_mitigation(document)

    def test_wrong_program_fails_closed(self):
        document = self.document()
        document["LaunchDaemons"][WATCHDOGD_CACHE_KEY]["ProgramArguments"] = [
            "/tmp/not-watchdogd"
        ]
        with self.assertRaisesRegex(JobShapeError, "ProgramArguments"):
            apply_mitigation(document)

from apfs_role import volume_for_role  # noqa: E402


IPAD_BOOT_FIRMWARE = tuple(name for name in DEFAULT_BOOT_FIRMWARE
                           if name not in {"Ap,SecurePageTableMonitor", "PMP", "WCHFirmwareUpdater"})


class APFSRoleTests(unittest.TestCase):
    def test_preboot_is_selected_by_role_instead_of_partition_number(self):
        registry = '''+-o Preboot@5 <class AppleAPFSVolume, id 1>
          "Role" = ("Preboot")
          "BSD Name" = "disk1s5"
        +-o Update@6 <class AppleAPFSVolume, id 2>
          "Role" = ("Update")
          "BSD Name" = "disk1s6"
        '''
        self.assertEqual(volume_for_role(registry, 'Preboot'), '/dev/disk1s5')
        self.assertEqual(volume_for_role(registry.replace('"Role"', '\x1b[0;31m"Role"'), 'Preboot'), '/dev/disk1s5')

    def test_missing_or_ambiguous_role_is_rejected(self):
        volume = '''+-o Preboot@5 <class AppleAPFSVolume, id 1>
          "Role" = ("Preboot")
          "BSD Name" = "disk1s5"
        '''
        for registry in ('', volume + volume, volume.replace('disk1s5', 'disk1s5;reboot')):
            with self.assertRaises(ValueError):
                volume_for_role(registry, 'Preboot')


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.source = self.root / "source"
        self.resources = self.root / "resources"
        self.liter8 = self.root / "liter8"
        self.work.mkdir()
        self.source.mkdir()
        self.resources.mkdir()
        self.liter8.touch()
        self.context_file = self.work / "context.json"
        self.context_file.write_text(json.dumps({
            "schema": 3,
            "profileID": "fixture-profile",
            "sourceRoot": str(self.source),
            "components": {"iBSS": "Firmware/dfu/iBSS.im4p"},
            "bootPlan": {
                "firmwareComponents": list(DEFAULT_BOOT_FIRMWARE),
                "normalTrustCache": "RestoreTrustCache",
                "normalIBSSAdditionalPlans": ["ibss-skip-display-init"],
                "restoreIBSSAdditionalPlans": ["ibss-skip-display-init"],
            },
        }))
        self.environment = {
            "LITER8_CONTEXT": str(self.context_file),
            "LITER8_SELF": str(self.liter8),
            "LITER8_RESOURCE_DIR": str(self.resources),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_loads_manifest_component_without_build_specific_names(self):
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                context = Context.load()
            self.assertEqual(
                context.component("iBSS"),
                (self.source / "Firmware/dfu/iBSS.im4p").resolve(),
            )
            self.assertEqual(
                context.normal_ibss_additional_plans,
                ("ibss-skip-display-init",),
            )
            self.assertEqual(
                context.restore_ibss_additional_plans,
                ("ibss-skip-display-init",),
            )
        finally:
            os.chdir(previous)

    def test_rejects_context_without_reviewed_boot_plan(self):
        document = json.loads(self.context_file.read_text())
        del document["bootPlan"]
        self.context_file.write_text(json.dumps(document))
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                with self.assertRaisesRegex(WorkflowError, "no reviewed boot plan"):
                    Context.load()
        finally:
            os.chdir(previous)

    def test_rejects_unknown_hardware_boot_plan(self):
        document = json.loads(self.context_file.read_text())
        document["bootPlan"]["normalIBSSAdditionalPlans"] = ["unknown-board-patch"]
        self.context_file.write_text(json.dumps(document))
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                with self.assertRaisesRegex(WorkflowError, "unsupported normal iBSS plans"):
                    Context.load()
        finally:
            os.chdir(previous)

    def test_rejects_stale_or_malformed_boot_firmware_policy(self):
        original = json.loads(self.context_file.read_text())
        invalid = [None, [], ["RestoreLogo", "SEP", "unknown"],
                   ["RestoreLogo", "SEP", "SEP"], ["RestoreLogo", 1]]
        for value in invalid:
            document = copy.deepcopy(original)
            document["bootPlan"]["firmwareComponents"] = value
            self.context_file.write_text(json.dumps(document))
            with self.subTest(value=value), patch.dict(os.environ, self.environment, clear=True):
                with self.assertRaises(WorkflowError):
                    Context.load()
        document = copy.deepcopy(original)
        document["schema"] = 2
        self.context_file.write_text(json.dumps(document))
        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(WorkflowError, "unsupported Liter8 context schema"):
                Context.load()

    def test_rejects_context_path_that_escapes_firmware_tree(self):
        document = json.loads(self.context_file.read_text())
        document["components"]["iBSS"] = "../outside.im4p"
        self.context_file.write_text(json.dumps(document))
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                context = Context.load()
            with self.assertRaises(WorkflowError):
                context.component("iBSS")
        finally:
            os.chdir(previous)

    def test_records_exact_artifact_hash(self):
        artifact = self.work / "patched.im4p"
        artifact.write_bytes(b"patched firmware")
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                context = Context.load()
                context.record_hash(artifact, "kernel-restore")
            digest = (self.work / "artifact-hashes/kernel-restore.sha256")
            self.assertEqual(
                digest.read_text().strip(),
                "069e3b50f8d711e4f139628e6f401c6a570d478655fa7fb1b3d63edf8b340aa6",
            )
            self.assertFalse(
                (self.work / ".liter8").exists(),
                "an explicit work directory must not gain a nested .liter8",
            )
        finally:
            os.chdir(previous)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS APFS clone support")
    def test_cfw_uses_an_atomic_writable_clone(self):
        """A CFW tree must not require a second physical 10-GB copy."""
        source_file = self.source / "large-firmware-image"
        source_file.write_bytes(b"firmware" * 1024)
        source_file.chmod(0o444)
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
        )

        with redirect_stdout(io.StringIO()):
            context.prepare_cfw()
        cloned_file = context.cfw / source_file.name
        self.assertEqual(cloned_file.read_bytes(), source_file.read_bytes())
        self.assertTrue(cloned_file.stat().st_mode & 0o200)
        self.assertTrue((context.cfw / ".copy-complete").is_file())

        # The clone becomes independent on first write, while a rerun trusts
        # only the profile/source-bound completion marker.
        cloned_file.write_bytes(b"patched")
        self.assertNotEqual(cloned_file.read_bytes(), source_file.read_bytes())
        with redirect_stdout(io.StringIO()):
            context.prepare_cfw()

    def test_atomic_patch_does_not_double_dot_hidden_intermediate(self):
        target = self.work / ".DeviceTree.im4p"
        target.write_bytes(b"input")
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
        )
        applied_output = None

        def fake_run(arguments, *, capture=False, environment=None):
            nonlocal applied_output
            applied_output = Path(arguments[5])
            applied_output.write_bytes(target.read_bytes())
            return type("Result", (), {"stdout": ""})()

        with patch("liter8_workflow.run", side_effect=fake_run):
            context.apply(
                "devicetree", "normal", target,
                record_name="devicetree", capture_records=False,
            )

        self.assertIsNotNone(applied_output)
        self.assertTrue(applied_output.name.startswith(".DeviceTree.im4p.liter8-"))
        self.assertFalse(applied_output.name.startswith(".."))

    def test_apply_patches_and_records_in_one_liter8_process(self):
        target = self.work / "kernelcache"
        target.write_bytes(b"clean")
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
        )
        commands = []

        def fake_run(arguments, *, capture=False, environment=None):
            commands.append(arguments)
            self.assertEqual(arguments[1:4], ["apply", "kernel", "restore"])
            self.assertEqual(arguments[4], target)
            self.assertEqual(arguments[6], "--records-out")
            Path(arguments[5]).write_bytes(b"patched")
            Path(arguments[7]).write_text("[]\n")
            return type("Result", (), {"stdout": ""})()

        with patch("liter8_workflow.run", side_effect=fake_run):
            context.apply("kernel", "restore", target, record_name="kernel-restore")

        self.assertEqual(len(commands), 1, "one workflow patch must launch Liter8 once")
        self.assertEqual(target.read_bytes(), b"patched")
        self.assertEqual(
            (self.work / "patch-records/kernel-restore.json").read_text(),
            "[]\n",
        )

    def test_failed_apply_keeps_target_and_does_not_publish_records(self):
        target = self.work / "kernelcache"
        target.write_bytes(b"previous output")
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
        )

        with patch(
            "liter8_workflow.run",
            side_effect=WorkflowError("pre-image mismatch"),
        ):
            with self.assertRaisesRegex(WorkflowError, "pre-image mismatch"):
                context.apply("kernel", "restore", target, record_name="kernel-restore")

        self.assertEqual(target.read_bytes(), b"previous output")
        self.assertFalse((self.work / "patch-records/kernel-restore.json").exists())

    def test_rootfs_validation_binds_build_and_launchd(self):
        """A mounted DMG is trusted only after build and launchd checks agree."""
        mount = self.root / "rootfs-mount"
        version = mount / "System/Library/CoreServices/SystemVersion.plist"
        launchd = mount / "sbin/launchd"
        launchd_cache = mount / "System/Library/xpc/launchd.plist"
        version.parent.mkdir(parents=True)
        launchd.parent.mkdir(parents=True)
        launchd_cache.parent.mkdir(parents=True)
        version.write_bytes(plistlib.dumps({
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A5390f",
        }))
        launchd.write_bytes(b"reviewed launchd")
        launchd_cache.write_bytes(plistlib.dumps({"LaunchDaemons": {"fixture": {}}}))
        expected = rootfs_workflow.sha256_file(launchd)
        expected_cache = rootfs_workflow.sha256_file(launchd_cache)
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={"OS": "OS.dmg.aea"},
            liter8=self.liter8,
            resources=self.resources,
            product_version="27.0",
            build="24A5390f",
        )

        with patch.dict(os.environ, {
            "LITER8_LAUNCHD_SHA": expected,
            "LITER8_LAUNCHD_CACHE_SHA": expected_cache,
            "LITER8_LAUNCHD_CACHE_DAEMONS": "1",
        }):
            details = rootfs_workflow.validate_rootfs(context, mount)

        self.assertEqual(details["build"], "24A5390f")
        self.assertEqual(details["launchdSHA256"], expected)
        self.assertEqual(details["launchdCacheSHA256"], expected_cache)
        self.assertEqual(details["launchdCacheDaemonCount"], "1")

    def test_rootfs_validation_rejects_another_build(self):
        mount = self.root / "wrong-rootfs"
        version = mount / "System/Library/CoreServices/SystemVersion.plist"
        launchd = mount / "sbin/launchd"
        launchd_cache = mount / "System/Library/xpc/launchd.plist"
        version.parent.mkdir(parents=True)
        launchd.parent.mkdir(parents=True)
        launchd_cache.parent.mkdir(parents=True)
        version.write_bytes(plistlib.dumps({
            "ProductVersion": "27.0",
            "ProductBuildVersion": "another-build",
        }))
        launchd.write_bytes(b"launchd")
        launchd_cache.write_bytes(plistlib.dumps({"LaunchDaemons": {}}))
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
            product_version="27.0",
            build="24A5390f",
        )

        with self.assertRaisesRegex(WorkflowError, "expected 27.0.*24A5390f"):
            rootfs_workflow.validate_rootfs(context, mount)

    def test_rootfs_recognizes_only_aea1_envelopes(self):
        encrypted = self.root / "encrypted.aea"
        plaintext = self.root / "plaintext.dmg"
        encrypted.write_bytes(b"AEA1payload")
        plaintext.write_bytes(b"koly payload")
        self.assertTrue(rootfs_workflow.is_aea_encrypted(encrypted))
        self.assertFalse(rootfs_workflow.is_aea_encrypted(plaintext))
        self.assertEqual(rootfs_workflow.readable_size(3 * 1024**3), "3.0 GiB")

    def test_rootfs_finds_the_automatic_mountpoint_by_image_identity(self):
        """The mount path may change, but it must belong to our cached image."""
        image = self.work / "rootfs/OS.dmg"
        image.parent.mkdir()
        image.touch()
        inventory = [{
            "image-path": str(image),
            "system-entities": [{
                "dev-entry": "/dev/disk42s1",
                "mount-point": "/Volumes/Liter8Fixture",
            }],
        }]
        with patch.object(rootfs_workflow, "mounted_images", return_value=inventory):
            mounted = rootfs_workflow.mountpoint_for_image("hdiutil", image)

        self.assertIsNotNone(mounted)
        self.assertEqual(mounted[1], Path("/Volumes/Liter8Fixture"))

    def test_provision_uses_profile_bound_recorded_rootfs_mountpoint(self):
        mountpoint = self.root / "mounted-rootfs"
        image = self.work / "rootfs/OS.dmg"
        image.parent.mkdir()
        image.touch()
        (image.parent / "rootfs.json").write_text(json.dumps({
            "schema": 1,
            "profileID": "fixture-profile",
            "productVersion": "27.0",
            "build": "24A5390f",
            "launchdSHA256": "reviewed-launchd",
            "launchdCacheSHA256": "reviewed-cache",
            "launchdCacheDaemonCount": "731",
            "image": str(image),
            "mountpoint": str(mountpoint),
        }))
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=self.resources,
            product_version="27.0",
            build="24A5390f",
        )

        rootfs = prepared_rootfs(context, {
            "LITER8_LAUNCHD_SHA": "reviewed-launchd",
            "LITER8_LAUNCHD_CACHE_SHA": "reviewed-cache",
            "LITER8_LAUNCHD_CACHE_DAEMONS": "731",
        })
        self.assertEqual(rootfs, mountpoint.resolve())

    def test_setup_parser_keeps_patch_scope_class_owned(self):
        """The broad methlist sweep must not silently replace the proven class walk."""
        beta = SCRIPTS.parent.parent / "offsets/userland/Setup.pristine"
        release = SCRIPTS.parent.parent / "offsets/24A435/Setup"
        if not beta.is_file() or not release.is_file():
            self.skipTest("local beta-4 and RC Setup research binaries are absent")

        beta_targets = discover_targets(beta.read_bytes())
        release_targets = discover_targets(release.read_bytes())
        self.assertEqual(len(beta_targets), 65)
        self.assertEqual(len(release_targets), 66)
        beta_classes = {target["class"] for target in beta_targets}
        release_classes = {target["class"] for target in release_targets}
        self.assertEqual(release_classes - beta_classes, {"BuddyServicesTermsFlow"})
        self.assertEqual(beta_classes - release_classes, set())

    def test_restore_owns_tss_proxy_lifecycle(self):
        """The restore command must not leave an external proxy running."""
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=SCRIPTS.parent,
        )

        with self.assertRaisesRegex(RuntimeError, "simulated restore failure"):
            with redirect_stdout(io.StringIO()):
                with managed_tss_proxy(context) as url:
                    with urllib.request.urlopen(f"{url}/health") as response:
                        self.assertEqual(response.read(), b"ok\n")
                    pid = int((self.work / "tss-proxy.pid").read_text())
                    os.kill(pid, 0)
                    raise RuntimeError("simulated restore failure")
        self.assertFalse((self.work / "tss-proxy.pid").exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_loopback_tss_startup_does_not_depend_on_reverse_dns(self):
        with patch("socket.getfqdn", side_effect=AssertionError("unexpected DNS lookup")):
            with TSSProxyServer(("127.0.0.1", 0), TSSProxyHandler) as server:
                self.assertEqual(server.server_name, "127.0.0.1")
                self.assertGreater(server.server_port, 0)

    def test_restore_log_paths_are_durable_and_stage_output_is_visible(self):
        context = Context(
            profile_id="fixture-profile",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=SCRIPTS.parent,
        )
        first = restore_log_path(context)
        first.touch()
        second = restore_log_path(context)

        self.assertEqual(first.parent, self.work / "logs")
        self.assertNotEqual(first, second)
        output = io.StringIO()
        with redirect_stdout(output):
            stage(4, "run idevicerestore")
        self.assertIn("RESTORE STAGE 4/5: run idevicerestore", output.getvalue())
        self.assertIn("+" * 72, output.getvalue())

    def test_tss_retry_fields_are_inserted_only_once(self):
        request = (
            b"<?xml version='1.0'?><plist><dict>"
            b"<key>@HostIpAddress</key><string>127.0.0.1</string>"
            b"</dict></plist>"
        )
        modified = inject_euicc(request)
        self.assertEqual(modified.count(b"eUICC,ChipID"), 1)
        self.assertEqual(inject_euicc(modified), modified)

    def test_apticket_is_extracted_from_tss_and_completed_restore_log(self):
        ticket = b"\x30\x06\x16\x04IM4M"
        response_plist = plistlib.dumps({"ApImg4Ticket": ticket})
        response = (
            b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING="
            + quote_from_bytes(response_plist).encode()
        )
        self.assertEqual(ticket_from_tss_response(response), ticket)

        log = self.work / "logs/restore-cfw-fixture.log"
        log.parent.mkdir()
        formatted = " ".join(f"{byte:02x}" for byte in ticket)
        log.write_text(
            "ECID: 1234\n"
            "IPSW Product Build: 24A5390f Major: 24\n"
            "Getting ApNonce in Recovery mode... " + "01 " * 31 + "01\n"
            f'{{\n  "APTicket": <{formatted}>\n}}\n'
            f'{{\n  "APTicket": <{formatted}>\n}}\n'
            "Status: Restore Finished\n"
        )
        self.assertEqual(tickets_from_debug_log(log.read_text()), [ticket])
        output = capture_from_debug_log(log, self.work, profile_id="fixture-profile")
        self.assertEqual(output.read_bytes(), ticket)
        metadata = json.loads((self.work / "apticket.json").read_text())
        self.assertEqual(metadata["ecid"], 1234)
        self.assertEqual(metadata["build"], "24A5390f")
        self.assertEqual(metadata["profileID"], "fixture-profile")
        self.assertEqual(metadata["apNonce"], "01" * 32)

    def test_apticket_rejects_truncated_or_non_im4m_der(self):
        with self.assertRaises(WorkflowError):
            validate_im4m(b"\x30\x06\x16\x04IM")
        with self.assertRaises(WorkflowError):
            validate_im4m(b"\x30\x06\x16\x04NOPE")

    def test_ticket_must_be_explicit(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(WorkflowError):
                ticket_from_environment()

    def test_boot_output_is_replaced_only_at_publish(self):
        destination = self.work / "Ramdisk"
        staging = self.work / "staging"
        (destination).mkdir()
        (destination / "old").write_text("old")
        staging.mkdir()
        (staging / "new").write_text("new")

        publish_directory(staging, destination)

        self.assertFalse((destination / "old").exists())
        self.assertEqual((destination / "new").read_text(), "new")

    def test_sshrd_rejects_unreviewed_payload_before_host_operations(self):
        payloads = self.resources / "payloads"
        payloads.mkdir()
        (payloads / "ssh.tar.gz").write_bytes(b"not the reviewed payload")
        (payloads / "sftp_server_ents.plist").write_text("<plist/>")
        previous = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, self.environment, clear=True):
                context = Context.load()
                with self.assertRaisesRegex(WorkflowError, "SHA-256"):
                    build_sshrd(context, self.work / "ticket", self.work / "rd.img4")
        finally:
            os.chdir(previous)

    def test_bundled_sshrd_payload_is_the_reviewed_archive(self):
        """Keep the checked-in runtime payload tied to its reviewed provenance."""
        payload = SCRIPTS.parent / "payloads" / "ssh.tar.gz"
        self.assertTrue(payload.is_file())
        self.assertEqual(sha256_file(payload), REVIEWED_PAYLOAD_SHA256)

    def test_sshrd_privileged_operation_allows_interactive_sudo(self):
        """The workflow must let sudo display its normal password or Touch ID prompt."""
        with (
            patch.object(sshrd.os, "geteuid", return_value=501),
            patch.object(sshrd, "run") as runner,
        ):
            sshrd.privileged(["/usr/bin/hdiutil", "resize", "fixture.dmg"])

        runner.assert_called_once_with([
            "/usr/bin/sudo",
            "/usr/bin/hdiutil",
            "resize",
            "fixture.dmg",
        ])

    def test_sshrd_does_not_nest_sudo_when_already_root(self):
        """A root caller should execute the host operation directly."""
        with (
            patch.object(sshrd.os, "geteuid", return_value=0),
            patch.object(sshrd, "run") as runner,
        ):
            sshrd.privileged(["/usr/bin/hdiutil", "resize", "fixture.dmg"])

        runner.assert_called_once_with([
            "/usr/bin/hdiutil",
            "resize",
            "fixture.dmg",
        ])

    def test_device_runtime_materializes_reviewed_inputs_and_keeps_outputs(self):
        """Provisioning gets mutable state without editing installed resources."""
        context = Context(
            profile_id="iphone12,1-n104ap-24A5390f",
            work=self.work,
            source=self.source,
            cfw=self.work / "CFW",
            components={},
            liter8=self.liter8,
            resources=SCRIPTS.parent,
        )

        runtime = prepare_runtime(context)
        self.assertEqual(
            sha256_file(runtime / "bootstrap_1900.tar.zst"),
            BOOTSTRAP_SHA256,
        )
        self.assertEqual(sha256_file(runtime / "ssh.tar.gz"), SSHRD_PAYLOAD_SHA256)
        self.assertTrue((runtime.parent / "tools/sshpass").is_symlink())

        # Generated payloads are intentionally resumable across CLI runs.
        generated = runtime / "payload/operator-note"
        generated.parent.mkdir()
        generated.write_text("keep me")
        self.assertEqual(prepare_runtime(context), runtime)
        self.assertEqual(generated.read_text(), "keep me")

    def test_command_runner_passes_curated_environment(self):
        result = run(
            ["/usr/bin/env"],
            capture=True,
            environment={"LITER8_TEST_ENVIRONMENT": "present"},
        )
        self.assertIn("LITER8_TEST_ENVIRONMENT=present", result.stdout.splitlines())

    def test_normal_boot_dropbear_does_not_install_shared_private_keys(self):
        installer = (SCRIPTS.parent / "device/install_dropbear.sh").read_text()
        cache_patcher = (SCRIPTS.parent / "device/patch_launchd_cache.py").read_text()
        self.assertNotIn("|/mnt1/private/etc/dropbear/dropbear_", installer)
        self.assertIn('"bin/sh|/mnt1/bin/sh"', installer)
        self.assertIn('"bin/ls|/mnt1/bin/ls"', installer)
        self.assertIn('"bin/cat|/mnt1/bin/cat"', installer)
        self.assertIn("mount -u -o rw /dev/disk1s1", installer)
        self.assertIn("mount -u -o rw /dev/disk1s2", installer)
        self.assertIn(".liter8-write-test", installer)
        self.assertNotIn('"-R"', cache_patcher)
        self.assertIn('"/private/var/dropbear/dropbear_rsa_host_key"', cache_patcher)
        self.assertIn('"/private/var/dropbear/dropbear_ecdsa_host_key"', cache_patcher)
        self.assertIn('"/private/var/dropbear/dropbear_dss_host_key"', cache_patcher)
        self.assertIn("/mnt2/dropbear", installer)
        self.assertIn("dropbearkey -t '$type' -s '$bits' -f '$key_file'", installer)
        self.assertIn("report_key", installer)
        self.assertIn("$CHMOD 600", installer)
        self.assertIn("closes during key exchange", (DEVICE / "finalize.sh").read_text())

    def test_setup_shell_owns_its_usb_forward_and_reports_transport_failure(self):
        """A refused SSH connection must not be mislabeled as missing zsh."""
        setup = (SCRIPTS.parent / "device/setup_shell.sh").read_text()
        self.assertIn("iproxy 2222 22", setup)
        self.assertIn("cannot reach normal-boot SSH on port 2222", setup)
        self.assertIn("normal-boot SSH disconnected", setup)
        self.assertIn("exit 1", setup)

    def test_finalize_is_guarded_and_uses_the_proven_bootstrap_invocation(self):
        finalizer = (DEVICE / "finalize.sh").read_text()
        runner = (SCRIPTS / "device_provision.py").read_text()
        self.assertIn('NO_PASSWORD_PROMPT=1 /var/jb/bin/sh /var/jb/prep_bootstrap.sh', finalizer)
        self.assertIn("prep_bootstrap.sh.liter8-backup", finalizer)
        self.assertIn(".liter8-system-apps-registered", finalizer)
        self.assertIn("dropbear_ecdsa_host_key", finalizer)
        self.assertIn("container app already exists", finalizer)
        self.assertIn("/var/jb/usr/bin/uicache -a", finalizer)
        self.assertIn('action == "finalize"', runner)

    def test_screentime_override_preserves_unrelated_launchd_state(self):
        path = self.root / "disabled.plist"
        with path.open("wb") as stream:
            plistlib.dump({"com.example.existing": False}, stream, fmt=plistlib.FMT_BINARY)

        with redirect_stdout(io.StringIO()):
            screen_time(path, verify_only=False)
            screen_time(path, verify_only=True)

        with path.open("rb") as stream:
            document = plistlib.load(stream)
        self.assertIs(document["com.example.existing"], False)
        for label in SCREEN_TIME_LABELS:
            self.assertIs(document[label], True)
        self.assertEqual(path.read_bytes()[:8], b"bplist00")

    def test_userland_provisioning_is_wired_into_device_verification(self):
        provisioner = (DEVICE / "sshrd_provision.sh").read_text()
        self.assertIn("ticket setup userland pairing screentime injection", provisioner)
        self.assertIn("mount -u -o rw /dev/disk1s2", provisioner)
        self.assertIn("Data volume NOT writable", provisioner)
        self.assertIn("verify_userland_patch coreauthd", provisioner)
        self.assertIn("verify_userland_patch lockdownd", provisioner)
        self.assertIn("verify_userland_patch remotepairingdeviced", provisioner)
        self.assertIn("deploy_pairing_library", provisioner)
        self.assertIn("deploy_remotepairing_library", provisioner)
        self.assertIn("deploy_coreauth_library", provisioner)
        self.assertIn("deploy_userland_daemon coreauthd", provisioner)
        self.assertIn("if ! wants userland", provisioner)
        self.assertIn(".liter8-pairing-fallback", provisioner)
        self.assertIn('note "l8pair dylib"', provisioner)
        self.assertIn('note "l8remotepairing dylib"', provisioner)
        self.assertIn('note "l8coreauth dylib"', provisioner)
        self.assertIn('note "ScreenTime overrides"', provisioner)
        self.assertIn('note "Setup CodeDirectory/id"', provisioner)
        self.assertIn('note "System /bin/sh"', provisioner)
        self.assertIn('""|*ABSENT*|*MISSING*', provisioner)
        self.assertIn("verify.Setup.orig", provisioner)
        self.assertIn('-I"$setup_identifier"', provisioner)
        self.assertIn("SSH_ATTEMPTS=5", provisioner)
        self.assertIn("liter8-ssh-out.XXXXXX", provisioner)
        self.assertIn("liter8-ssh-put.XXXXXX", provisioner)

    def test_provisioning_help_needs_no_device_environment_or_host_tools(self):
        environment = os.environ.copy()
        for name in (
            "LITER8_LAUNCHD_SHA",
            "LITER8_LAUNCHD_CACHE_SHA",
            "LITER8_LAUNCHD_CACHE_DAEMONS",
            "LITER8_SETUP_METHODS",
        ):
            environment.pop(name, None)
        environment["PATH"] = "/usr/bin:/bin"

        result = subprocess.run(
            [DEVICE / "sshrd_provision.sh", "--list"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("steps: mounts ticket setup userland pairing", result.stdout)
        self.assertIn("coreauthd companion guard", result.stdout)

    def test_pairing_fallback_is_narrow_and_marker_gated(self):
        source = (DEVICE / "pairingfix/l8pair.c").read_text()
        auth_source = (DEVICE / "pairingfix/l8pair_auth.m").read_text()
        builder = (DEVICE / "pairingfix/build.sh").read_text()
        payload_builder = (DEVICE / "fetch_payloads.sh").read_text()
        fixups = (DEVICE / "userland_fixups.py").read_text()
        remotexpc_source = (DEVICE / "remotexpcfix/l8remotepairing.c").read_text()
        remotexpc_builder = (DEVICE / "remotexpcfix/build.sh").read_text()

        self.assertIn("lockdown-identities", source)
        self.assertIn("com.apple.lockdown.pairingkeypair", source)
        self.assertIn("kSecUseSystemKeychain", source)
        self.assertIn("fallback_enabled()", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("DYLD_INTERPOSE(l8_SecItemCopyMatching", source)
        self.assertIn("DYLD_INTERPOSE(l8_SecItemAdd", source)
        self.assertIn("DYLD_INTERPOSE(l8_SecItemDelete", source)
        self.assertIn("kLocationBasedTrustComputerPolicy = 1028", auth_source)
        self.assertIn('strcmp(program, "lockdownd")', auth_source)
        self.assertIn("pairing_fallback_enabled()", auth_source)
        self.assertIn("error.code != -1000", auth_source)
        self.assertIn('@"LocationBasedTrustComputer"', auth_source)
        self.assertIn('@"failed: -3"', auth_source)
        self.assertIn("gOriginalEvaluatePolicy(", auth_source)
        self.assertIn("method_setImplementation", auth_source)

        # Exact 24A446 lockdownd evidence: Copy/Delete carry kSecClassKey, but
        # SecItemAdd relies on the SecKeyRef in kSecValueRef and omits class.
        identity_matcher = source.split(
            "static bool is_pairing_identity_dictionary", 1
        )[1].split("static CFDataRef read_key_data", 1)[0]
        add_hook = source.split("static OSStatus l8_SecItemAdd", 1)[1].split(
            "static OSStatus l8_SecItemDelete", 1
        )[0]
        copy_hook = source.split(
            "static OSStatus l8_SecItemCopyMatching", 1
        )[1].split("static OSStatus l8_SecItemAdd", 1)[0]
        self.assertNotIn("kSecClass", identity_matcher)
        self.assertIn("kSecValueRef", add_hook)
        self.assertIn("item_class != NULL", add_hook)
        self.assertIn("kSecClassKey", copy_hook)

        self.assertIn("-install_name /usr/lib/l8pair.dylib", builder)
        self.assertIn('"$BASE/l8pair_auth.m"', builder)
        self.assertIn("sileo helpers cache injection pairing", payload_builder)
        self.assertIn('"lockdownd": ("/usr/lib/l8pair.dylib"', fixups)

        self.assertIn('strcmp(program, "remotepairingdeviced")', remotexpc_source)
        self.assertIn("fallback_marker_status()", remotexpc_source)
        self.assertIn("options != NULL", remotexpc_source)
        self.assertIn("state != 0", remotexpc_source)
        self.assertIn("formatted = MKBDeviceFormattedForContentProtection()", remotexpc_source)
        self.assertIn("unlocked = MKBDeviceUnlockedSinceBoot()", remotexpc_source)
        self.assertIn("formatted != 0", remotexpc_source)
        self.assertIn("unlocked != 1", remotexpc_source)
        self.assertIn("return 3", remotexpc_source)
        self.assertIn("/usr/lib/.liter8-remotepairing-fallback", remotexpc_source)
        self.assertIn("guard state=%d", remotexpc_source)
        self.assertIn("com.apple.RemotePairing", remotexpc_source)
        self.assertIn("Remote Pairing Identity", remotexpc_source)
        self.assertIn("Remote Pairing Paired Peer", remotexpc_source)
        self.assertIn("Liter8RemotePairingKeychainItems", remotexpc_source)
        self.assertIn("CFPreferencesAppSynchronize", remotexpc_source)
        self.assertIn(
            "DYLD_INTERPOSE(l8_MKBGetDeviceLockState, MKBGetDeviceLockState)",
            remotexpc_source,
        )
        self.assertIn(
            "DYLD_INTERPOSE(l8_SecItemCopyMatching, SecItemCopyMatching)",
            remotexpc_source,
        )
        self.assertIn(
            "DYLD_INTERPOSE(l8_SecItemAdd, SecItemAdd)",
            remotexpc_source,
        )
        self.assertIn(
            "DYLD_INTERPOSE(l8_SecItemUpdate, SecItemUpdate)",
            remotexpc_source,
        )
        self.assertIn(
            "DYLD_INTERPOSE(l8_SecItemDelete, SecItemDelete)",
            remotexpc_source,
        )
        self.assertNotIn("LAContext", remotexpc_source)
        self.assertIn(
            "-install_name /usr/lib/l8remotepairing.dylib",
            remotexpc_builder,
        )
        self.assertIn("-framework Security", remotexpc_builder)
        self.assertIn("exactly five interposers", remotexpc_builder)
        self.assertIn("remotexpcfix/l8remotepairing.dylib", payload_builder)
        self.assertIn('"/usr/lib/l8remotepairing.dylib"', fixups)
        self.assertIn(
            '"remotepairingdeviced.load-l8remotepairing"',
            fixups,
        )

        coreauth_source = (DEVICE / "coreauthfix/l8coreauth.m").read_text()
        self.assertIn("LACDTORatchetSEPStateParser", coreauth_source)
        self.assertIn("ratchetStateFromState:", coreauth_source)
        self.assertIn("kRatchetStateBytes = 0x14b", coreauth_source)
        self.assertIn("length >= kRatchetStateBytes", coreauth_source)
        self.assertIn("method_setImplementation", coreauth_source)
        self.assertIn('dylib_path = "/usr/lib/l8coreauth.dylib"', fixups)

    def test_userland_builder_preserves_identity_and_entitlements(self):
        liter8 = SCRIPTS.parent / ".build/debug/liter8"
        ldid = SCRIPTS.parent / "tools/ldid_macosx_arm64"
        fixtures = SCRIPTS.parent.parent / "offsets/userland"
        if not liter8.is_file() or not ldid.is_file() or not fixtures.is_dir():
            self.skipTest("local beta-4 userland fixture or debug tools are absent")

        expected_records = {"coreauthd": 2, "mobileactivationd": 5, "ctkd": 2}
        for name, count in expected_records.items():
            fixture = fixtures / name
            if not fixture.is_file():
                self.skipTest(f"local beta-4 fixture is absent: {name}")
            output = self.root / f"{name}.patched"
            records = self.root / f"{name}.records.json"
            with redirect_stdout(io.StringIO()):
                build_binary(
                    liter8=liter8,
                    ldid=ldid,
                    plan=name,
                    pristine=fixture,
                    output=output,
                    records=records,
                )

            self.assertEqual(signing_identifier(output), signing_identifier(fixture))
            self.assertEqual(entitlements(ldid, output), entitlements(ldid, fixture))
            self.assertEqual(len(json.loads(records.read_text())), count)

        coreauth_records = json.loads((self.root / "coreauthd.records.json").read_text())
        self.assertEqual(coreauth_records[-1]["id"], "coreauthd.load-l8coreauth")
        self.assertEqual(coreauth_records[-1]["path"], "/usr/lib/l8coreauth.dylib")

    def test_boot_manifest_rejects_wrong_mode_and_modified_artifacts(self):
        fixture_context = self.make_boot_set("restore")

        self.assertEqual(validate_boot_set(fixture_context, "restore"), self.work / "Ramdisk")
        with self.assertRaisesRegex(WorkflowError, "expected normal"):
            validate_boot_set(fixture_context, "normal")

        (self.work / "Ramdisk/iBEC.img4").write_bytes(b"tampered")
        with self.assertRaisesRegex(WorkflowError, "changed after generation"):
            validate_boot_set(fixture_context, "restore")

    def test_ipad_boot_sequence_uses_erase_identity_components(self):
        # The 23H30 j171aap erase identity has these keys and no SPTM/TXM,
        # PMP, or WCH. The boot set must be buildable without those artifacts.
        components = {
            name: f"Firmware/{name}.im4p" for name in (
                "RestoreLogo", "ANE", "AOP", "AVE", "GFX", "ISP",
                "RestoreTrustCache", "SIO", "SEP",
            )
        }
        fixture_context = self.make_boot_set("restore", components, firmware_components=IPAD_BOOT_FIRMWARE)
        sequence = selected_firmware_sequence(components, "restore", IPAD_BOOT_FIRMWARE)
        self.assertEqual(
            [name for name, _, _ in sequence],
            ["RestoreLogo.img4", "ANE.img4", "AOP.img4", "AVE.img4",
             "GFX.img4", "ISP.img4", "RestoreTrustCache.img4", "SIO.img4"],
        )
        self.assertEqual(validate_boot_set(fixture_context, "restore"), self.work / "Ramdisk")
        self.assertFalse(has_txm(components, "restore", IPAD_BOOT_FIRMWARE))

    def test_ipad_normal_boot_uses_static_trust_cache(self):
        components = {
            name: f"Firmware/{name}.im4p" for name in (
                "RestoreLogo", "ANE", "AOP", "AVE", "GFX", "ISP",
                "StaticTrustCache", "RestoreTrustCache", "SIO", "SEP",
            )
        }
        firmware = IPAD_BOOT_FIRMWARE
        normal = [name for name, _, _ in selected_firmware_sequence(components, "normal", firmware, "StaticTrustCache")]
        restore = [name for name, _, _ in selected_firmware_sequence(components, "restore", firmware, "StaticTrustCache")]
        self.assertIn("StaticTrustCache.img4", normal)
        self.assertNotIn("RestoreTrustCache.img4", normal)
        self.assertIn("RestoreTrustCache.img4", restore)
        self.assertNotIn("StaticTrustCache.img4", restore)

    def test_rejects_partial_sptm_txm_boot_chain(self):
        components = {name: name for name, _, _ in PASSTHROUGH_IMG4}
        del components["Ap,SecurePageTableMonitor"]
        components["Ap,RestoreTrustedExecutionMonitor"] = "txm.im4p"
        with self.assertRaisesRegex(WorkflowError, "incomplete restore SPTM/TXM pair"):
            selected_firmware_sequence(components, "restore", IPAD_BOOT_FIRMWARE)

    def test_iphone_boot_preserves_the_complete_firmware_order(self):
        components = {name: name for name, _, _ in PASSTHROUGH_IMG4}
        components["Ap,RestoreTrustedExecutionMonitor"] = "txm.im4p"
        sequence = selected_firmware_sequence(components, "restore")
        self.assertEqual([name for name, _, _ in sequence], [
            "RestoreLogo.img4", "ANE.img4", "AOP.img4", "AVE.img4", "SPTM.img4",
            "TXM.img4", "GFX.img4", "ISP.img4", "PMP.img4", "RestoreTrustCache.img4",
            "SIO.img4", "WCH.img4",
        ])

    def test_missing_iphone_peripheral_is_not_silently_omitted(self):
        for missing in DEFAULT_BOOT_FIRMWARE:
            components = {name: name for name, _, _ in PASSTHROUGH_IMG4}
            components["Ap,RestoreTrustedExecutionMonitor"] = "txm.im4p"
            del components[missing]
            with self.subTest(component=missing), self.assertRaises(WorkflowError):
                selected_firmware_sequence(components, "restore")

    def test_absent_monitor_pair_requires_explicit_profile_policy(self):
        components = {name: name for name in IPAD_BOOT_FIRMWARE}
        components["RestoreTrustCache"] = "cache.im4p"
        with self.assertRaisesRegex(WorkflowError, "disagrees with the boot profile"):
            selected_firmware_sequence(components, "restore")

    def test_missing_static_cache_is_not_replaced_by_restore_cache(self):
        components = {name: name for name in IPAD_BOOT_FIRMWARE}
        components["RestoreTrustCache"] = "cache.im4p"
        with self.assertRaisesRegex(WorkflowError, "StaticTrustCache"):
            selected_firmware_sequence(components, "normal", IPAD_BOOT_FIRMWARE, "StaticTrustCache")

    def test_unknown_boot_mode_fails_before_upload(self):
        with self.assertRaisesRegex(WorkflowError, "unknown boot mode"):
            selected_firmware_sequence({}, "unknown")

    def test_normal_boot_manifest_records_the_public_kernel_plan(self):
        fixture_context = self.make_boot_set("normal", kernel_plan="boot-public")
        manifest = json.loads((self.work / "Ramdisk/liter8-boot.json").read_text())
        self.assertEqual(manifest["kernelPlan"], "boot-public")
        self.assertEqual(validate_boot_set(fixture_context, "normal"), self.work / "Ramdisk")

    def test_restore_boot_sequence_sends_ramdisk_before_devicetree(self):
        fixture_context = self.make_boot_set("restore")
        with (
            patch("device_boot.Context.load", return_value=fixture_context),
            patch("device_boot.require_executable", side_effect=["/custom/irecovery", "/tools/usbliter8ctl"]),
            patch("device_boot.run") as run_command,
            patch("device_boot.subprocess.run", return_value=type("Result", (), {"returncode": 0})()) as direct_command,
            patch("device_boot.time.sleep"),
            patch.dict(os.environ, {"LITER8_FW_ACTION": "boot-rd", "LITER8_IRECOVERY": "/custom/irecovery"}),
        ):
            # Progress is useful interactively but should not obscure the test
            # runner's own result stream.
            with redirect_stdout(io.StringIO()):
                boot_device()

        commands = [call.args[0] for call in run_command.call_args_list]
        ramdisk = ["/custom/irecovery", "-f", self.work / "Ramdisk/RestoreRamdisk.img4"]
        devicetree = ["/custom/irecovery", "-f", self.work / "Ramdisk/DeviceTree.img4"]
        self.assertLess(commands.index(ramdisk), commands.index(devicetree))
        self.assertEqual(
            direct_command.call_args_list[-1].args[0],
            ["/custom/irecovery", "-c", "bootx"],
        )

    def make_boot_set(self, mode, components=None, *, kernel_plan=None,
                      firmware_components=DEFAULT_BOOT_FIRMWARE, normal_trust_cache="RestoreTrustCache"):
        staging = self.work / "boot-staging"
        staging.mkdir()
        if components is None:
            components = {name: name for name, _, _ in PASSTHROUGH_IMG4}
            components[
                "Ap,TrustedExecutionMonitor" if mode == "normal"
                else "Ap,RestoreTrustedExecutionMonitor"
            ] = "txm.im4p"
        names = {
            "iBSS.raw", "iBEC.img4", "DeviceTree.img4", "SEP.img4", "Kernelcache.img4",
            *(name for name, _, _ in selected_firmware_sequence(components, mode, firmware_components, normal_trust_cache)),
        }
        if mode == "restore":
            names.add("RestoreRamdisk.img4")
        for name in names:
            (staging / name).write_bytes(f"fixture:{name}".encode())

        # The real Context has many operations, but the manifest boundary only
        # needs the selected profile and work root.
        fixture_context = type("FixtureContext", (), {
            "profile_id": "fixture-profile",
            "work": self.work,
            "components": components,
            "boot_firmware_components": firmware_components,
            "normal_trust_cache": normal_trust_cache,
        })()
        write_boot_manifest(fixture_context, staging, mode, kernel_plan=kernel_plan)
        publish_directory(staging, self.work / "Ramdisk")
        return fixture_context


class MeasureGuardsTests(unittest.TestCase):
    """`survey --guards` turns an extracted IPSW into a profile to paste.

    The decrypt and mount are macOS tools on an 8 GB image, so these cover the
    parts that decide what the printed profile says.
    """

    @staticmethod
    def manifest(identities):
        return {
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A437",
            "SupportedProductTypes": ["iPhone12,3", "iPhone12,5"],
            "BuildIdentities": identities,
        }

    @staticmethod
    def identity(device_class, board, product, behavior="Erase", os_path="OS.dmg.aea"):
        return {
            "ApBoardID": board,
            "ApChipID": "0x8030",
            "Ap,ProductType": product,
            "Info": {"DeviceClass": device_class, "RestoreBehavior": behavior},
            "Manifest": {"OS": {"Info": {"Path": os_path}}},
        }

    def test_boards_deduplicates_each_board(self):
        # Erase and Update are separate identities for the same hardware.
        manifest = self.manifest([
            self.identity("d421ap", "0x06", "iPhone12,3"),
            self.identity("d421ap", "0x06", "iPhone12,3", behavior="Update"),
            self.identity("d431ap", "0x02", "iPhone12,5"),
        ])
        found = measure_guards.boards(manifest)
        self.assertEqual(
            sorted(b["deviceClass"] for b in found), ["d421ap", "d431ap"]
        )
        self.assertEqual(sorted(b["boardID"] for b in found), ["0x02", "0x06"])

    def test_boards_ignores_non_erase_identities(self):
        manifest = self.manifest([
            self.identity("d421ap", "0x06", "iPhone12,3", behavior="Update"),
        ])
        self.assertEqual(measure_guards.boards(manifest), [])

    def test_product_type_comes_from_the_build_identity(self):
        # SupportedProductTypes lists both, so only Ap,ProductType can say
        # which board is which.
        manifest = self.manifest([
            self.identity("d421ap", "0x06", "iPhone12,3"),
            self.identity("d431ap", "0x02", "iPhone12,5"),
        ])
        self.assertEqual(
            measure_guards.product_type_for(manifest, "d421ap"), "iPhone12,3"
        )
        self.assertEqual(
            measure_guards.product_type_for(manifest, "d431ap"), "iPhone12,5"
        )

    def test_product_type_refuses_an_unknown_board(self):
        manifest = self.manifest([self.identity("d421ap", "0x06", "iPhone12,3")])
        with self.assertRaises(WorkflowError):
            measure_guards.product_type_for(manifest, "n104ap")

    def test_emit_prints_one_profile_per_board_sharing_the_guards(self):
        manifest = self.manifest([
            self.identity("d421ap", "0x06", "iPhone12,3"),
            self.identity("d431ap", "0x02", "iPhone12,5"),
        ])
        guards = {
            "launchdSHA256": "a" * 64,
            "launchdCacheSHA256": "b" * 64,
            "launchdCacheDaemonCount": 729,
            "setupControllerMethodCount": 66,
        }
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            measure_guards.emit(manifest, Path("/x/iPhone12,3,iPhone12,5_27.0_24A437_Restore"), guards)
        output = buffer.getvalue()

        self.assertEqual(output.count("DeviceWorkflowProfile("), 2)
        self.assertIn('id: "iphone12,3-d421ap-24A437"', output)
        self.assertIn('id: "iphone12,5-d431ap-24A437"', output)
        self.assertIn("boardID: 0x06", output)
        self.assertIn("boardID: 0x02", output)
        # One root filesystem serves both boards, so the guards repeat.
        self.assertEqual(output.count(f'launchdCacheSHA256: "{"b" * 64}"'), 2)
        self.assertEqual(output.count("launchdCacheDaemonCount: 729"), 2)
        # Neither of these is measurable from the firmware files.
        self.assertEqual(output.count("validationState: .experimental"), 2)
        self.assertEqual(output.count("normalIBSSAdditionalPlans: []"), 2)
        self.assertIn(
            'extractedDirectoryName: "iPhone12,3,iPhone12,5_27.0_24A437_Restore"', output
        )

    def test_measure_reads_the_launchd_guards_off_a_mount(self):
        with tempfile.TemporaryDirectory() as scratch:
            mount = Path(scratch)
            (mount / "sbin").mkdir()
            (mount / "System/Library/xpc").mkdir(parents=True)
            (mount / "Applications/Setup.app").mkdir(parents=True)
            (mount / "sbin/launchd").write_bytes(b"launchd")
            cache = {"LaunchDaemons": {f"d{i}": {"Label": f"l{i}"} for i in range(3)}}
            (mount / "System/Library/xpc/launchd.plist").write_bytes(plistlib.dumps(cache))
            (mount / "Applications/Setup.app/Setup").write_bytes(b"setup")

            with patch.object(measure_guards, "setup_controller_count", return_value=66):
                guards = measure_guards.measure(mount)

            self.assertEqual(
                guards["launchdSHA256"], hashlib.sha256(b"launchd").hexdigest()
            )
            self.assertEqual(guards["launchdCacheDaemonCount"], 3)
            self.assertEqual(guards["setupControllerMethodCount"], 66)

    def test_measure_names_the_file_a_root_filesystem_is_missing(self):
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(WorkflowError) as raised:
                measure_guards.measure(Path(scratch))
            self.assertIn("sbin/launchd", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
