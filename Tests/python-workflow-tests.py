#!/usr/bin/env python3
"""Focused tests for the generic Python/Swift workflow boundary."""

import json
import hashlib
import io
import os
import plistlib
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
from liter8_workflow import Context, WorkflowError, run  # noqa: E402
from boot_artifacts import (  # noqa: E402
    publish_directory,
    ticket_from_environment,
    write_boot_manifest,
)
from device_boot import FIRMWARE_SEQUENCE, boot as boot_device, validate_boot_set  # noqa: E402
from device_provision import (  # noqa: E402
    BOOTSTRAP_SHA256,
    SSHRD_PAYLOAD_SHA256,
    prepared_rootfs,
    prepare_runtime,
)
import sshrd  # noqa: E402
from sshrd import REVIEWED_PAYLOAD_SHA256, build_sshrd, sha256_file  # noqa: E402
from restore_cfw import managed_tss_proxy, restore_log_path, stage  # noqa: E402
from tss_proxy import inject_euicc  # noqa: E402
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
            "schema": 1,
            "profileID": "fixture-profile",
            "sourceRoot": str(self.source),
            "components": {"iBSS": "Firmware/dfu/iBSS.im4p"},
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
        finally:
            os.chdir(previous)

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
            if arguments[1] == "resolve":
                return type("Result", (), {"stdout": "[]"})()
            applied_output = Path(arguments[-1])
            applied_output.write_bytes(target.read_bytes())
            return type("Result", (), {"stdout": ""})()

        with patch("liter8_workflow.run", side_effect=fake_run):
            context.apply("devicetree", "normal", target, record_name="devicetree")

        self.assertIsNotNone(applied_output)
        self.assertTrue(applied_output.name.startswith(".DeviceTree.im4p.liter8-"))
        self.assertFalse(applied_output.name.startswith(".."))

    def test_rootfs_validation_binds_build_and_launchd(self):
        """A mounted DMG is trusted only after build and launchd checks agree."""
        mount = self.root / "rootfs-mount"
        version = mount / "System/Library/CoreServices/SystemVersion.plist"
        launchd = mount / "sbin/launchd"
        version.parent.mkdir(parents=True)
        launchd.parent.mkdir(parents=True)
        version.write_bytes(plistlib.dumps({
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A5390f",
        }))
        launchd.write_bytes(b"reviewed launchd")
        expected = rootfs_workflow.sha256_file(launchd)
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

        with patch.dict(os.environ, {"LITER8_LAUNCHD_SHA": expected}):
            details = rootfs_workflow.validate_rootfs(context, mount)

        self.assertEqual(details["build"], "24A5390f")
        self.assertEqual(details["launchdSHA256"], expected)

    def test_rootfs_validation_rejects_another_build(self):
        mount = self.root / "wrong-rootfs"
        version = mount / "System/Library/CoreServices/SystemVersion.plist"
        launchd = mount / "sbin/launchd"
        version.parent.mkdir(parents=True)
        launchd.parent.mkdir(parents=True)
        version.write_bytes(plistlib.dumps({
            "ProductVersion": "27.0",
            "ProductBuildVersion": "another-build",
        }))
        launchd.write_bytes(b"launchd")
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

        rootfs = prepared_rootfs(context, {"LITER8_LAUNCHD_SHA": "reviewed-launchd"})
        self.assertEqual(rootfs, mountpoint.resolve())

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
        self.assertIn("ticket setup userland screentime injection", provisioner)
        self.assertIn("mount -u -o rw /dev/disk1s2", provisioner)
        self.assertIn("Data volume NOT writable", provisioner)
        self.assertIn("verify_userland_patch coreauthd", provisioner)
        self.assertIn('note "ScreenTime overrides"', provisioner)
        self.assertIn('note "Setup CodeDirectory/id"', provisioner)
        self.assertIn('note "System /bin/sh"', provisioner)
        self.assertIn('""|*ABSENT*|*MISSING*', provisioner)
        self.assertIn("verify.Setup.orig", provisioner)
        self.assertIn('-I"$setup_identifier"', provisioner)

    def test_userland_builder_preserves_identity_and_entitlements(self):
        liter8 = SCRIPTS.parent / ".build/debug/liter8"
        ldid = SCRIPTS.parent / "tools/ldid_macosx_arm64"
        fixtures = SCRIPTS.parent.parent / "offsets/userland"
        if not liter8.is_file() or not ldid.is_file() or not fixtures.is_dir():
            self.skipTest("local beta-4 userland fixture or debug tools are absent")

        expected_records = {"coreauthd": 1, "mobileactivationd": 5, "ctkd": 2}
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

        # This exact artifact was deployed successfully in the earlier beta-4
        # research, so the orchestration must continue reproducing it.
        coreauth_digest = hashlib.sha256((self.root / "coreauthd.patched").read_bytes()).hexdigest()
        self.assertEqual(
            coreauth_digest,
            "51531edb37ebef37c23d4ce9127e61e2fa1908c408f02de074958a34ee892a7d",
        )

    def test_boot_manifest_rejects_wrong_mode_and_modified_artifacts(self):
        fixture_context = self.make_boot_set("restore")

        self.assertEqual(validate_boot_set(fixture_context, "restore"), self.work / "Ramdisk")
        with self.assertRaisesRegex(WorkflowError, "expected normal"):
            validate_boot_set(fixture_context, "normal")

        (self.work / "Ramdisk/iBEC.img4").write_bytes(b"tampered")
        with self.assertRaisesRegex(WorkflowError, "changed after generation"):
            validate_boot_set(fixture_context, "restore")

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

    def make_boot_set(self, mode):
        staging = self.work / "boot-staging"
        staging.mkdir()
        names = {
            "iBSS.raw", "iBEC.img4", "DeviceTree.img4", "SEP.img4", "Kernelcache.img4",
            *(name for name, _, _ in FIRMWARE_SEQUENCE),
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
        })()
        write_boot_manifest(fixture_context, staging, mode)
        publish_directory(staging, self.work / "Ramdisk")
        return fixture_context


if __name__ == "__main__":
    unittest.main()
