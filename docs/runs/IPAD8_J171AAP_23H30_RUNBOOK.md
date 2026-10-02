# iPad 8 (j171aap, iPadOS 26.7.1 / 23H30) — runbook

The profile remains experimental. CFW restore completed successfully and SSHRD
SSH works on the iPad. Provisioning is running; normal SEP-less iOS boot is
not yet demonstrated.

The kernelcache rejection was an iBoot LZFSE compatibility error, fixed in
`FirmwareArtifact` using compression/decompression algorithm `0x891`.
Kernel and launchd startup now work. The first corrected CFW attempt failed
to start modified `restored_external` and timed out before ASR. Its log is
`logs/restore-cfw-20261002-221148.log`; no system-image write began.

The missing T8020 PPL loaded-trust-cache decision has now been added to
`kernel restore` and therefore to `boot-public`. It is one guarded instruction,
with an exact-build fixture and independently checked trust-level-9 caller.
The corrected CFW completed ASR and the full restore (`Status: Restore Finished`,
exit 0). Its log is `logs/restore-cfw-20261002-222207.log`. The prior 117 boot
records are unchanged.

SSHRD is the provisioning step after CFW restore, not proof of jailbreak.
`get-rd` now builds successfully after fixing terminal ownership and writable
image creation. The first live run lacked the PPL patch and had no SSH; the
corrected run reports PATCHED_ARM64_T8020 over SSH. System is disk1s1, Data
is disk1s2, and Preboot is disk1s5 (disk1s6 is Update). Provisioning now reads
APFS roles from ioreg instead of assuming the iPhone partition number.

The 23H30 launchd has 40 bytes of load-command padding. Its weak dependency
uses `/usr/lib/lhook` (40-byte command), with matching install name and device
path. Byte-diff and code-signature checks pass. On a Mac with only Command Line
Tools, set `LITER8_IOS_SDK` to an unpacked iPhoneOS SDK before provisioning. This
run uses Theos iPhoneOS16.5.sdk at commit
`0222fd5413cf4b9af096f37b4621afa2688572f7`; all required local helpers built.

`restore-cfw` uses an erase restore and wipes the iPad. The user has explicitly
authorized that operation for this run. Do not repeat approval prompts for retries.

## Prerequisites

- Built Liter8: `make setup && make release` → `.build/release/liter8`.
- An explicit `irecovery` binary passed with `--irecovery` on every boot
  command. The first live normal-boot test used Homebrew's binary.
- The user's usbliter8 hardware transport, prepared to boot a raw iBSS on
  **j171a/T8020**. Liter8 invokes `usbliter8ctl`.
- The IPSW: `iPad_10.2_2020_26.7.1_23H30_Restore.ipsw`.
- A signing window: `restore-cfw` captures a live APTicket, so Apple must still
  be signing 23H30 at restore time.

## Gate — all must be true before `restore-cfw`

1. Host-side patch plans resolve and their exact-build fixtures verify:
   ```sh
   .build/release/liter8 resolve kernel restore      <kernelcache>
   .build/release/liter8 resolve kernel boot-public  <kernelcache>
   .build/release/liter8 resolve iboot  ibec-restore  <iBEC>
   ```
2. The operator has a valid ticket for this device/build and has reviewed the
   untested restore risk. Keep `ipad11,6-j171aap-23H30` experimental through
   the first complete device run.

## Command sequence (for when the gate passes)

Every `fw` command needs `--experimental` while the profile is experimental.

```sh
export WORK_DIR="$PWD/.liter8-ipad8-23H30"
export IPSW_FILE="/Users/ruslan/Downloads/iPad_10.2_2020_26.7.1_23H30_Restore.ipsw"
B=.build/release/liter8
IREC=/path/to/project/irecovery

# 1. Prepare — extracts the IPSW, selects the j171aap profile.
#    VERIFIED HOST-SIDE on the attached IPSW.
$B fw prepare --experimental --file "$IPSW_FILE"

# 2. Build the CFW.
#    VERIFIED HOST-SIDE, including restore-ramdisk and artifact hashes.
$B fw make-cfw --experimental

# 3. Restore (DESTRUCTIVE erase). Device in pwn DFU. The first live attempt
#    stopped before ASR and did not install the CFW.
$B fw restore-cfw --experimental

# 4. SSH ramdisk. Device back in pwn DFU.
$B fw get-rd   --experimental
$B fw boot-rd  --experimental --irecovery "$IREC"

# 5. Provision (in SSHRD). iOS 26 uses Cryptex1 volumes — provisioning may need
#    changes beyond the n104 path; validate carefully.
$B fw bootstrap --experimental --check
$B fw bootstrap --experimental
$B fw prepare-rootfs  --experimental
$B fw provision --experimental --check
$B fw provision --experimental
$B fw unmount-rootfs  --experimental

# 6. Normal boot. Device in pwn DFU.
$B fw get-boot --experimental
$B fw boot     --experimental --irecovery "$IREC"

# 7. Finalize (once SSH into booted iOS works).
$B fw finalize --experimental --check
$B fw finalize --experimental
$B fw finalize --experimental --check
```

The boot builder and sender now use the selected BuildManifest component set.
For the attached `j171aap` erase identity, the firmware stage contains
RestoreLogo, ANE, AOP, AVE, GFX, ISP, RestoreTrustCache, and SIO for restore;
normal boot selects StaticTrustCache instead. TXM patching
in the CFW and SSHRD paths is also conditional on an SPTM/TXM manifest pair.
Restore USB and SSHRD are confirmed with the PPL correction. Usable normal
iOS remains to be established. `CFW-iBSS.raw` now lives outside `Ramdisk`, so `get-boot`
cannot replace the restore iBSS used by `restore-cfw`.

## To finish the port

Tracked in [../plans/IPAD8_26_7_1_PORT.md](../plans/IPAD8_26_7_1_PORT.md):

1. Capture a live ticket and generate ticketed SSHRD and normal boot artifacts.
2. Run the usbliter8 → iBSS → iBEC transition on the iPad and collect logs.
3. Validate restore, SSHRD, Cryptex1 provisioning, and normal boot on device.
4. Review any failed patch against the resulting device logs before changing
   the experimental profile; promote it only after a repeatable device boot.
