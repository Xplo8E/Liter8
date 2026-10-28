# iPad 8 (`j171aap`) on iPadOS 26.7.1 `23H30`

Experimental. On a real iPad 8 Wi-Fi the CFW erase restore completes
(`Status: Restore Finished`) and the SSH ramdisk boots with SSH, reporting
`PATCHED_ARM64_T8020`. Provisioning then completed and a normal SEP-less boot
with the 123-record `boot-jit` kernel reached the UI with SSH on the same
iPad11,6 (fixture `kernel-boot-jit-j171aap-23H30.json`). There is no
repeat-boot record yet, so the profile stays `.experimental` and every `fw`
command needs `--experimental`.

## Why this is not an ordinary port

Every other profile is an A13 on iOS 27. This one changes the SoC and the OS
family, and keeps the same usbliter8 transport.

| | iPhone 11 (`n104ap`) | iPad 8 Wi-Fi (`j171aap`) |
| --- | --- | --- |
| SoC | A13 `T8030` | A12 `T8020` (`0x8020`, board `0x24`) |
| OS | iOS 27, XNU 13432 | iPadOS 26.7.1, XNU 12377 |
| Kernel | `kernelcache.release.iphone12b` | `kernelcache.release.ipad11b` |
| SPTM / TXM | present | absent |
| Firmware also absent | | PMP, WCH |
| Normal boot trust cache | RestoreTrustCache | StaticTrustCache |
| Preboot volume | `disk1s6` | `disk1s5` (`disk1s6` is Update) |
| launchd load-command slack | 48 bytes | 40 bytes |

The Cellular board (`j172aap`, board `0x26`) shares the kernelcache, so the
kernel profile lists it, but there is no workflow profile for it.

## What had to change

Generic changes, each a no-op for the existing profiles:

- **IM4P compression.** The A12 iBoot rejects the uncompressed images the
  n104 recipe writes (tried with each trust cache), so patched images keep
  their shipped compression. For LZFSE that only works with the restricted
  encoder (algorithm `0x891`): generic LZFSE (`0x801`) round-trips on macOS
  and fails in iBoot with `0x40040028`. Selected per profile with
  `DeviceBootPlan.preservesIM4PCompression`.
- **PAYP.** The kernel's PAYP DER header is eight bytes here, not ten, so it is
  now copied as a whole DER child.
- **Kernel identity.** The SoC token is read from the version string instead of
  assuming `T8030`.
- **Firmware set.** Boot, SSHRD and CFW recipes send what the BuildManifest
  identity has, patch TXM only with a complete SPTM/TXM pair, and use
  StaticTrustCache for normal boot when the profile asks for it.
- **Preboot.** Selected by APFS role through `ioreg` in SSHRD.
- **launchd hook.** Installed as `/usr/lib/lhook`, which fits 40 bytes.
- **Valeria.** Its code cave follows the scoped Sandbox shim's predecessor,
  which this kernel lacks, so the profile omits it from boot-public. It is
  AirPlay/QuickTime related and not needed to boot.
- **Exception port.** The enforcement-byte resolver was written for 27.x
  kernels and has not been ported to xnu-12377, so the profile omits it from
  boot-jit (`KernelExceptionPortResolver.compositeRecords`). The standalone
  `kernel exception-port` plan still fails on this kernel, and `survey`
  reports both omitted families as unused rather than as porting failures.
- **Cellular.** iPad11,6 has no modem. The workflow profile sets
  `hasBaseband: false`, so provisioning leaves out the `cellular` step (whose
  CommCenter resolver targets the iOS 27 iPhone builds), refuses it when named
  explicitly, and `verify` stops expecting its patch, dylib and marker.

Resolvers extended for this build:

| Plan | 23H30 | Notes |
| --- | --- | --- |
| `kernel ppl-trust-cache` | 1 record | New. Without it, modified `restored_external` failed to exec (`OS_REASON_EXEC`) and the restore timed out before ASR. Helper at `0x324da20`, result `0x324da64`, trust-level-9 caller `0x324d5d4`. Matches PongoOS `031e5cc`. |
| `kernel restore` | 21 records | 20 + PPL |
| `kernel credential-manager` | 50 records, 25 entries | `updateAnalytics` has no distinct entry, entries are not in address order |
| `kernel sandbox-public` | 11 records | The wider `sandbox` plan has no cave for its scoped shim on this kernel |
| `kernel boot-public` | 118 records | 117 + PPL, Valeria omitted |
| `kernel boot-jit` | 123 records | boot-public + the 5 T8020 code-signing-invalid records (`ppl-allow-invalid`, `vm-fault-cs-bypass`, `vm-map-protect`); exception-port omitted |
| `iboot ibss-bootargs` | resolves at `0x28828` | destination is `SUB X0,X29,#imm` |
| `iboot ibec-restore` | 6 records | nonce-cache address built in a BL leaf |
| `userland mobileactivationd` | 5 records | one-entry dictionary fallback |
| `userland asr` | 1 record | |
| `iboot ibss-skip-display-init` | no candidate | not in the boot plan |

All of these are bound by exact-build fixtures in `fixtures/23H30/j171aap`.
The XCTests that check them need private copies of the clean binaries under
`$LITER8_FIXTURE_ROOT/offsets/23H30/`: `kernelcache`, `kernelcache.im4p`,
`iBEC.raw`, `mobileactivationd`, `asr`.

iBSS and iBEC ship unencrypted on this build (LZFSE, no KBAG) and decompress to
identical images, so the iBoot resolvers run host side.

Pre-boot guards, measured from the mounted `23H30` System volume:

| Guard | Value |
| --- | --- |
| `launchdSHA256` | `1b37dae048542729a622a1a3f4b77ec8829d32e918f0d6a0c0c037f32d9e84b1` |
| `launchdCacheSHA256` | `af9183685525a0833fea7a16c7a81b3f85e14372ea33d49f3e1ec6ab1a90ca4f` |
| `launchdCacheDaemonCount` | 672 |
| `setupControllerMethodCount` | 58 |

## Running it

Same sequence as the iPhone 11, from `iPad_10.2_2020_26.7.1_23H30_Restore.ipsw`,
with `--experimental` on every `fw` command. Apple has to still be signing
`23H30` for `restore-cfw`.

With only Command Line Tools installed, point `LITER8_IOS_SDK` at an unpacked
iPhoneOS SDK before `fw provision` so the device helpers can build.

```sh
export WORK_DIR="$PWD/.liter8-ipad8-23H30"
B=.build/release/liter8

$B fw prepare --experimental --file /path/to/iPad_10.2_2020_26.7.1_23H30_Restore.ipsw
$B fw make-cfw --experimental
$B fw restore-cfw --experimental      # erase restore, wipes the iPad

$B fw get-rd --experimental
$B fw boot-rd --experimental

$B fw bootstrap --experimental
$B fw prepare-rootfs --experimental
$B fw provision --experimental
$B fw unmount-rootfs --experimental

$B fw get-boot --experimental
$B fw boot --experimental
```

## Open

- Repeat boot of the normal SEP-less boot.
- Apps that register an `EXCEPTION_DEFAULT` handler (crash SDKs) can be killed
  as platform binaries, because the exception-port byte is not patched here.
- Binaries signed with `get-task-allow` or `task_for_pid-allow` are killed at
  exec by PPL on this boot. That includes the packaged
  `device/launchctl/launchctl`, which carries `task_for_pid-allow`; re-signing
  it without that one entitlement was measured to restore `version`, `print`,
  `kickstart` and `bootout` on the iPad, but the shared binary is not changed
  here because the iPhone profiles use it too.
- Whether the analytics path left unpatched by the 25-entry ACM roster matters.
- The scoped Sandbox shim and Valeria need a new cave on this kernel.
- A workflow profile for the Cellular board.
