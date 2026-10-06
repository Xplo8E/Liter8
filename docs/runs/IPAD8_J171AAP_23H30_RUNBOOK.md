# iPad 8 Wi-Fi / j171aap / 23H30 runbook

The profile is experimental. The original 2026-10-02 run note reports CFW
restore completion and working SSHRD SSH. Normal iPadOS boot, finalization
and repeat boot were not demonstrated. These are prior observations; the
upstream-integrated branch needs a fresh device run.

| Stage | Prior recorded evidence |
| --- | --- |
| CFW / restore | First attempt, `restore-cfw-20261002-221148.log`, timed out before ASR because modified restored_external could not execute. After the PPL trust-cache correction, `restore-cfw-20261002-222207.log` recorded `Status: Restore Finished`, exit 0. |
| SSHRD | Corrected kernel reported PATCHED_ARM64_T8020 over SSH. |
| Provisioning | System disk1s1, Data disk1s2, Preboot disk1s5, Update disk1s6. Hook byte-diff and signature checks passed; provisioning completion was not recorded. |
| Normal boot / finalization | Unconfirmed. |

The logs and Apple binaries are not in this repository. The original build
used an external iOS SDK (Theos iPhoneOS16.5.sdk, commit
`0222fd5413cf4b9af096f37b4621afa2688572f7`) with Command Line Tools, and could
not run XCTest. Use full Xcode with its iPhoneOS SDK for the current workflow;
helper SDK overrides from the early port are not included in the PR.

## Prerequisites

Build with `make setup && make release` on macOS. Use the existing usbliter8
transport for j171a/T8020, the exact 26.7.1 / 23H30 IPSW and a compatible
irecovery on PATH (or override it with `--irecovery`). Apple must still sign
23H30 for a new restore ticket. Keep tickets, extracted firmware and raw logs
outside version control.

Run `make check` first, then verify the exact-build fixture set with private
binaries. The [port note](../plans/IPAD8_26_7_1_PORT.md) lists the oracles and
unverified patch families.

## Sequence

`restore-cfw` performs an erase restore and removes all data from the target
IPad. Check build, board and work directory before running it. DFU transitions
are performed by the device operator; this runbook does not run them remotely.

```sh
export WORK_DIR="$PWD/.liter8-ipad8-23H30"
export IPSW_FILE="/path/to/iPad_10.2_2020_26.7.1_23H30_Restore.ipsw"
B=.build/release/liter8

$B fw prepare --experimental --file "$IPSW_FILE"
$B fw make-cfw --experimental

# Device in pwn DFU. Erase restore.
$B fw restore-cfw --experimental

# Back in pwn DFU; build and boot SSHRD.
$B fw get-rd --experimental
$B fw boot-rd --experimental

# Inspect each check result before advancing.
$B fw bootstrap --experimental --check
$B fw bootstrap --experimental
$B fw prepare-rootfs --experimental
$B fw provision --experimental --check
$B fw provision --experimental
$B fw unmount-rootfs --experimental

# Back in pwn DFU; experimental normal boot.
$B fw get-boot --experimental
$B fw boot --experimental

# Only after SSH into booted iPadOS works.
$B fw finalize --experimental --check
$B fw finalize --experimental
$B fw finalize --experimental --check
```

Record artifact hashes, restore exit status, SSHRD identity, mounts,
provisioning checks, visible normal boot, finalization and repeat-boot health
separately. Strip ECIDs, serial numbers, tickets, keys and network credentials
before sharing logs. Promote to reviewed only after the complete sequence is
repeatable. The Cellular j172aap board is not enabled by this workflow.
