# Normal boot investigation handoff

Target: iPhone12,1 / n104ap, iOS 27 beta 4 (`24A5390f`).

## Confirmed before normal boot

- The CFW restore finished successfully.
- The restore-bound APTicket was captured and verified.
- SSHRD booted and was reachable even though its panel stayed black.
- Bootstrap installation and full SSHRD provisioning passed their on-device
  verification, including the launchd cache, Dropbear, Sileo, Setup patch,
  System applications and local APTicket.
- The normal boot set was generated and verified from the same work directory.

## Current observation

`liter8 fw boot` successfully sent iBSS, iBEC, every firmware component,
DeviceTree, SEP and the kernelcache, then issued `bootx`. The phone displayed
the sky-blue background, Apple logo and verbose boot text during the early
handoff. It later became black and disappeared from USB.

After waiting, the corrected `liter8 fw setup-shell --check` started its own
`iproxy` but could not reach normal-boot SSH on port 2222. `idevice_id -l`
returned no device and `irecovery -q` could not connect. No further device
mutation was performed.

## Second normal-boot diagnosis

After deploying the daemon and ScreenTime fixes, a fresh SSHRD collection was
saved under `.liter8/diagnostics/normal-boot-20260913-074328`. The earlier
`coreauthd` failure is gone: the new stackshot contains patched `coreauthd` and
`mobileactivationd` processes running normally.

This boot failed for two separate provisioning regressions:

- SpringBoard launched three times and deliberately aborted each time because
  `posix_spawn(/Applications/Setup.app/Setup)` returned `0x55` (`BADEXEC`). We
  had changed Setup's instructions but left its original CodeDirectory in the
  Mach-O, so launchd correctly rejected the modified executable. The provisioner
  now rebuilds from `Setup.orig`, preserves Apple's entitlements and
  `com.apple.purplebuddy` identifier, ad-hoc signs the patched binary, validates
  the new CodeDirectory, and verifies the device readback.
- The restored System volume did not contain `/bin/sh`. Consequently launchd
  could not initialize `com.jbboot`, whose program is `/bin/sh`, and Dropbear
  could not open root's configured login shell. The SSHRD payload installer now
  deploys the known-good `sh`, `ls`, and `cat` from `ssh.tar.gz` alongside the
  Dropbear binaries.

Both faults are now explicit gates in `fw provision --check`. A device must
report `Setup CodeDirectory/id OK` and `System /bin/sh present` before another
normal boot is attempted.

The following SSHRD session collected the persistent diagnostics into
`.liter8/diagnostics/normal-boot-20260912-1711`. They prove that the kernel
reached deep userspace: SpringBoard, backboardd and the normal daemon set were
running. There is no panic breadcrumb.

Five `coreauthd` reports contain the same `EXC_BAD_ACCESS / SIGSEGV` at address
`0x120`. The faulting stack runs through
`LACDTORatchetSEPStateParser` and
`LACDTOPendingPolicyEvaluationController startController`. This exactly
matches the crash documented and fixed by the existing beta-4 research.

The root cause was an orchestration omission. Liter8 already had semantic Swift
resolvers for `coreauthd`, `mobileactivationd` and `ctkd`, but `fw provision`
did not deploy their patches. It also omitted the five ScreenTime launchd
overrides used by the known-good device state.

## Reference comparison completed

Reference directory:

```text
/Volumes/vinay-ssd/iphone11-usbliter8/usbliter8-fun/work-27.0b4-n104
```

The following behavior currently matches the reference `boot.py` and
`get_boot.py`:

- The n104 display-init bypass is applied to normal iBSS only, never iBEC.
- `bgcolor 0 191 255` runs before uploading the logo and `setpicture 0x1`.
- Firmware upload ordering and the deliberate AVE, SPTM, PMP and DeviceTree
  pauses match.
- The `bootx` status is deliberately ignored because successful kernel handoff
  removes the recovery USB transport.

The old reference also says to wait roughly five minutes, return through SSHRD,
and inspect persistent logs instead of treating a black screen or missing USB
as proof of failure.

## Fix deployed

`fw provision` now has guarded `userland` and `screentime` phases. It builds
from the device's preserved `.orig` files, asks Swift to resolve and apply the
patches, preserves entitlements and signing identifiers, deploys atomically,
reads every binary back and includes all four states in `--check` verification.

Local validation covers all three exact beta-4 binaries. The SSHRD deployment
completed and exact readback verification reported `OK` for all three daemon
artifacts, their pristine backups and the ScreenTime overrides. The repaired
Setup signature and System shell also passed the full on-device preboot check.

The following `get-boot` and `boot` run reached the iOS Setup screen. Normal
boot is therefore confirmed end to end on the beta-4 iPhone 11; the previous
SpringBoard reboot loop is resolved.

## Next investigation

1. Confirm normal-mode SSH and remaining work with `fw finalize --check`.
2. Run the one-time bootstrap, shell and app setup through `fw finalize`.
3. Collect a fresh crash-report delta; no new DTO-ratchet `coreauthd` report
   should appear.

The misleading `setup-shell` readiness check was fixed in commit `f36e8b0`. It
now owns `iproxy` and distinguishes unreachable SSH from a missing bootstrap.
