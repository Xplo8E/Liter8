# Device provisioning resources

This directory contains the reviewed bootstrap, jailbreak provisioning and
shell-setup inputs migrated from the public iPhone 11 beta-4 work directory.
They are installed as immutable Liter8 resources. The CLI copies them into
`<work-dir>/device-runtime/workflow` before running them, because the
payload builders need a persistent writable `payload/` and build directory.

The checked-in archives are pinned by complete SHA-256 values in
`scripts/device_provision.py`. The launchd input is also pinned to the firmware
profile selected from `BuildManifest.plist`; provisioning refuses an unknown
profile instead of applying a boot-critical patch by pattern alone.

Commands have deliberately narrow device states:

- `liter8 fw bootstrap` runs from the Mac while the phone is in SSHRD and
  installs the Procursus tree on the Data volume.
- `liter8 fw provision --rootfs <mounted-rootfs>` builds the reviewed payloads,
  installs Dropbear and performs the System/Data/Preboot provisioning pass. It
  also patches and entitlement-preserving re-signs `coreauthd`,
  `mobileactivationd`, `ctkd`, `lockdownd`, `remotepairingdeviced` and Setup,
  then installs the five fail-fast ScreenTime overrides recorded by the beta-4
  device research.
  `lockdownd` weak-loads `/usr/lib/l8pair.dylib`, a marker-gated fallback for
  its one pairing identity when the no-content-protection profile cannot
  persist the corresponding system-keychain row. The Dropbear
  payload also supplies the minimal System `/bin/sh`, `ls` and `cat`; the shell
  is required by both root logins and the `com.jbboot` launchd-cache job. It
  requires `fw bootstrap` to have created `/var/jb` first.
- `liter8 fw setup-shell` runs only after a normal boot and installs the root
  shell profiles on the writable Data volume.
- `liter8 fw finalize` runs once after the first normal boot. It explicitly
  invokes the bootstrap through `/var/jb/bin/sh`, configures passwd databases
  and shells, installs the root profile, performs the guarded one-time System
  application registration, restarts SpringBoard and verifies `com.jbboot`.
  It refuses registration when container applications already exist.

Add `--check` to inspect the corresponding state without installing files.
Device scripts retain `.orig` or `.prev` copies when replacing boot-critical
content. They still require operator-controlled device state and are never run
as part of build or test targets.

The pairing fallback is active only while
`/private/var/root/Library/Lockdown/.liter8-pairing-fallback` exists. It
interposes the three `SecItem` operations only for access group
`lockdown-identities`, label `com.apple.lockdown.pairingkeypair`, and the system
keychain. The exported RSA private key is stored root-only beside the marker as
`liter8_pairing_key.der`. Removing the marker from SSHRD returns the loaded
dylib to complete pass-through behavior.

The same marker also gates one lockdownd-only LocalAuthentication fallback.
After the user explicitly presses Trust, lockdownd evaluates private policy
1028 (`LocationBasedTrustComputer`) to obtain passcode authorization. The
SEP-less profile returns LocalAuthentication `-1000` with ACM status `-3`
before showing the passcode sheet. `l8pair.dylib` first runs the real policy
and converts only that exact failure to success. Successful evaluations, all
other policies, and all other errors pass through unchanged. Consequently,
this profile retains the explicit Trust decision but cannot provide genuine
SEP-backed passcode proof; removing the marker disables this fallback too.

`coreauthd` also weak-loads `/usr/lib/l8coreauth.dylib`. On the SEP-less boot
path ACM can return an empty DTO ratchet-state `NSData` without an error;
LocalAuthenticationCore 24A446 otherwise copies 75 bytes from offset `0x100`
and crashes at NULL + `0x120` after the user accepts the Trust dialog. The
guard pads only short state blobs to the parser's 331-byte layout. Valid SEP
state is passed through unchanged, and the hook is restricted to `coreauthd`.

`remotepairingdeviced` weak-loads `/usr/lib/l8remotepairing.dylib`. After its
own visible Trust dialog, the 24A446 daemon skips policy 1013 only when
`MKBGetDeviceLockState(NULL)` returns the disabled-keybag state 3. The Liter8
AKS shim reports scalar unlocked state but leaves the larger lock-state buffer
zeroed, so the real API returns 0 and CoreAuth fails before it can display the
passcode sheet. The interposer returns 3 only in `remotepairingdeviced`, with
the root-owned `/usr/lib/.liter8-remotepairing-fallback` marker enabled, a
`NULL` options argument, real state 0, content protection off, and
unlocked-since-boot true. Every other state passes through unchanged; the
payload does not intercept LocalAuthentication. This separate System marker is
used because normal-boot processes can be denied access to lockdownd's
Data-volume marker.

The same daemon uses the system keychain for its self identity and paired-peer
records. On this SEP-less profile, `SecItemAdd` can report success while the
next PairVerify sees no identities or peers. The dylib keeps the real keychain
as the first choice, then mirrors only the `com.apple.RemotePairing` generic-
password items named `Remote Pairing Identity` or `Remote Pairing Paired Peer`
into the daemon's writable `com.apple.remotepairing` preferences domain. Copy,
update, and delete fall back to that bounded store only when the same System
marker and process guard match. Other keychain access is unchanged.

Exact-device validation completed PairSetup after an explicit Trust decision,
then completed PairVerify on a second connection in the same boot without a
new Trust sheet. After manually bootstrapping the already-mounted personalized
DeveloperDiskImage launchd jobs, CoreDevice enumerated processes and captured a
screenshot. Persistence across a full reboot and automatic DDI job registration
remain separate, unconfirmed boundaries.
