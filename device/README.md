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
  requires `fw bootstrap` to have created `/var/jb` first. Provisioning also
  installs `/usr/local/bin/l8boot` (`boothelper/`), which that job runs every
  boot: it links Dropbear's `/tmp/bin` and `/tmp/usr/bin` PATH entries into
  `/var/jb`, and enables injection after SpringBoard is up when
  `/var/jb/.lhook_autoenable` exists, which `fw finalize` creates.
- `liter8 fw setup-shell` runs only after a normal boot and installs the root
  shell profiles on the writable Data volume.
- `liter8 fw finalize` runs once after the first normal boot. It explicitly
  invokes the bootstrap through `/var/jb/bin/sh`, configures passwd databases
  and shells, installs the root profile, installs the dpkg hook that re-signs
  TweakInject dylibs ad-hoc (`tweaksign/`), performs the guarded one-time System
  application registration, restarts SpringBoard and verifies `com.jbboot`.
  It refuses registration when container applications already exist.

Provisioning also installs the os_log reader as `/var/root/oslog`. A normally
booted device has no `/usr/bin/log`, so this is the only way to read what a
booted Liter8 device is logging:

```sh
liter8/tools/logdev --info --debug
liter8/tools/logdev -p wifid
```

It goes in root's home on the Data volume because that is the only writable
location once the device has booted; the System volume is sealed read-only.
The binary is the pinned `payloads/oslog` resource and carries Apple's private
logging entitlements, which `logd` checks before it opens a stream, so it is
compared byte for byte after the transfer. Its provenance, its iOS 27 message
layout fix and the reason it must not be re-signed with `codesign` are
documented in `payloads/README.md`.

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

`wifid` weak-loads `/usr/lib/l8wifi.dylib`. Without SEP the system keychain
cannot retain the generic-password record that carries a Wi-Fi network
password, so the device forgets it on the next boot and a password-protected
network has to be typed again. The dylib keeps that one record in a file on
the Data volume instead, at
`/private/var/preferences/SystemConfiguration/com.liter8.wifi-passwords.plist`.

It is active only while the root-owned `/usr/lib/.liter8-wifi-credentials`
marker exists, and only inside `wifid`. It interposes the four `SecItem`
operations for exactly one class of item: service `AirPort`, class
`kSecClassGenericPassword`. Every other service, every other item class, and
every request that does not match pass through to the real implementation, as
does every request made by any process other than `wifid`. A record's
system-keychain selection is part of its identity, so it is kept in the store
key along with the account. An update that names a new account moves the
record to it, and a change onto an account that already holds a record is
refused rather than overwriting that record.

The stored password is not encrypted: the file is protected only by Unix mode
`0600`, the same tradeoff the pairing fallback already makes for the
lockdownd RSA key. Removing the marker from SSHRD returns the loaded dylib to
complete pass-through behavior.

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
screenshot. The generated launchd cache now includes
`com.liter8.ddi-services`, which keeps the System-volume `ddiwatch` helper alive.
The helper waits for the DDI's `dtdeviceinfod` plist without busy-looping, then
uses the bootstrap's `/var/jb/usr/bin/launchctl` through `/bin/sh` to register
the complete launch-daemon directory. It resets when the image disappears and
handles a later remount. A native watcher is required because 24A446 has no
`/bin/launchctl`, and exact-device testing showed that `StartOnMount` did not
relaunch a generated-cache job when CoreDevice mounted `/System/Developer`.
After provisioning this watcher and performing a clean normal boot, the helper
remained supervised by launchd, detected the later personalized-image mount,
registered `dtdeviceinfod` and `dtappserviced`, and allowed
`devicectl device info processes` to complete without an SSH bootstrap or host
service restart. The normal Xcode/debugserver/LLDB lifecycle remains untested.
