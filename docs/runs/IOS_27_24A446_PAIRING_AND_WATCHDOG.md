# iPhone 11 `24A446`: watchdog panic and USB pairing research notes

- **Device:** iPhone 11 (`iPhone12,1`, `n104ap`)
- **OS:** iOS 27.0.1 (`24A446`)
- **Status:** USB lockdown pairing and same-boot RemoteXPC confirmed; watchdog mitigation deployed and under soak

This note records the failures behind two symptoms that initially looked unrelated:

- the normal-boot device eventually powered off or rebooted after sitting for a while;
- the Mac could see the phone over USB and display Trust, but pairing never completed.

They share the same background: Liter8's current research boot deliberately runs without a working SEP/AKS path and without a content-protected Data volume. The final fixes are narrow compatibility shims for that environment. They do not pretend SEP or data protection is working.

## Short version

The delayed reboot was `watchdogd` repeatedly failing to open `IOWatchdog`. launchd restarted it after each unsuccessful exit, then its private consecutive-crash policy deliberately panicked the device. Liter8 now removes only the automatic trigger, unsuccessful-exit restart, and panic escalation from the reviewed launchd-cache job. The Mach services remain intact.

Pairing had three separate blockers:

1. `securityd` could not retain lockdownd's RSA identity because the class-0 keychain metadata key did not exist.
2. Once a persistent identity was supplied, accepting Trust crashed `coreauthd` on an empty SEP ratchet-state buffer.
3. Once that crash was guarded, lockdownd's private policy 1028 failed with ACM status `-3` before a passcode sheet could appear.

The pairing fix therefore has three parts:

- persist only lockdownd's pairing identity in a root-only file;
- pad only malformed short ratchet-state inputs before Apple's normal parser sees them;
- after explicit Trust, accept only the exact observed policy-1028 `LocationBasedTrustComputer` failure.

That path now survives Trust, cable replug, normal reboot, and deletion plus recreation of the Mac's pairing record.

## What the device was actually doing

### The watchdog panic

The serial capture finally caught the shutdown. The important sequence was not a hardware watchdog firing after a fixed number of seconds. The kernel boot argument still disables that watchdog with `wdt=-1`.

The userland daemon was the problem:

```text
IOKit LaunchEvent starts watchdogd
  -> watchdogd cannot open IOWatchdog in this boot environment
  -> watchdogd exits through its failure path
  -> KeepAlive SuccessfulExit=false starts it again
  -> launchd counts consecutive crashes
  -> _PanicOnCrash/PanicOnConsecutiveCrash panics the device
```

The stock job carried all three pieces needed for that loop:

```text
LaunchEvents    com.apple.iokit.matching -> com.apple.driver.watchdog
KeepAlive       SuccessfulExit = false
_PanicOnCrash   PanicOnConsecutiveCrash = true
```

Changing `wdt=-1` to a positive deadline would not fix this. That changes the kernel watchdog behavior, while this panic came from launchd escalating a repeatedly crashing userspace daemon.

### Pairing stopped before certificate exchange

The first host failure was `MissingValue` for `DevicePublicKey`. usbmux and lockdown were both working. The device answered structured requests, but it had no pairing public key to return.

The device-side sequence made the cause clear:

```text
lockdownd calls SecItemCopyMatching
  -> no usable pairing identity
lockdownd creates a 2048-bit RSA key
lockdownd calls SecItemAdd in the system keychain
  -> securityd inserts the row
securityd cannot load the class-0 metadata key
  -> "Unable to find a suitable metadata key and not permitted to create one"
  -> the row is treated as corrupt and deleted
next SecItemCopyMatching
  -> identity is missing again
host receives MissingValue
```

Serial independently showed why the metadata key was unavailable:

```text
creating unencrypted Data partition
mount point (/mnt10) does not support Data Protection
disk1s2 ... unencrypted
AppleCredentialManagerUserClient ... persona=NO, SUID=-1
```

This ruled out USB transport, a stale Mac pairing record, and a missing lockdownd access-group entitlement. The failure was the system-keychain storage model on this exact no-content-protection boot.

### Trust exposed a second crash

After supplying a usable pairing identity, the Trust dialog appeared. Pressing Trust did not complete pairing because `coreauthd` crashed four times at the same instruction:

```text
-[LACDTORatchetSEPStateParser _statusFromRatchetState:] + 36
EXC_BAD_ACCESS at 0x120
```

The 24A446 implementation calls `-[NSData bytes]`, then reads a status structure beginning at offset `0x100` without checking the data length. ACM returned zero-length data with no error, so the parser dereferenced `NULL + 0x120`.

The older Liter8 patch that skipped one DTO `startController` call did not cover this later policy-evaluation path. That was an important dead end: the expected patch was present, but the crash lived somewhere else.

### Fixing the crash exposed the real authorization failure

Once `coreauthd` stayed alive, lockdownd reached private LocalAuthentication policy 1028:

```text
policy: 1028 (LocationBasedTrustComputer)
title:  Enter Device Passcode to Trust This Computer
result: com.apple.LocalAuthentication/-1000
detail: ACM verification ... failed: -3
```

The failure happened before the passcode UI could appear. On this boot there is no genuine SEP-backed proof to collect, so retrying the prompt could never solve it.

## The implemented fix

### 1. Stop the watchdogd crash loop without deleting watchdogd

[`device/patch_watchdogd_job.py`](../../device/patch_watchdogd_job.py) validates the exact job identity and expected Mach services before changing anything. It removes only:

- `LaunchEvents`;
- `KeepAlive`;
- `_PanicOnCrash`.

Everything else remains. In particular, `com.apple.unblock` and `com.apple.watchdogd.optin.registration` remain registered as Mach services, so an explicit request can still start the daemon. One failure just no longer becomes an automatic restart loop and then a panic.

The patcher recognizes only two complete states: reviewed stock and reviewed mitigated. A partially modified or unknown job shape fails closed. It also writes through a verified temporary file and retains a hash-bound backup of the original cache.

### 2. Give lockdownd one durable identity

[`device/pairingfix/l8pair.c`](../../device/pairingfix/l8pair.c) is weak-loaded into `lockdownd`. It interposes `SecItemCopyMatching`, `SecItemAdd`, and `SecItemDelete`, but only handles the exact lockdown pairing identity:

```text
access group: lockdown-identities
label:        com.apple.lockdown.pairingkeypair
keychain:     system keychain
class:        key, where present in the real 24A446 call shape
```

The fallback is disabled unless this operator-controlled marker is present and root-owned:

```text
/private/var/root/Library/Lockdown/.liter8-pairing-fallback
```

The RSA private key is exported to:

```text
/private/var/root/Library/Lockdown/liter8_pairing_key.der
```

The file is written mode `0600` through a temporary file, `fsync`, and atomic `rename`. A later Copy imports it back into a `SecKeyRef`, allowing lockdownd's normal public-key export and private-key use to continue. Unrelated keychain traffic goes straight to Apple's implementation.

One subtle bug was found during live validation. The 24A446 `SecItemAdd` dictionary does not contain `kSecClass`, while Copy and Delete do. The first matcher required `kSecClassKey` for all three operations, so Add never reached the persistence path. The final matcher follows the observed per-operation dictionary shape instead of assuming they are identical.

### 3. Keep Apple's ratchet parser, but give it a valid-sized buffer

[`device/coreauthfix/l8coreauth.m`](../../device/coreauthfix/l8coreauth.m) weak-loads only into `coreauthd` and swizzles only:

```text
-[LACDTORatchetSEPStateParser ratchetStateFromState:]
```

Inputs of at least `0x14b` bytes pass through unchanged. Short inputs are copied into a zero-filled `0x14b`-byte buffer, preserving any real prefix, then sent to the original parser. The hook does not fabricate a result object and does not replace the policy engine.

This changed the observed empty state from a crash into the framework's normal `NotStarted` result:

```text
l8coreauth: padded short SEP ratchet state (0 -> 331 bytes)
```

### 4. Handle only lockdownd's exact policy-1028 failure

[`device/pairingfix/l8pair_auth.m`](../../device/pairingfix/l8pair_auth.m) wraps private `-[LAContext evaluatePolicy:options:reply:]` inside `lockdownd`.

The real policy always runs first. Failure is converted to an empty successful result only when every condition matches:

- process name is `lockdownd`;
- the root-owned pairing marker is active;
- policy is exactly 1028;
- the result is nil;
- the error is `com.apple.LocalAuthentication/-1000`;
- `NSDebugDescription` contains both `LocationBasedTrustComputer` and `failed: -3`.

All normal successes, other policies, and other errors pass through unchanged. The user must still press Trust before lockdownd reaches this policy.

This is deliberately a compatibility fallback, not real passcode authorization. The no-SEP boot cannot produce that proof. Removing the marker disables both the key persistence and policy fallback without removing the weak load command.

## Provisioning and rollback

`fw provision` builds universal `arm64` and `arm64e` dylibs, verifies their structure, weak-loads them into the exact daemons, preserves identifiers and entitlements while re-signing, and verifies whole-file readbacks.

The selective `pairing` step includes the `coreauthd` companion guard. Deploying only the lockdownd half would get past `DevicePublicKey` and then crash during Trust.

Provisioning retains pristine `.orig` daemon files. The root marker is the runtime kill switch:

```sh
rm /private/var/root/Library/Lockdown/.liter8-pairing-fallback
```

Run that only from the controlled SSHRD recovery environment. On the next normal boot the loaded hooks become pass-through.

## Validation

### Host-side checks

- full `make check` passed with Xcode's Swift 6.4 toolchain;
- 105 XCTest cases passed with 35 local-fixture skips;
- 21 Swift Testing cases passed;
- all 14 IPSW robustness cases passed;
- 49 Python workflow tests passed with two fixture-dependent skips;
- both dylibs contain `arm64` and `arm64e` slices and valid ad-hoc signatures;
- provisioning verifies hashes, signatures, entitlements, load commands, backups, and generated launchd-cache state.

Validated dylib hashes:

| Artifact | SHA-256 |
| --- | --- |
| `l8pair.dylib` | `4feff917fd1c32b8b41af243a181e5f6fc7387a547b36632834e60ec7e861469` |
| `l8coreauth.dylib` | `e6927105bd21c957d435f243aa36fec7945ca05fa828f15198a96fa9fc2fd2f8` |

### Exact-device checks

On iPhone12,1 build 24A446:

- Trust completed without a new `coreauthd` crash;
- `idevicepair validate` succeeded repeatedly;
- paired `ideviceinfo`, syslog relay, diagnostics relay, AFC, installation proxy, notification proxy, SpringBoard, and profile services worked;
- the pairing public key remained stable across repeated reads, physical cable replug, and normal reboot;
- deleting this Mac's pairing relationship produced a fresh Trust flow and a different host certificate, then validated again;
- TrollStore Lite installed through the patched iOS 27 SSH helper, appeared as `ApplicationType: System`, and was removed through host `installation_proxy`;
- no new kernel panic, `watchdogd` event, userspace-watchdog timeout, or unexpected shutdown appeared during the completed stress interval.

The stable pairing public-key SHA-256 was:

```text
55b5de34b901d1cca559a8043e0578594913085d53e4b6cc866e2b47bd1c10d7
```

## Remaining boundaries

Pairing working does not make the whole SEP-less device equivalent to stock.

### MobileBackup2

Both tested clients reached `com.apple.mobilebackup2` and negotiated the protocol. The backup then failed with:

```text
nil personaAttributes (MBErrorDomain/1)
```

The service transport and escrow pairing are reachable, but a real backup does not complete because the boot has no normal persona state.

### RemoteXPC and DeveloperDiskImage lifecycle

A personalized DeveloperDiskImage mounts at `/System/Developer`. Xcode also maintains a wired CoreDevice tunnel and heartbeats succeed, but `ddiServicesAvailable` stays false.

An independent privileged RemoteXPC attempt exposed another LocalAuthentication path:

```text
policy: 1013 (TouchIdEnrollment)
error:  com.apple.LocalAuthentication/-1000
detail: ACM verification of TouchIdEnrollment on ACMContext 0 failed: -3
```

The policy-1028 lockdownd fallback does not and should not match this. Before
the daemon-scoped repair below, RemoteXPC consent therefore failed before
screenshot, process-control, LLDB/Xcode, or WDA services became reachable.

The device-scoped fix weak-loads `/usr/lib/l8remotepairing.dylib` only into
`remotepairingdeviced`. Its MobileKeyBag interposer preserves the real
`MKBGetDeviceLockState` result unless all measured Liter8 conditions match:

- the process name is exactly `remotepairingdeviced`;
- the root-owned `/usr/lib/.liter8-remotepairing-fallback` marker exists and is
  not group/world writable;
- the caller passed `NULL`, as the recovered 24A446 call site does;
- the real state is 0;
- content protection is off and the device reports unlocked-since-boot.

Only then does it return state 3, selecting the daemon's existing
`Not requiring user passcode as key bag is disabled` branch after the visible
Trust decision. It does not intercept `LAContext` or relax policy 1013
globally. Host-side validation confirmed the universal dylib shape, the exact
daemon's 50,336-byte load-command slack, the weak load command, and preservation
of the daemon's signing identifier and entitlements. SSHRD readback then
verified the patched daemon, its original backup, all three pairing dylibs, and
the complete existing provisioning state.

The first normal-boot test rejected the original marker location. Trust was
explicitly approved at 17:41:12, but the daemon still entered policy 1013 and
failed ACM `-3`. The active daemon and dylib hashes matched the deployed
artifacts and the daemon retained its weak load. A normal-boot root process also
received `EPERM` reading the shared Data-volume marker, making that marker a
concrete candidate for the pass-through. The revised build uses a distinct
System-volume marker beside the dylib and logs its observed guard values once.
SSHRD deployment read back the revised dylib at SHA-256
`b9ab0009b59b021de423b0728c1bc5c9a96d3680ab2e568de10eb4101360ceeb`,
verified both fallback markers, and completed the full device-state check with
`done, safe to reboot`. Normal boot then confirmed the complete intended
consent path: the guard observed `state=0 null_options=1 marker=1 formatted=0
unlocked=1`, selected the built-in disabled-keybag branch, and logged
`Successfully authenticated user` followed by `PairSetup server done -- client
authenticated`.

The first tunnel did not survive reconnection. Each new connection logged
`Not paired with anyone`, then PairVerify failed while copying the device
identity with `kNotFoundErr`. The host pairing plist was created and updated,
so the residual failure is the device's RemotePairing system-keychain state.
IDA recovered two generic-password item families in access group
`com.apple.RemotePairing`: `Remote Pairing Identity` and
`Remote Pairing Paired Peer`.

The deployed five-interposer build keeps the real keychain first and mirrors
only those records into the daemon's writable preferences domain. On the first
connection it logged bounded persistence and retrieval, completed PairSetup,
and created a TCP tunnel. After terminating only that tunnel, a second
connection required no new Trust sheet, restored the identity and peer, and
completed PairVerify M1 through M4. This confirms the fallback across
independent connections in the same boot.

The personalized DeveloperDiskImage was already mounted, but its launchd jobs
were absent after boot. CoreDevice therefore obtained the tunnel and stalled
while enabling DDI services. Manually bootstrapping
`/System/Developer/Library/LaunchDaemons` registered the expected RemoteServices;
`devicectl device info processes` then succeeded and CoreDevice captured an
828x1792 screenshot. RemoteXPC pairing is fixed for the tested boot. Automatic
DDI job registration and persistence of the newly written RemotePairing peer
across a full reboot remain unconfirmed. QuickTime USB capture is a separate
Valeria callback-ownership failure and is not fixed by this change.

### Wi-Fi pairing

Wi-Fi pairing already worked before this change, so it is not evidence for the fix. The validated result here is USB lockdown pairing and its fresh-record lifecycle.

### Content protection

Turning `content-protect` back on in a later normal boot cannot encrypt the existing Data volume. A meaningful experiment requires an erase restore and a SEP/AKS path capable of creating and using the real class keys. With the current dead-SEP model, the likely result is an earlier restore or boot failure.

## Scope

Confirmed:

- watchdogd's observed crash-loop-to-panic mechanism and the generated-cache mitigation;
- the pairing keychain failure;
- the empty ratchet-state crash;
- the policy-1028 ACM `-3` boundary;
- pairing, replug, reboot, and same-Mac fresh-record behavior on iPhone12,1 / 24A446;
- RemoteXPC PairSetup and same-boot PairVerify reconnect;
- CoreDevice process enumeration and screenshot capture after manual DDI job bootstrap.

Not claimed:

- genuine SEP-backed passcode proof;
- support for another device or build;
- working MobileBackup2, automatic DDI job registration, post-write reboot
  persistence, Xcode, or WDA;
- working QuickTime USB capture;
- conversion of the existing Data volume to content protection;
- long-term watchdog reliability beyond the completed and ongoing soak evidence.
