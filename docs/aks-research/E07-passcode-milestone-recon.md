# E07: passcode pane arc + state-scalar consumer decode

> **Setup-flow arc (2026-11-05, in progress):** goal is passcode
> setup / turn off / change working without a SEP. Progress so far:
> the pane's row state derives from `MCProfileConnection isPasscodeSet`
> (the ManagedConfiguration profile connection answers YES from its
> daemon state forever on this boot - keybagd never reports passcode
> state through its broken AKS, so managedconfiguration sits at its
> fail-closed default). Overriding it to NO flipped the pane to the
> no-passcode view: "Turn Passcode On" renders, the whole LAPS family
> cascades NO, and coreauthd (the auth daemon) answers NO through the
> LACore gate hook. Tapping Turn Passcode On starts
> `LAPasscodeChangeService ('Set Passcode')` and dies at the
> **Stolen Device Protection change ratchet**: it demands prior
> authentication via `evaluatePolicy:1026`, whose evaluation fails
> correctly ("SDP is not available when Passcode is not set") because
> the ratchet state comes from SEP-less ACM context properties
> (`-[LACStorageValueTransformer transformFromACMValue:forKey:error:]`
> rejects them; KVS reads for ratchet keys 7/25/27 error). The ratchet
> gate code lives in the PasscodeAndBiometricsSettings stack, which is
> in no cache image and no on-disk binary we can find - the next lever
> is runtime image hunting plus overriding the `LACDTORatchetManager`
> XPC reads. Decoded en route: `passcodeType` derives from
> `hasPasscode` in the MCAdapter (`noneType` when NO); the credential
> crypto funnel is `LAContext _encodeCredential/_decodeCredential` ->
> `LACContextCredentialCoder encode/decode:seed:` ->
> `+[LACACMHelper encodeData/decodeData:seed:externalizedContext:error:]`
> -> `ACMEncryptDataEx`/`ACMDecryptDataEx` (the -3 wall), now answered
> by the l8acm software crypto (L8CM blobs, master key at
> /var/mobile/Library/l8acm.master).

# E07: passcode pane arc + state-scalar consumer decode

> **Read-this-first (final state, 2026-11-05):** SOLVED. The day-one
> "Enter your passcode" demand in Settings came from
> `LAPSPasscodePersistenceMCAdapter.hasPasscode` — the pane consults the
> ManagedConfiguration PROFILE-CONNECTION store (persisted state, YES since
> the first boot), not the keybag, the AKS scalar, or any LAContext path.
> l8localauth's hasPasscode family hooks answer NO there and the pane opens
> normally with no crash (device-validated 2026-11-05 ~11:05, clean pwnDFU
> boot, probe log captured). The LACore chain below (isPasscodeSetForUser,
> the ls table) is decoded but NOT consulted by the pane — kept for the
> mechanism/evaluation side. Pane rows may still render a mixed state
> (Turn Passcode Off / Change Passcode) because row getters are separate;
> do not tap them — those flows hit the ACM -3 wall.

## Curated summary

### Why the pane predates every experiment

Vinay's observation: the passcode sheet appears from the very first
Liter8 boot, before E06/l8keychain/l8localauth existed. The decode
confirms this is structural, not experimental damage:

- `LAContext canEvaluatePolicy:error:` (LocalAuthentication,
  `0x1cbcc178c`) forwards to `_evaluatePolicy:options:log:cid:error:`
  (daemon-side evaluation) and returns NO only when the error carries
  code `-1004`.
- The `-1004` is produced by exactly one place:
  `+[LACEnvironmentMechanismUserPassword environmentMechanismForUser:auditToken:dependencies:error:]`
  (`0x20842cee8`) builds the passcode mechanism and stores
  `[LACError errorWithCode:-1004 "User interaction is required"]` as its
  availability error when `[passcodeHelper isPasscodeSetForUser:]`
  returns NO.
- `isPasscodeSetForUser:` resolves to
  `-[LACPasscodeUserHelper isPasscodeSetForUser:error:]` (`0x20844bdb4`)
  which answers from `-[LACManagedConfiguration isPasscodeSet]`
  (`0x2084748e4`):
  `[LACKeyBagProvider keybagForUserId:geteuid()].state != 1`.
- That `state` is `LACKeyBagState`, produced solely by
  `-[LACKeyBagStateProviderMKBAdapter state]` (`0x208457644`): it calls
  `MKBGetDeviceLockState` and maps the result through a 12-entry table
  at `0x2085ac120`. **No input maps to 1.** Therefore
  `isPasscodeSet` is unconditionally YES on this boot, the mechanism is
  registered, `canEvaluatePolicy` answers YES, and Settings shows the
  passcode gate regardless of keybagd, the kernel driver, or any shim
  beneath it.

### The state-scalar mapping (what selector 7 actually controls)

`MKBGetDeviceLockState` (`0x1aefd809c`) returns the reply field the
keybagd XPC call calls `ls` (the reply dict schema, decoded from
`MKBGetDeviceLockStateInfo` `0x1aefd85d8`, is
`state:int32, ls:int32, boff, fa, countdown` plus user-session extras
`sw`/`pb` = wipe-pending / permanently-blocked). The adapter table
(`LDR X0, [X9,W8,UXTW#3]` at `0x2084576c4`, base `0x2085ac120`,
index = ls+8):

| ls (keybagd reply) | LACKeyBagState | consumer meaning |
|---|---|---|
| -8 | 4 | error-mapped state |
| -7 .. 0 | 0 | Unknown (fail-closed) |
| 1 | 5 | **Unlocked** |
| 2 | 3 | locked family |
| 3 | 2 | locked family |
| anything else (incl. shim value 6) | 0 | Unknown |

Consumer semantics, all decompiled:

- `LACAutoLockKeybagMonitor.handleKeyBagStateChange` (`0x20851402c`):
  `_isKeybagUnlocked = (state == 5)`; logs "Device became
  UNLOCKED"/"LOCKED". LACKeyBagState 5 is the only unlocked value.
- `LACPasscodeMonitor.keybagStateDidChange` (`0x20853b13c`):
  `keyBagDisabled = (state == 1)` - keybag DISABLED (repair mode), not
  "no passcode".
- `LACManagedConfiguration.isPasscodeSet` = `state != 1` - the pane gate.
- `LAPSPasscodePersistenceMKBAdapter` (`0x24d4af3e0`) reads the same
  reply dict for `isPasscodeLockedOutForUserId:` (pb),
  `backoffTimeoutForUserId:` (boff/countdown),
  `failedPasscodeAttemptsForUserId:` (fa).

So the scalar path governs: unlocked-vs-locked (autolock, availability),
lockout/backoff, and keybag-disabled. It does NOT govern passcode-set.
The Darwin notification `com.apple.mobile.keybagd.lock_status`
(`-[LACKeyBagMKBAdapter _addKeybagStatusObserver]` `0x20844d320`) is a
payload-free re-poll trigger; there is no second producer of
LACKeyBagState.

### The empty-passcode machinery (iOS 27 ships a no-passcode route)

`-[LACDTOPolicyProcessorEmptyPasscode _processAndEvaluateRequest:completion:]`
(`0x208440ce4`) proves the intended no-passcode flow exists:

- `canProcessRequest:` = request options `@1081` set.
- `-[LACDTODeviceInfoProvider hasPasscodeSetForUser:]` NO, options
  `@1000` unset -> `[LACCredentialStore setValue:[LACSecureData
  secureDataWithData:nil] forCredential:... completion:...]` - stores an
  EMPTY passcode credential so user-password auth succeeds without any
  secret.
- passcode-set -> logs "Removing %d option because user %d has
  passcode", strips option `@1081`, forwards to the next processor.

`LACDTODeviceInfoProvider` is OBJC_UNDEF in the cache database: the
class is referenced from LocalAuthenticationCore but defined in a
non-cached binary (searched the whole 87-file 24B119 cache with
`ipsw dyld str`; only libobjc's format string carries the name). The
provider presumably reads keybagd's `state` field or the keybag type -
to be confirmed when that image is pulled.

### The hook point

### Device test history (2026-11-05)

1. **First build (LACore gate only, `bd9d05e3`)**: hooked
   `isPasscodeSetForUser:error:` on LACPasscodeUserHelper +
   LACPasscodeHelper. Installed cleanly (gate mask 0x3) but the pane
   still demanded the passcode with ZERO hook calls — the pane does not
   consult the LACore gate. During the same window Settings hung at
   splash ~30s and died on every launch; marker-off and the previous
   proven build reproduced it, so it was the post-push
   identity/throttle churn (the Nov-4 pattern), NOT the hooks. A
   `launchctl reboot userspace` left the device black and USB-dead
   (kernel patches are per-boot; only pwnDFU -> fw boot recovers —
   recorded as a standing rule: never reboot this device autonomously).
2. **Second build (probe + override, `5b0622fc`)**: hooks `hasPasscode`
   on the whole LAPSPasscode* persistence family (8 of 9 classes; the
   plain `LAPSPasscodePersistence` class was absent), forwards + logs,
   and overrides NO on the two state-backed providers. Clean pwnDFU
   boot, tap at 11:05:26 — probe captured:
   `MCAdapter hasPasscode YES -> NO` — the ManagedConfiguration
   profile-connection store answered YES and was the pane's source.
   CurrentPasscodeService cascaded NO; the pane opened fully
   (Set Up Face ID / Turn Passcode Off / Change Passcode rows), no
   passcode demand, no crash, Settings stable. Rows show a mixed state
   because row getters are separate — do not tap them (ACM wall).

### The hook point (LACore chain — decoded, not the pane's path)

## Session log

### 2026-11-04/05 - E07 experiments (prior slice)

- l8localauth E07 device-owner policy shim (policies 1/2 ->
  LAErrorPasscodeNotSet): built fat arm64+arm64e, classic
  `evaluatePolicy:localizedReason:reply:` hook variant was AMFI-rejected
  then bisected out; working build is the current 201568-shape source
  (device/localauthfix/l8localauth.m). Injection reliability into
  Settings is pending; parked, not retired.
- Passcode-set pane crash chain (debugserver + oslog): LAContext sheet
  -> LAPSPasscode initWithPasscode:type: -> LACSExtractablePassword
  initWithData:error: -> ACM context encryption query "Failed to obtain
  encryption size -3" -> NSInternalInconsistencyException -> SIGABRT.
  The ACM context query requires SEP; below any userspace layer we can
  reach.
- keybagd revert-to-stock completed after the E07-E6 shim cycle;
  device boots clean on stock keybagd + l8keychain weak-load.
- CTRR clarification (Vinay asked whether CTRR explains the failures):
  no - CTRR gates the sealed-System-volume page mappings at a layer
  above these userspace failures; the crash mechanisms are AMFI
  signing and SEP-absent ACM queries.

### 2026-11-05 - E07-E7 state-scalar consumer decode (this slice)

Trigger: Vinay corrected that the pane predates E06 and asked to dig
into the state scalar bit decode. All addresses below are in the
24B119 dyld_shared_cache_arm64e IDA database (9bc73cd3e2c0), image
noted per function.

1. MKB framework (loaded into the cache db by Vinay):
   `_MKBGetDeviceLockState` `0x1aefd809c` returns `v9[1]` on success
   = reply field `ls`; error otherwise. `_MKBDeviceUnlockedSinceBoot`
   `0x1aefd852c` = `(raw_scalar & 4)` (bit 2 = beenUnlocked), cached
   in `gUserUnlockedSinceBoot`; raw-bit path is SEPARATE from `ls`.
   `_MKBUserUnlockedSinceBoot` `0x1aefd8ce0` same bit 2.
2. Reply schema from `_MKBGetDeviceLockStateInfo` `0x1aefd85d8`:
   `state` (dword0), `ls` (dword1), `boff`, `fa`, `countdown`; user
   sessions add `sw`/`pb` via `-[MKBKeyStoreDevice getLockStateForUser:]`.
3. LocalAuthenticationCore adapter: `-[LACKeyBagStateProviderMKBAdapter
   state]` `0x208457644` - builds `@{DeviceHandle: userId}`, calls
   `MKBGetDeviceLockState`, maps via table `0x2085ac120` with range
   check `(ls+8) > 0xB -> 0`. Table bytes read and verified.
4. Consumers decoded (see curated table above): autolock monitor
   `0x20851402c`, passcode monitor `0x20853b13c`, managed config
   `0x2084748e4`, persistence adapter `0x24d4af3e0`.
5. canEvaluatePolicy `-1004` traced to the UserPassword mechanism
   factory `0x20842cee8`; empty-passcode processor `0x208440ce4`;
   `LACDTODeviceInfoProvider` confirmed absent from the cache
   (`ipsw dyld str`, grep over all 87 cache files, device-side grep).
6. Kernel-shim hypothesis (MOV X8,#6 -> truthful scalar) is DEAD for
   the pane: no scalar value reaches `isPasscodeSet`. Parked; do not
   spend an SSHRD cycle on it.

## Standing notes

- Evidence tags: [V] verified decompile/bytes, [I] inference, [R] to
  re-verify. All chain links above are [V] except the
  `LACDTODeviceInfoProvider` internals ([R], image not yet available).
- Never invent: selector numbers, struct layouts, entitlement strings.
- The E07 l8localauth classic-hook encoding fix (`v@:q@@?`) is in the
  archived commit 4536bd7 if the classic evaluatePolicy hook is ever
  revived.
