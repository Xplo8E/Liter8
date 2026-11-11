# E08 — Lock-Screen Passcode Recon (SEP-less)

Date: 2026-11-07. Branch: research/e07-passcode-gate. Builds on the E07 passcode arc
(set/change/pane working end-to-end, commit 99ab587). Evidence tags: [V] measured/decoded,
[I] inference, [R] runtime-pending.

## State at arc open

Set/change/pane flows complete end-to-end through the shim (see E07 doc + 99ab587):
client encodes credentials with software AES-CTR+HMAC (l8acm-core), daemon blob store
serves read-backs, confirm compare runs on plaintext, constraints/change verdicts
overridden. The lock screen was untouched: locking the device shows no passcode prompt —
the screen swipes open.

## What the lock screen consults [V]

The lock prompt does NOT use the MC/pane layer (our state-file-aware isPasscodeSet/hasPasscode
overrides work in SpringBoard — it loads the shim and reads YES — and the lock screen ignores
them). The belief comes from the keybag layer:

- SpringBoard → MobileKeyBag framework → **MKBKeyStoreDevice** (the only ObjC class in
  MobileKeyBag, 44 methods; runs inside SpringBoard as the keybagd XPC client):
  - `getDeviceLockStateForUser:extendedState:withLockStateInfo:` — lock-state query; the
    reply block (decoded @0x1aefe636c) writes exactly ONE int (the ls value) into the
    caller's pointer.
  - `getLockStateForUser:` — dict variant (boff/fa/countdown).
  - `passcodeUnlockStart/Success/Failed`, `loadKeybagForUserSession:withSessionID:withSecret:`,
    `createKeybagForUserSession:` — the unlock/keybag-op family.
- C transport: `MKBGetDeviceLockState` → `__get_device_lock_state` → `aks_get_device_state`
  — the AKS kernel layer, where the E06 kernel shim already synthesizes the selector-7
  scalar (noPin|beenUnlocked). Per the E07-E7 consumer audit, no bit in that scalar encodes
  "passcode set"; the prompt belief rides keybag presence + ls state.
- SpringBoard's own classes are all CONSUMERS: 11 classes implement
  `keybag:extendedStateDidChange:` (SBLockScreenManager, SBAmbientPresentationController,
  SBContinuityDisplayAuthenticationCoordinator, ...). No SpringBoard class owns the state
  or queries passcode-set directly (`SBUserAgent deviceIsPasscodeLocked` =
  `!authenticationController.isAuthenticatedCached` — auth cache, not passcode belief).
- The decisive selector: **`requiresPasscode`** — present in SpringBoard's selrefs, NOT
  implemented in SpringBoard: the keyBag object (SBDefaultAuthenticationPolicy._keyBag,
  injected via initWithMobileKeyBag:) is backed by a class in another framework
  (BackBoardServices primary candidate) that owns the state and fires
  `keybag:extendedStateDidChange:`.

## Attempt 1 [V]: ObjC wrapper hook — deployed, no prompt

Build 13l (l8_lockstate.m): swizzle
`getDeviceLockStateForUser:extendedState:withLockStateInfo:` (runtime-confirmed encoding
family "B@:iB^i"), call original, overwrite the out int with the fabricated locked value
(ls=2, build-flag) when the passcode state file + a second marker
(/var/mobile/Library/l8acm.lockstate-fake) are present. Result: hook installs everywhere
(mask 0x1, incl. post-restart SpringBoard), but the lock action never triggers a call from
SpringBoard — the fabrication never fires. Conclusion: SpringBoard does not poll the ObjC
wrapper at lock time; the belief arrives via the state-owner object's push
(`keybag:extendedStateDidChange:`), or a C-level call the merged-db xref scan cannot see.

## Next decode (checkpointed)

1. Find the `requiresPasscode` implementer (mirror-settled bounded query; candidate
   frameworks: BackBoardServices, SpringBoardUI). Decompile what it consults.
2. Hook THAT with the state file + verifier hash.
3. Unlock leg: `SBLockScreenManager attemptUnlockWithPasscode:` family
   (`_attemptUnlockWithPasscode:mesa:finishUIUnlock:completion:` + 4 block_invokes) —
   gate the entered passcode on the verifier hash.
4. Boot-safety law: the fabrication must be scoped to SpringBoard's UI query. keybagd's
   global lock state is load-bearing for content protection (E07-E1 wedge: apfs
   class-open retry loops when keybag state and the no-CP boot profile disagree).

## Debug-craft banked this segment

- On-disk SpringBoard.app is a 140KB thin launcher; the code lives in SpringBoard.framework
  (dyld-cache-resident). `ipsw dyld image` LISTS /System/Library/CoreServices/SpringBoard.app/
  SpringBoard but extract refuses it — false listing (AppleCredentialManagerDaemon pattern).
- iOS 17+ encrypted isa: low 40 bits = class address (slide 0x8694000 device→IDA in the
  merged db), high bits per-object tag; class→name via ro+0x18, but the device bits word is
  ptrauth-signed — resolve class names statically in IDA, not on device.
- poolwalk (LLDB-python autorelease-pool walker, research/aks-e07/poolwalk.py) — reads pool
  pages at a releaseUntil freeze, names live entries, flags stale/freed ones. This found the
  double-autorelease that the whole deferred-crash hunt had missed.
- Early-boot law: daemons spawning before the injection stage enables (coreauthd, keybagd,
  SpringBoard at boot) run tweak-less — recycle them post-boot for any shim work.
- LLDB python (no expr JIT — hardened targets block expression evaluation) can read remote
  memory for structured introspection when `malloc stack`/expr are unavailable.
