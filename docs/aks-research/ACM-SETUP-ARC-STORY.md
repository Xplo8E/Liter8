# The passcode setup arc: how far a SEP-less iPhone gets, and where the real wall stands

> Story-grade writeup of the 2026-11-05 session arc (internal explanation /
> blog seed). Companion documents: E07-passcode-milestone-recon.md (the
> decode record with addresses), SEPLESS-AKS-RESEARCH-STORY.md (the earlier
> keychain arc). Everything below was measured on iPhone 12,1 / iOS 27.2
> 24B119 booted Liter8 (SEP-less, diagnostic-mode profile).

## The question this arc answers

A jailbroken iPhone without a Secure Enclave can be *told* it has no
passcode — we proved that first. The harder question is the one Vinay set
as this arc's goal: **can it actually run the passcode flows** — Turn
Passcode On, enter a code, Change Passcode, Turn Passcode Off — with
nothing SEP-shaped behind it?

The answer after this arc: **the entire userspace gate stack can be beaten
with four hooks, the credential can be encoded with our own crypto, and
the flow dies at a wall we can now name precisely: the credential STORE is
a kernel-side user client, not userspace at all.** Everything needed to
emulate it is mapped. The emulation itself is the next arc.

## Act 1 — the lie that started it all

Since the first Liter8 boot, Settings showed "Enter your passcode to
unlock this iPhone" on the Face ID & Passcode pane. Tapping through it
crashed Settings with `Failed to obtain encryption size -3` — ACM, the
Secure Enclave credential subsystem, answering that there is no SEP to
encrypt against.

The obvious suspects were all innocent. The keybag shim didn't cause it
(it predates every experiment). The LAContext hooks didn't intercept it
(the pane doesn't route through LAContext evaluate at all). The kernel
AKS lock-state scalar was decoded bit by bit — bits 2/6/7 consumed, none
of them a passcode flag — and it turned out to feed only the lock/unlock
family and the Stolen Device Protection lockout state, not the pane.

The actual answer was found by probing the whole LAPS persistence family
with forwarding hooks and watching which one answered: **the pane's
passcode belief comes from `LAPSPasscodePersistenceMCAdapter.hasPasscode`,
which asks `MCProfileConnection` — ManagedConfiguration, the MDM profile
store.** A persisted, daemon-owned state that answered YES since day one,
knows nothing about keybags, and was never told otherwise because keybagd
on this boot can't report passcode state through its broken AKS path.
Fail-closed, forever.

One interposer method answering NO there flipped the pane to the
no-passcode view. Day-one behavior: solved with one hook.

## Act 2 — the gate stack, in order of discovery

With the pane showing "Turn Passcode On", tapping it walked a stack of
gates, each named by live logs, then pinned by live LLDB (debugserver
over iproxy, single-connect discipline):

1. **The LAPS family gate** — `hasPasscode` on nine
   `LAPSPasscode*` classes; overridden to NO; consistent cascade observed.
2. **The SDP change ratchet** — "Security Delay Required to Change
   Passcode". It demands authentication via `evaluatePolicy:1026`, and
   the arm request made **coreauthd itself crash**: it fetches the ratchet
   config-and-status from the SEP interface and a payload-anomaly
   tripwire deliberately aborts the daemon on the malformed SEP-less
   payload ("Ratchet config-and-status payload anomaly (reason=1)" →
   corpse). Fixed by intercepting
   `performArmRequestWithContext:options:completion:` in-process and
   completing with a nil result — the daemon never sees the request.
3. **The seed fetch** — encoding a credential needs an encoding seed,
   fetched over a synchronous XPC to coreauthd, whose reply carried
   malformed objects that SIGSEGV'd Settings during the autorelease pool
   pop of the transaction. Fixed by serving the seed locally:
   SHA-256 of the shim master key, deterministic so encode/decode stay
   HKDF-consistent. Reply block encoding `v@:@?` (the block-typed
   argument) — one of those "read it from the live runtime" details.
4. **The credential encode** — the real crypto. `ACMEncryptDataEx`
   two-phase (query size, then encrypt), SEP-bound, -3 without a SEP.
   Now answered by **l8acm**: AES-256-CTR + HMAC-SHA256 over a 32-byte
   master key (`/var/mobile/Library/l8acm.master`), tag binding the
   caller's seed and ACM externalized context. 6-byte passcode → 62-byte
   L8CM blob, encoded in software, on device.

Each gate was a hook; each hook was live-validated; the crash logs and
LLDB traces for all of them are in the session records.

## Act 3 — the wall, named

After the encode succeeds, the flow sends the encoded credential to
**coreauthd** for storage (`LACSContext storeCredentialData:securely:error:`
→ XPC). The reply from that transaction poisons Preferences' autorelease
pool: a later runloop cycle pops the pool, releases the poisoned object,
and SIGSEGVs on its freed chunk. We caught it live in LLDB (attached
through iproxy, single-connect discipline — the recipe is committed as a
memory note), inspected the freed chunk (isa bits decode to garbage,
freed-pattern word in the second qword), and disproved our own shim as
the source (the MRC-vs-autorelease seed fix changed nothing).

The storage the flow wants is not userspace. Following the daemon-side
binary (`AppleCredentialManagerDaemon` — a 178 KB on-disk binary, not a
cache image, which is why it never appeared in the DSC dialog) mapped the
entire remaining stack:

```
ACMLib (statically linked into every client — LocalAuthenticationCore,
        ManagedConfiguration, acmd, ...)
  → IOServiceOpen("/IOResources/AppleCredentialManager")
  → AppleCredentialManagerUserClient        (kernel extension)
  → SEP-backed context store                (the actual wall)
```

**46 client functions** enumerated from the acmd binary: context
lifecycle (`ACMContextCreate/LoadFromImage/UnloadToImage/Delete`),
the data store (`ACMContextSetData/GetData/CopyData`), credential
management (`AddCredentialWithScope/RemoveCredentials…`), the verify
engine (`ACMContextVerifyPolicyEx + Preflight + CopyRequirementEx`),
SEP specials (`ACMSecContextGetUnlockSecret`, `ACMSEPControl`), and the
kernel control channel (`ACMKernelControl`, `ACMKernDoubleClickNotify`).

That is the wall's exact shape: an IOKit user client whose methods are
the passcode subsystem's real API.

## The architecture that beats it (next arc)

The client library is statically linked into each consumer, so the ACM
functions themselves are not interposable. But their **transport is**:
`IOServiceOpen` / `IOConnectCall*Method` are IOKit framework exports,
dyld-interposable from the proven TweakInject pattern. One shim can:

1. filter `IOServiceOpen` for the AppleCredentialManager service,
2. hand every caller an emulated user client handle,
3. serve the hot subset of the 46 methods from a software context store
   (the l8acm-core crypto already covers the credential parts),
4. let everything else pass through.

coreauthd, Preferences, and any other client then run against a working
software ACM with no SEP — the same "software subsystem behind an
interface" play as l8keychain, one layer up. The decode work remaining
is ACMLib's user-client selector dispatch (which method numbers map to
which of the 46 functions) — decodable from LocalAuthenticationCore,
already in the IDA cache set.

## Lessons worth keeping (debug craft)

- **Probe families, not functions.** The pane lied through a *family* of
  nine persistence classes; forwarding probes on the whole family found
  the answering one in a single boot cycle. Hook-by-guess would have
  burned five.
- **os_log privacy is a format-specifier choice.** `%@` redacts; 
  `%{public}@` doesn't. Our own probe logs were unreadable until we
  publicized our own specifiers — the device-side "don't redact" knob
  was never needed.
- **Single-client debugserver.** One `process connect` per
  debugserver instance; zombies make later connects fail *silently*
  ("Command requires a current process" with no error on the connect).
  Clean both ends: `target delete`, kill device debugservers, restart.
- **`launchctl setenv` beats LLDB `setenv`** for env vars on
  uiopen-launched apps: the expression path on a stopped attach target
  does not evaluate, but launchctl reaches the next launch.
- **MRC across an ARC boundary**: an alloc+release on an object the ARC
  machinery also owns over-releases once the pool drains. Symptom:
  delayed SIGSEGV in `AutoreleasePoolPage::releaseUntil` on a chunk
  whose isa decodes to garbage. Fix: autoreleased factory objects.
- **Verify deploys twice.** A staged mv raced once and burned a boot
  cycle on stale bytes; `sync` + a second-connection md5 is the
  minimum proof.

## Where this leaves the device

Build 12 (`efdad204…`) on device: pane fixed, no crashes on pane entry,
Set Passcode screen reachable, credential encode working, coreauthd no
longer killed by the flow. Committed: `e707aab`, `f4aa4ff`, `8bf99f5`
on `research/e07-passcode-gate` (not pushed; PR #34 remains the keychain
arc and stays draft). The next arc — the IOKit user client emulation —
has its recon complete and its architecture chosen; it is a multi-session
project and starts with the selector-dispatch decode.
