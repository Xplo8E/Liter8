# E04 design note: securityd class-key provider (post-E06 iteration 1)

**Status:** design, not implementation. Date 2026-11-03. Evidence tags per
research.md. Companion to AKS_INTERFACE_MAP.md and the E06 run record
(`runs/2026-11-03-E06-selector10-wrap-reply/`).

## Where the system stands after E06 iteration 1

The E06 kernel shim answers AKS selector 10 (wrap) with a coherent status
reply. securityd's `SecDbKeychainMetadataKeyStore` wrap path now completes and
keychain adds fail **cleanly** at the next gate instead of writing corrupt
rows:

```text
ks_encrypt_data (db): failed: -25291
ks_crypt: failed to 'oe' item (class 6, bag: 0)
```

Runtime probe (run dir `06-keybagd-negotiation-probe.txt`): **keybagd logs
nothing during an add**. securityd never asks keybagd at this gate; `bag: 0`
is securityd's own in-process keychain keybag state. The provider therefore
must live inside securityd. `[V]`

## The gate, from the binary

`ks_crypt_diversify` = `0x1001aa0e8` in the 24B119 securityd binary
(`research/offsets/24B119/securityd`). Decoded structure `[V]`:

1. Obtains the AKS client (`0x100278efc`); missing -> error `-0x6c`.
2. Looks up a bag/state (`0x100278f2c(client, 0xf, arg7, stack_arg)`) and two
   output objects (`0x100278f1c`).
3. Dispatches on arg0's operation selector: compared against selector
   globals at `0x100355d90/d98/da0` (the `%@` in the error is the operation,
   `oe` = encrypt, `od` = decrypt `[I]`).
4. Consults a key dictionary with the sentinel magic
   `0xAAAAAAAAAAAAAAAA` (`0x100278f9c(obj, &magic)`) — the "key available"
   lookup.
5. Lookup miss -> the logging cluster at `0x1001aa374..0x1001aa590` with the
   `No key available for class` format; hit -> encrypt/decrypt via AKS ref
   keys (`aks_ref_key_encrypt` / `aks_ref_key_decrypt` imports).

The binary also imports `aks_ref_key_create` and
**`aks_ref_key_create_with_blob`** — a ref key can be minted from raw key
bytes without any SEP involvement. `[V]` (import table)

## Proposed provider (l8keychain, weak-loaded into securityd)

Follow the established shim contract (target process, marker kill switch,
pass-through otherwise):

1. **Hook point:** the bag/key-lookup step of `ks_crypt_diversify` — located
   semantically per build via the `No key available for class` format-string
   xref (`0x2c8de4`-family) into the function head, exactly as E06's anchor
   discipline. C++/no-symbols, so this is an MSHookFunction on the resolved
   entry, gated on the same arity/type checks the other shims perform where
   possible.
2. **Software keys:** on first use, generate 256-bit class keys for the
   system classes (6 first; others only when a consumer demands them),
   persist them in one 0600 root-owned file next to the l8pair DER
   (`/private/var/root/Library/lockdown/` pattern), and mint ref keys via
   `aks_ref_key_create_with_blob`. Cache the ref-key handles.
3. **Consistency:** the same persisted key must serve both `oe` and `od`,
   and both the metadata-key store (`SecDbKeychainMetadataKeyStore`) and
   item encryption (`ks_crypt`) — then items are readable across reboots,
   which is the entire point. The wrap side additionally depends on the E06
   kernel selector-10 reply (deployed).
4. **Explicit limits (must be documented in the profile comment):** these
   keys protect nothing (no SEP, no passcode binding, file is 0600-root like
   l8pair's DER). Any attacker with root reads them. This is compatibility,
   not security.

## Open questions before implementation

- The exact signature/layout of `ks_crypt_diversify` args (C++ ABI, no
  symbols). Resolution: LLDB hardware breakpoint at `0x1001aa0e8` on the live
  securityd during an `e01probe` add, capturing x0-x7 + stack args; the
  runtime arg dump plus the decoded flow pins the hook ABI.
- Where the ref-key dictionary lives so the provider can INSERT rather than
  bypass (preferred: insert into the dict, keep Apple's encrypt path intact).
- Whether `aks_ref_key_create_with_blob` requires a live AKS user client
  session (the E06 kernel answers selector 10; ref-key create uses different
  selectors — capture them at runtime for the R01 map).
- Which classes must be provided for the priority consumers: 6 observed;
  lockdownd identity (key class), RemotePairing items and the metadata-key
  store's own class need enumeration from their add failures.

## Recommendation

Proceed as E04: this is the userland compatibility layer the research plan
prefers (Case A confirmed twice: metadata-key wrap in E06, class-key gate
here), and if it works it replaces l8wifi + l8pair + l8remotepairing
keychain persistence with one layer and makes every system-keychain consumer
work. The kernel selector-10 shim (E06 iteration 1) is a prerequisite and is
deployed.

## Update: ObjC swizzle targets found (same night, post-capture attempt)

The runtime ABI capture at `ks_crypt_diversify` never fired: the add-path
-25291 error uses a **different sibling** — the plain `ks_crypt` formats
(`ks_crypt: %x failed to '%@' item (class %d, bag: %d) No key available for
class.` at `0x2c8fe5`) which have NO detectable xrefs (no adrp+add, no fixup
slot — the plain-ks_crypt family loads formats via computed offsets). Static
ABI pinning on that C layer is a dead end, and it is unnecessary:

**securityd's ObjC metadata symbolizes the whole item-encryption surface**
(`[V]` from the ObjC method list), including:

- `-[SecDbKeychainItemV7 metadataClassKeyWithKeybag:allowWrites:error:]`
  `0x100012bac` — the per-item class-key getter. Thin wrapper: reads the
  item's class at `self+0x30`, dispatches one class-method
  (`0x100288560` on the Class ref at `0x1003c4748`) with
  (class, keybag, allowWrites, error).
- `-[SecDbKeychainItemV7 encryptSecretDataWithKeybag:accessControl:acmContext:error:]`
  `0x100013f94`
- `-[SecDbKeychainItemV7 encryptedBlobWithKeybag:accessControl:acmContext:error:]`
  `0x100013e34`
- `-[SecDbKeychainItemV7 initWithData:decryptionKeybag:error:]` `0x1000104cc`
  (the decrypt side)
- `-[SecDbKeychainItemV7 wrapToAKS:withKeybag:accessControl:acmContext:error:]`
  `0x10001363c`

`[I]` design consequence: an l8keychain tweak can swizzle these **ObjC
methods directly** (class_getInstanceMethod + method_exchangeImplementations,
the l8localauth pattern — arity + encoding checked) instead of hooking the
symbol-less C layer. The swizzles wrap the software class keys at
`metadataClassKeyWithKeybag:` (supply a key object minted from the persisted
software key) and let Apple's encryption code run; the decrypt side
(`initWithData:decryptionKeybag:`) receives the same keys, giving
round-trip consistency. `keybag:` arrives as nil on this boot and must be
tolerated (the swizzle never forwards into ks_crypt for the provided
classes).

Remaining decode before implementation: the class-key object type returned
by the manager class method (what the swizzle must construct — NSData of raw
bytes vs a key-handle object) and the exact per-item flow order (metadata
class key vs secret-data encryption). Both are runtime-observable with the
established LLDB setup (bp at `0x100012bac` + arg/object dumps during an
`e01probe` add).

## Runtime captures on the live securityd (2026-11-03, final session)

Setup: debugserver attach to securityd (pid 122, load 0x104d94000, slide
0x4d94000) driven through a persistent FIFO-fed lldb session. Findings `[V]`:

1. `ks_crypt_diversify` (0x1001aa0e8) **never fires** during a real add — the
   runtime -25291 uses the plain `ks_crypt` sibling, whose format strings have
   no static xrefs (computed format offsets). Static ABI pinning on the C
   layer is a dead end; closed.
2. `-[SecDbKeychainItemV7 encryptSecretDataWithKeybag:accessControl:acmContext:error:]`
   (`0x100013f94`) DOES fire during the add: keybag arg = nil (x2=0), called
   from `encryptedBlobWithKeybag:` (`0x100013e34+128`) from the insert
   machinery. Returns nil + error via the error out-param. E06 session-2
   backtrace showed the inner chain
   encryptSecretData -> wrapToAKS -> aksEncryptWithKeybag, i.e. the metadata/
   AKS wrap sits INSIDE this method while the class-key ks_crypt gate fails
   alongside.
3. Full `SecDbKeychainItemV7` ObjC surface (method list + ivars):
   - methods: `initWithData:decryptionKeybag:error:` (decrypt/plaintext entry,
     0x1000104cc), `initWithSecretAttributes:metadataAttributes:tamperCheck:keyclass:`
     (0x100020398), `encryptedBlobWithKeybag:` (0x100013e34),
     `encryptSecretDataWithKeybag:` (0x100013f94),
     `encryptMetadataWithKeybag:` (0x10001fe58), `metadataClassKeyWithKeybag:allowWrites:`
     (0x100012bac), `wrapToAKS:withKeybag:accessControl:acmContext:error:` (0x10001363c),
     `unwrapFromAKS:accessControl:acmContext:callerAccessGroups:delete:keyDiversify:error:`
     (0x10000db8c) (the decrypt side), `encryptedSecretDataBlob` (0x10001bd8c),
     `encryptedMetadataBlob` (0x10001bcd0), `keyclass` (0x10017ab80),
     `secretAttributesWithAcmContext:...`, `deleteWithAcmContext:...`
   - ivars: `_encryptedSecretData`, `_encryptedMetadata`, `_secretAttributes`,
     `_metadataAttributes`, `_tamperCheck`, `_keyclass`, `_keybag`
   - the item carries its OWN `_keybag` ivar (nil on this boot).

## l8keychain v1 design (final)

All name-based (class_getInstanceMethod + sel_getUid at load time; ivars via
class_getInstanceVariable/ivar_getOffset by name) — no baked offsets, works
across builds that keep the selectors.

- Swizzle `initWithData:decryptionKeybag:error:`: capture arg1 (the client's
  plaintext secret NSData) into a side table keyed by the new item object.
  The item's own `_keybag` is nil and is never forwarded into ks_crypt.
- Swizzle `encryptSecretDataWithKeybag:accessControl:acmContext:error:`:
  take the stashed plaintext, encrypt with AES-GCM under a per-class
  software key (HKDF(master, class); master = 32 random bytes persisted 0600
  at `/private/var/root/Library/l8keychain.master` on first use), set the
  blob (`_encryptedSecretData` or the method's own storage via the original
  setter path replaced by direct construction), return the blob object.
  Format: magic `L8KC` | version | class | 12-byte nonce | ct | 16-byte tag.
- Swizzle the decrypt side (`unwrapFromAKS:...` and/or
  `initWithData:decryptionKeybag:` of the READ path — decode which at
  implementation time with one bp): parse the L8KC blob, AES-GCM-decrypt
  with the same per-class key.
- Marker `/private/var/root/Library/.liter8-keychain` (root-owned kill
  switch, same contract as l8pair/l8wifi).
- Explicit limits: keys in a 0600 root file, no SEP, no passcode binding,
  no ACL enforcement (record ACLs as software). This is compatibility, not
  security.

## Why v1 avoids the metadata store entirely

`SecDbKeychainMetadataKeyStore` (wrap/unwrap via E06 selector 10) manages
per-DB metadata encryption. With l8keychain providing item-level crypto
directly, the metadata store's fake-wrapped key is never consumed on the
provided classes' items, sidestepping the unverified metadata unwrap reply
entirely. Items from OTHER consumers that still use Apple's path behave
exactly as today (fail cleanly).

## Next session

1. Write `device/keychainprobe/l8keychain.m` per this design (swizzles +
   CommonCrypto AES-GCM + marker + persistence), self-test on host.
2. Provision into securityd (weak load or TweakInject for the ObjC daemon;
   securityd has ObjC runtime), reboot, run the E01 CRUD matrix + reboot
   persistence readback.
3. Expected positive signal: add returns 0 AND read-immediate returns the
   secret (the first readable keychain item on this boot), persistence
   across reboot via the master key file.

## ks_crypt runtime-address hunt (2026-11-03, latest) — state preserved

Target: find plain `ks_crypt`'s runtime entry to hook it for the class-key
provider. Status: NOT yet found; the hunt produced these verified facts:

1. The ks_crypt error text ("ks_crypt: %x failed to '%@' item...") is NOT an
   os_log FORMAT — it is DATA (an NSError description string). Filter-bps on
   os_log functions cannot match it. The message reaches oslog as the
   description of an error object logged with a generic format.
2. The family formats ARE referenced through a computed/indexed mechanism:
   fixup slots exist (0x10037c808 -> 0x2c8fd8, 0x10037c848 -> 0x2c909e,
   0x37c868 -> 0x2c90db, strided 0x20) but no adrp/ldr pair in __TEXT loads
   them (verified with corrected page arithmetic — earlier "no xref" scans
   were vacuous due to a missing 0x100000000 base in the page computation;
   the FIXED scanner verified against known pairs, e.g. adrp x2, 0x37c000 at
   0x1001aa210). The slots are indexed at runtime (base+index*32 or similar).
3. The error string is built via CFString formatting
   (`CFStringCreateWithFormatAndArguments` island confirmed in the log
   helper), but a python-callback bp on it (reads fmt CFString content for
   "ks_crypt") saw 25+ hits with no match — consistent with the error
   CFString being CONSTRUCTED ONCE AND CACHED (first-failure-only
   construction), or built via mutable-string append.
4. Runtime-verified: `-SecDbKeychainItemV7 encryptSecretDataWithKeybag:`
   fires during add with keybag=nil, returns nil+error, from
   `encryptedBlobWithKeybag:` <- insert machinery.

### Route for the next session (highest probability)

Attach debugserver+lldb IMMEDIATELY after a reboot, BEFORE the first
keychain operation, arm the CFString bp with the content-matching callback,
then run the FIRST add — the first ks_crypt failure constructs and caches
the error CFString, so the bp fires inside ks_crypt's error path. Then:
lr -> scan back for pacibsp -> ks_crypt entry -> bp entry -> ABI capture on
the following add. After the ABI is known, write the l8keychain shim
(MSHookFunction on ks_crypt at the runtime address located by in-process
pattern match of its prologue bytes, which the capture provides), with the
software class-key provider (aks_ref_key_create_with_blob path).

Alternative if CFString-caching defeats the first-add approach: capture
during the very FIRST keychain operation after an ERASE (fresh securityd
databases), or on the SSHRD (different userspace, same ks_crypt code path
for metadata... verify applicability first).

Device state at checkpoint: E06 kernel ON device (serial=3, boot-jit,
booted 21:13), securityd pid 122 resumed and healthy, no debugserver
attached, e01probe + mkbprobe on /var/root, l8keychain master-key file not
yet created. lldb PTY sessions closed.

## ks_crypt located (final capture of 2026-11-03)

Plain `ks_crypt` static entry: **0x1001aae20** (24B119 securityd). Identified by
full-function decode (152 instructions): 7 register args + stack, arg4 is the
operation NSString ('oe' encrypt / 'od' decrypt, dispatched via strcmp helpers),
arg5 gates the diversify block, arg6 feeds the AKS client getter, then the
keybag lookup (0x100278eec) and the operation (0x100278f5c). Error branches log
the ks_crypt family formats via the 0x10000b570 helper; one branch returns
-26275 (errSecDecode). The runtime -25291 (errSecNotAvailable, "No key available
for class") is the no-keybag outcome of the keybag lookup (arg bag = nil/0).

Runtime entry = securityd load + 0x1ae20 (0x104DAEE20 at load 0x104d94000).
Next session: runtime ABI capture at this entry during an e01probe add (dump
x0-x7 + stack + memory at pointer args), then write the l8keychain shim
(MSHookFunction intercepting 'oe'/'od' for class 6 with software AES-GCM under
a persisted master key), provision, CRUD + reboot persistence matrix.

## 2026-11-04: family bp sweep — negative result + Apple contract found

HW bps at all four decoded ks_crypt-family entries (0x104f3e0e8/ee20/f1fc/f7a8):
ZERO hits during a full probe with 21 adds failing -25291. The add-path
ks_crypt is a different code region, not yet located.

Steering correction incorporated: `bag: 0` is NOT evidence of an empty keybag.
Apple's SecKeybagSupport.h (OSX/sec/securityd, Apple-FOSS-Mirror/Security):
`g_keychain_keybag = 0 /* 0 == device_keybag_handle, constant dictated by AKS */`
and the full contract:
`bool ks_crypt(CFTypeRef operation, keybag_handle_t keybag, keyclass_t keyclass,
uint32_t textLength, const uint8_t *source, keyclass_t *actual_class,
CFMutableDataRef dest, CFErrorRef *error)` — x0=op ('oe'/'od'), x1=bag handle
(0 = DEVICE keybag, the normal value), x2=class (6 = key_class_ak),
x3=textLength, x4=source bytes, x5=actual_class out, x6=dest CFMutableData,
x7=error out, returns bool. The failure "No key available for class" means the
DEVICE keybag lacks a class-AK key — the keybag store was never loaded on this
boot (no systembag.kb) — not that the bag argument was empty.

Next: locate the real add-path ks_crypt at runtime via bp on
__os_log_default_impl (Notice funnel) + per-stop x3 polling for the
0x10505c/0x10505d fmt range during an add; LR -> pacibsp scan -> entry ->
ABI verify against the Apple contract above; then l8keychain hooks that
entry (software AES-GCM for 'oe', reverse for 'od', CFMutableData append,
*actual_class set, return true).

## 2026-11-04 late: CFString cache hypothesis + reboot protocol

The CFString content-match bp (on CFStringCreateWithFormatAndArguments, reads
fmt CFString data for "ks_crypt") saw 25+ hits with no match during a probe
whose adds failed -25291 — yet the -25291 path necessarily builds the
"ks_crypt: %x failed..." description at least once per boot. Explanation
[I]: the error CFString is constructed on the FIRST failure of a boot and
cached (the -25291 was first seen at 21:15; the bp was armed ~00:40).

**Reboot protocol for the ABI capture:**
1. After pwnDFU re-entry and `fw boot --serial` (E06 set), wait for SSH.
2. Restart debugserver (attach securityd, port 4321) + PTY lldb + tunnel.
3. Arm IMMEDIATELY, before any keychain operation:
   - bp on CFStringCreateWithFormatAndArguments + python content-match
     callback (/tmp/l8cfstr.py pattern: reads fmt CFString data ptr at +0x10,
     stops when content starts with "ks_crypt").
   - Optionally also the _os_log_impl plain-fmt pointer condition
     (load + 0x2c909e).
4. Run `/var/root/e01probe full` (re-push first) — the FIRST add of the boot
   constructs the error CFString → bp fires inside ks_crypt's error path.
5. `register read lr` → scan back for pacibsp → ks_crypt entry →
   `breakpoint set -H -a <entry>` → continue → next add hits entry →
   capture x0-x7 + stack + memory at pointer args (expect Apple contract:
   x0=op 'oe', x1=bag handle 0=DEVICE, x2=class 6, x3=textLength, x4=source
   bytes, x5=actual_class out, x6=dest CFMutableData, x7=error out).
6. Also capture the decrypt attempt path if reachable (probe's read steps
   fail before ks_crypt on this boot; decrypt capture may need the shim).

Verify before relying: the CFString cache hypothesis is [I]; if the bp still
does not fire on the first add, the construction path differs (try
CFStringCreateWithFormat, mutable-append, or CFErrorCreate internal paths).

## 2026-11-04 morning: round-2 sweep — negative

Fresh securityd instance (pid 2372, load 0x102418000 — the daemon restarts
periodically; always recompute the slide via `image list`). HW bp at the
decoded cluster entry (runtime 0x1025c2e20): 0 hits during a full probe with
-25291 add failures. Combined with the four-entry sweep: none of the
0x1001aa000-0x1001ab900 cluster functions execute during genp adds, though
the -25291 "ks_crypt: %x failed..." errors still appear in oslog.

Working explanation [I]: the ks_crypt-family error logging emits the text as
an ARGUMENT (the error description built by CFStringCreateWithFormat...) and
the Notice line reaches oslog through a generic "%@" funnel — so x3 at the
os_log impl is a generic format, never the ks_crypt literal. The emitting
function is therefore findable by breaking on __os_log_error_impl (unconditioned)
during an add and reading the args buffer (x4) for the "ks_crypt" text; its
LR identifies the real error path. Alternatively, the add path may not call
the 0x1001aa-cluster at all because securityd 2372's keybag object returns
"No key available" from an earlier gate than the cluster functions cover.

Both candidate routes are recorded; no device changes outstanding. Device:
E06 kernel, securityd 2372 healthy and detached, e01probe removed from
device, rollback set intact.

## 2026-11-04: ks_crypt contract VERIFIED from IDA (decision-ready)

IDA session (database `securityd`, hash 556ce02ff717, renames by Vinay):
`ks_crypt` = **0x10000D34C** (plain variant; the four earlier bp targets were
the diversify/ACL variants — explaining the zero-hit sweeps).

### Verified contract (decompiled, 10 args — one more than the old header)

```c
bool ks_crypt(CFTypeRef operation,   // x0 "oe"|"od"|"odel"
              int64 keybag,          // x1 handle (0 = DEVICE, per AKS)
              int64 backup_keypair,  // x2 personaId/backup pair (NULL = normal)
              int64 keyclass,        // x3 (6 = key_class_ak)
              int64 textLength,      // x4
              const uint8_t *source, // x5
              int *actual_class,     // x6 out
              CFMutableDataRef dest, // x7 out — USED IN PLACE
              char use_backup_keybag,// stack
              CFErrorRef *error);    // stack
```

Flow (decompiled):
- "oe": MutableBytePtr = CFDataGetMutableBytePtr(dest); aks_wrap_key(source,
  textLength, keyclass, keybag, ptr, &destLen, actual_class); status 0 ->
  CFDataSetLength(dest, destLen); return true.
- "od": aks_unwrap_key(blob, len, class, bag, ptr, &destLen); status 0 ->
  CFDataSetLength(dest, destLen); return true.
- backup paths via aks_kc_backup_wrap/unwrap_key when use_backup_keybag.
- Error switch on AKS status: 0xE00002F0 -> -25291 "No key available for
  class."; 0xE007C013 / 0xE00002FC -> -26275 "drop the item"; 0xE0000201 /
  0xE0000232 -> -25308 "keychain is locked"; default -> for "od"/"odel" try
  encrypted_data_from_blob (blob-fallback via aks_ref_key_create_with_blob,
  keys "d1"/"2" in the blob dict) then -25291 plain; for "oe" -25291 plain.

### Runtime -25291 explained

Our E06-kernel failure: aks_wrap_key returned a generic non-zero status (the
libAppleKeyStore side rejects the fake-success output — the E06 kernel shim
writes only the scalar status, not a valid wrapped-key structure). That
generic status matches no special case -> plain -25291. So the E06 kernel
reply fixed the transport but AKS still produced no usable wrapped key.

### Decision: Option A — hook ks_crypt (recommended)

Rationale:
1. Single choke point: ALL keychain item encryption (secret data, metadata
   keys, ACL blobs) funnels through ks_crypt — confirmed by its callers
   (aksEncryptWithKeybag, aksDecryptWithKeybag, ks_encrypt_data,
   ks_decrypt_data).
2. Apple contract fully known — dest is written in place and resized with
   CFDataSetLength; blob format for software items is ours to define.
3. Decrypt consistency is automatic: same hook handles "od" for the same
   blob format.
4. Smaller surface than option B (which would require fabricating keybag
   key material below ks_crypt inside AppleKeyStore).
5. Pass-through for everything else (backup-keybag paths, other classes)
   preserves existing behavior.

### Implementation sketch (NOT yet implemented — decision gate)

l8keychain.dylib loaded into securityd (TweakInject filter com.apple.securityd
or weak-load), marker /private/var/root/Library/.liter8-keychain:
1. Locate ks_crypt in-process: scan __TEXT for adrp/add pairs materializing
   the CFSTR("ks_crypt: %x failed to '%@' item (class %d, bag: %d)")
   constant (or the oslog-string byte pattern), OR MSHookFunction on the
   address derived from the static per-build offset encoded in a
   per-build profile (research discipline: semantic anchor preferred).
2. MSHookFunction(ks_crypt, replacement):
   - "oe" + supported class: AES-GCM(software key[class], source) -> blob
     (L8KC magic | class | nonce | ct | tag) -> write to dest via
     CFDataSetLength + memcpy; *actual_class = keyclass; return true.
   - "od" + L8KC blob: reverse. Non-L8KC blob: pass through to original
     (fails honestly).
   - Everything else: original.
3. Software keys: 32-byte per-class keys HKDF'd from a master persisted
   0600 at /private/var/root/Library/l8keychain.master (create on first use).

### Known limits (documented, intentional)
- Software keys protect nothing (0600 file, no SEP, no passcode binding).
- ACL/ACM data is not enforced (recorded in blob as "software" class).
- Items written while enabled are L8KC blobs; disabling the shim makes
  them unreadable (fail honestly, documented).
- keyclass 6 only for v1; other classes pass through.

## 2026-11-04 11:00: ks_crypt ABI CAPTURED LIVE (Phase 2 complete)

Steering-correction validated, negative-sweep explained, ABI captured:

1. **Fresh securityd instance** (2696, load 0x102760000 — the daemon restarts
   periodically; recompute the slide every session via image list).
2. HW bp at ks_crypt entry (load + 0xd34c): **fired on the first add** —
   confirming this IS the live add-path ks_crypt (the earlier zero-hit sweeps
   were against restarts that had already cached/funnelled differently, or
   the stale-slide bp address — session 14's 0x18ed9d5ec was a stale-slide
   address for _os_log_impl, and the same mistake caused the 0x104daee20/
   0x10492934c wild-goose chase: always recompute load per session).

### Captured entry state (first call during add)

```text
x0 = @"od"                    operation = DECRYPT (metadata-key read path)
x1 = 0                        keybag = KEYBAG_DEVICE (0) — Apple contract ✓
x2 = 0                        backup_keypair = NULL — normal path ✓
x3 = 0x27 (39)                keyclass = 39 (securityd metadata key class)
x4 = 0x80 (128)               textLength — the 128-byte metadata blob
x5 = 0x7391120650             source blob pointer (all-zero = never decrypted
                              — AKS returned error without touching it)
x6 = 0                        actual_class out NOT requested
x7 = 0x7391124240             dest CFMutableData
```

Matches the 10-arg IDA signature exactly (x2=backup NULL, x6=actual_class
NULL-able). The read-before-write path decrypts the EXISTING metadata key
blob first; with no device-keybag class key, AKS returns the error without
writing the plaintext — the -25291/no-key failure explained end-to-end
(`ks_crypt` → caller logs the failed-decode "corrupt genp" behavior).

## l8keychain v1 scope (final)

Hook ks_crypt; for "oe"/"od" on classes {6, 39}: software AES-CTR + HMAC
(keyclass-scoped keys from persisted master); blob L8KC | ver | class |
nonce | ct | mac; dest written in place + CFDataSetLength; *actual_class
set; return true. Everything else → original. Marker-gated.


## 2026-11-04 late: live ABI capture on current boot (Phase 2 complete)

Fresh debugserver attach to securityd 2696 (load 0x102760000, same UUID
DDBEB229-...). HW bp at ks_crypt entry (0x10276d34c). Two live captures:

**Capture 1** (first add of the probe):
x0=@"od", x1=0 (KEYBAG_DEVICE), x2=0 (backup NULL), x3=39 (metadata keyclass),
x4=0x80 (128), x5=source blob ptr (contents all-zero), x6=NULL, x7=dest
CFMutableData. Operation = DECRYPT of the existing 128-byte metadata blob —
the read-before-write path.

**Capture 2** (second call):
x0=@"od", x1=0, x3=10 (keyclass 10), x4=128, x5=source zeros. Backtrace by
symbol: ks_crypt <- aksDecryptWithKeybag (0x10000da64+220) <-
validateWrappedKey:forKeyClass:actualKeyClass:keybag:keySpecifier:error:
(0x100211ad0+156) <- fetchKeyForClass:fromDb:keybag:specifier:allowWrites:
(0x100212690+180) <- SecDbKeychainMetadataKeyStore glue (0x1002128a4+92).

`finish` from a hit: thread stepped out to the caller resume point
(aksDecryptWithKeybag+220) — return-path capture works via finish on this
setup. (The returned w0 itself was not sampled before the thread resumed;
the IDA decompile already documents the return contract: bool with the
CFError out-param on failure.)

### Confirmed understanding (all [V])

- ks_crypt entry = load + 0xd34c; fires during every add (metadata read and
  secret wrap both funnel here via aksDecrypt/aksEncrypt and the metadata
  store).
- keybag handle = 0 = KEYBAG_DEVICE (normal value, per Apple
  SecKeybagSupport.h).
- Two different keyclasses observed: 39 and 10 (metadata-store classes;
  neither is class 6 — class 6 is the ITEM secret class seen in the earlier
  session-2 aksEncrypt capture).
- source blob arrives zero-filled: AKS (below) returns "no key" without
  producing the wrapped output — the zero source + bool-false + CFError is
  the observable -25291 behavior at this layer.
- The failure is INSIDE AppleKeyStore (aks_wrap_key/aks_unwrap_key), one
  layer BELOW ks_crypt — ks_crypt only maps the returned status to
  OSStatus/CFError.

### Decision (Phase 3, confirmed)

Option A: hook ks_crypt. Rationale unchanged and now stronger: the hook
sees every metadata + secret crypto call with the full 10-arg verified
ABI, and the software implementation owns both directions ("oe"/"od") so
round-trip consistency is guaranteed without touching AppleKeyStore or
the keybag. Phase 2 complete; implementation is the next task.

## Appendix: 2026-11-04 app-crash incident (arm64e slice in TweakInject) [V]

**Symptom (user report):** apps crash on launch, including Settings.

**Device evidence:**
- `l8keychain.dylib` + `l8keychain.plist` (Foundation filter) sat in
  `/var/jb/usr/lib/TweakInject/` since the 2026-11-03 evening deploy.
- oslog capture while `uiopen prefs:` launched Settings: 100 fatal exceptions
  in 10 s, all identical signature `type=0x1 reason=0x2a code=0x32`
  (EXC_BAD_ACCESS, KERN_CODESIGN_ERROR), fault offsets ending `0x41c000`,
  crashers included Preferences (pid 11379, exit code 50), parsec-fbf, and
  ReportCrashService instances. Corpse quota exhausted ("Corpse failure, too
  many") so NO .ips files were generated - crash logs were a dead end; oslog
  was the only evidence source.
- asd had been SIGABRT crash-looping (26 consecutive) since the same evening
  deploy; same suspect, different manifestation.

**A/B test:** renamed only `l8keychain.plist` to `.plist.disabled` -> Settings
bootstrapped and stayed alive, 0 fatal exceptions. Renaming it back (via
deploy.sh) -> crash again pre-fix. Single-variable causality: the dylib's
LOAD, not its constructor (constructor is verified gated on
getprogname()=="securityd" + marker).

**Root cause:** build.sh compiled `-arch arm64 -arch arm64e`. dyld selects the
arm64e slice in arm64e processes (Settings and all system apps are arm64e);
AMFI rejects a third-party arm64e slice with KERN_CODESIGN_ERROR and kills
every process that loads the tweak. Ad-hoc ldid signature itself verified
clean on macOS (codesign --verify exit 0), no entitlements embedded, no ObjC
classes - only the slice selection was wrong. Jailbreak tweaks are
conventionally arm64-only for exactly this reason.

**Fix:** build.sh now compiles `-arch arm64` only (85 KB thin binary);
redeployed via deploy.sh; Settings pid 13328 bootstrap success with the tweak
active, 0 crashes; securityd respawned (pid 13322). Rollback during
diagnosis was a rename, no boot state touched.

**Standing rule (recorded):** anything pushed to TweakInject MUST be
arm64-only. Arm64e slices are for Apple binaries only in this environment.
Also: when the corpse quota is exhausted, .ips generation silently stops -
diagnose device crashes through `/var/root/oslog` captures, not the crash
log directory.

## Appendix: 2026-11-04 second incident — kernel AKS gate wedge (splash-stuck apps) [V]

**Symptom:** after the arm64e fix, system apps (Settings, Music) show splash/
blank then die; mkbprobe hangs; FrontBoard lost some app registrations
("unknown to FrontBoard").

**Evidence chain [V]:**
- .ips (corpse quota had freed): `scene-create watchdog transgression`
  exhausting the 19.93 s allowance, user CPU 12.3 s, stackshot captured.
- Stackshot of Preferences 13346: thread on queue `aks-client-queue` in
  state TH_WAIT|TH_UNINT, kernel stack deep in a wait; identical queue on
  every affected app.
- Live debugserver+lldb on a hung mkbprobe (AKRaspSample-style hang is the
  same wall): thread #1 on `aks-client-queue`:
  `mach_msg2_trap <- mach_msg2_internal <- IOKit io_service_open_extended
  <- IOServiceOpen <- AppleKeyStore _copy_aks_client_connection <-
  get_aks_client_connection <- aks_get_lock_state <- MobileKeyBag
  MKBDeviceUnlockedSinceBoot <- main`. **The hang is IOServiceOpen of the
  AppleKeyStore user client itself**, not any externalMethod selector.
- Everything AKS-touching deadlocks behind the wedged open path; apps die at
  the 20 s scene-create watchdog = "stuck at splash".

**Timeline:** securityd 13322 (respawned 11:29 by deploy.sh's kill -9)
completed its keychain pass at 11:34:49 with its AKS connection open, so the
wedge formed after that; mkbprobe already hung by 11:43. Prime suspect [I]:
the `kill -9 securityd` in deploy.sh (11:29) mid-AKS-command left the kernel
AKS driver state machine blocked; first subsequent IOServiceOpen queues
behind it forever. Kernel-side state; nothing userland can unwind it.

**Resolution:** reboot (pwnDFU + --serial). Prevention: deploy.sh now sends
SIGTERM (never kill -9) to securityd. Follow-up for next session: on the
fresh boot, watch which AKS call wedges first if it recurs (oslog AKS-open
watcher + mkbprobe canary), and consider widening the shim coverage analysis
(selector 0/1 separate paths from the dispatcher shim).

**Debugging recipe notes from this session (all [V], they cost real time):**
- debugserver must be attached to a target WITHOUT watchdog pressure; a
  scene-create-watchdog target dies mid-attach (~20 s window, too tight).
  A hung CLI probe (mkbprobe in the AKS wall) is the ideal static target.
- Killing debugserver kills its attached target; lldb -b without an explicit
  `detach` command also terminates the target on exit. Always end batches
  with `detach`.
- debugserver accepts exactly ONE client; any probe connect (nc -z through
  the tunnel) consumes the slot and the subsequent lldb handshake fails.
- Reuse the established morning-session tunnel form (`-L 127.0.0.1:4321:...`)
  — freshly created parallel tunnels failed the handshake repeatedly while
  the long-lived 4321 tunnel worked; cause not root-caused, but the lesson
  is: prefer the surviving tunnel over spawning new ones.

## Post-reboot verification (2026-11-04 12:11-12:20, all [V])

Fresh E06 boot (pwnDFU, boot chain sent 12:10, userspace 12:11):
- **Kernel wedge GONE:** mkbprobe answers instantly, `MKBDeviceUnlockedSinceBoot()=1`, full output — identical to the E06 soak baseline.
- **E06 intact:** e01probe adds fail `-25291` cleanly (shim behavior unchanged, no corrupt writes); persistence rows left for the future readback test.
- **Incident-1 fix holds on a real boot:** l8keychain.dylib (arm64-only) + plist in TweakInject; SpringBoard and installd running with tweaks loaded, zero crash storm.
- **asd + nearbyd SIGABRT = environmental, NOT ours:** asd's crash loop started 21:14 Nov 3 on the PRE-E06 boot (1 s after launch, abort_with_payload inside dispatch_once init, 5 consecutive); nearbyd aborted once on the fresh boot. Both predate every E06/l8keychain change. Working hypothesis [I]: daemons that hard-require keychain/account services abort when they are non-functional — the exact failure class l8keychain targets, so they may self-heal once the hook is live.
- Settings launch attempt was refused with "device is locked" — UI verification pending Vinay unlocking the device.

**UI verification CLOSED (2026-11-04 ~12:30, Vinay on device):** Settings and
apps launch and work normally on the fresh E06 boot with the arm64-only
l8keychain tweak active. Both incidents (arm64e codesign storm, kernel AKS
IOServiceOpen wedge) fully resolved.

## l8keychain v2: the interposer (2026-11-04, implementation record)

**Route decision changed after reading the proven shims.** The weak-load route
is exactly l8pair/l8wifi/l8coreauth's: an LC_LOAD_WEAK_DYLIB of
`/usr/lib/l8keychain.dylib` appended to securityd (restricted platform binaries
only load dylibs from the sealed System volume - moving l8fdr to /var/jb
silently failed before, so the dylib goes there, not to TweakInject). But the
v1 design (MSHookFunction on internal ks_crypt) needs ElleKit's substrate,
which securityd never loads, and the dynamic_lookup import that v1 needed is
the v1 crash-storm poison. v2 interposes one layer DOWN instead:

- **Interposition points:** `aks_wrap_key` / `aks_unwrap_key` - AppleKeyStore
  framework exports that securityd IMPORTS (nm -u verified) and ks_crypt calls
  cross-image. dyld `__interpose` needs no hooking library and is the exact
  proven mechanism. ks_crypt itself is internal to securityd and NOT
  interposable, but intercepting its callees is the same layer of effect:
  ks_crypt only maps the client's returned status to OSStatus/CFError.
- **Caller-visible contracts [V]** (decompiled ks_crypt 0x10000d34c + client
  disassembly in the DeviceSupport split AppleKeyStore):
  `aks_wrap_key(source, source_len, keyclass, keybag, out_buf, dest_len*,
  actual_class*)` and `aks_unwrap_key(source, source_len, keyclass, keybag,
  out_buf, dest_len*)`; dest_len[0] arrives = CFDataGetLength(dest); both
  return kern_return_t, and on 0 ks_crypt does CFDataSetLength(dest,
  dest_len[0]). The AppleKeyStore client relays *dest_len = reply+8 and
  *actual_class = the structure-output size.
- **Software path:** L8KC blob (magic|ver|class|rsv|nonce16|ct|mac32),
  AES-256-CTR under per-class key HMAC(master, "l8kc-class-N") + HMAC-SHA256
  encrypt-then-MAC under a distinct mac key - same scheme as v1 so an already
  minted master stays valid. Gate: marker (/usr/lib/.liter8-keychain on the
  System volume, provision-created, OR the v1 Data marker) + getprogname
  securityd + keybag 0 (KEYBAG_DEVICE) + keyclass {6, 39}. Everything else -
  every other class, bag, non-L8KC blob, dormant marker - passes to the real
  functions, which fail honestly as today. A tampered blob answers 0xe00002fc
  so ks_crypt says -26275 "drop the item".
- **Host tests:** 20/20 pass (round-trip both classes, fresh-nonce distinct
  blobs, cross-class/bag/class pass-through, HMAC failure, non-L8KC legacy
  blob, oversize, NULL, dormancy). Device build: fat arm64+arm64e, adhoc, no
  entitlements, exactly 2 unique aks_* imports via a minimal tbd stub
  (AppleKeyStore.tbd, the SDK ships no private-framework stubs).
- **Provisioning:** userland_fixups.py structural_loads + choices gained
  `securityd`; fetch_payloads.sh gained the `keychain` member (in the default
  set); sshrd_provision.sh gained the `keychain` step: deploy_keychain_library
  (staged+readback, same rigor as l8wifi), deploy_userland_daemon securityd
  (/mnt1/usr/libexec/securityd), enable_keychain_interposer (System marker).
  Local validation: the patcher run against pristine 24B119 securityd produced
  a verified signature with `LC_LOAD_WEAK_DYLIB /usr/lib/l8keychain.dylib
  (weak)` and the expected records json.
- **v1 leftovers retired:** the TweakInject dylib+plist moved off the live
  TweakInject dir on device (an interposer must not ship into every app), and
  deploy.sh is now a status/cleanup helper for that route.

**Incident-1 mechanism correction:** l8coreauth/l8wifi/l8fdr/l8localauth/
l8persona are ALL fat arm64+arm64e and load fine (LC_LOAD and ElleKit alike),
so "arm64e slices are rejected by AMFI" was wrong and the build.sh comment of
2026-11-04 morning overstated it. The v1 poison was `-Wl,-undefined,dynamic_lookup`
(the MSHookFunction import): fat + that flag = codesign-kill storm; arm64-only
+ that flag loaded cleanly; fat + no flag = the normal, proven shape. The
mechanism behind the flag+fat-slice combination is unproven [I]; v2 removes
the flag entirely, so the question is moot for this shim. The TweakInject
arm64-only STANDING RULE is relaxed to: TweakInject dylibs follow the proven
shim recipe (fat OK, no dynamic_lookup, no substrate imports).

## l8keychain v2 ON DEVICE: full pass (2026-11-04 14:31-14:40, all [V])

Device cycle 3 (SSHRD deploy of the fixed dylib + master pre-creation, then
two fw boots): **the system keychain works and persists across reboots.**

**CRUD matrix (all three shapes: plain, system, data-protection):**
- add: 0 for every shape (was -25291 since the project began)
- read-immediate: 0, "returned the stored item"
- update: 0; read-verify: bytes-equal=1, length=31
- delete: 0; query-after-delete: -25300 clean not-found
- persistence adds: 0, rows left for reboot

**Reboot persistence:** after a full tethered reboot,
`e01probe readback` -> `shape=plain osstatus=0 items=2 survived`,
`shape=system osstatus=0 items=2 survived`. Secrets stored before the
reboot came back after it through a fresh securityd + master-key read +
L8KC unwrap.

**Shim logs from inside securityd:** `l8keychain: wrapped class 6,
32 -> 88 bytes` / `unwrapped class 6, 88 -> 32 bytes` (the L8KC envelope:
8 header + 16 nonce + 32 ct + 32 mac). The class-39 metadata wrap happened
during securityd's boot upgrade pass, before the capture window.

**Sandbox lesson that cost one cycle [V]:** securityd's container denies
file-write-create AND file-read-data under /private/var/root/Library (both
measured via kernel `Sandbox: securityd(N) deny(1)` lines in oslog). The
master key path had to move to `/private/var/Keychains/` - securityd's own
keychain directory (keychain-2.db, _securityd-owned). Provisioning
pre-creates the master (32 B, 0600, device /dev/urandom via sshrd) so the
sandboxed mint path is never load-bearing; the shim also accepts a
securityd-euid-owned file, which is what the deployed device ended up with.

**Non-goals honored:** nothing else changed - mkbprobe answers identically
to baseline (E06 shim untouched), Settings/apps unaffected, the interposer
only enters its software path for keyclasses {6, 39} on keybag 0 with a
valid marker.

**asd note, RESOLVED (2026-11-04 16:02 boot):** the SIGABRT crash-loop
(running since 2026-11-03 21:14, before E06 or any deploy) is GONE with the
working keychain: `launchctl` reports state=running, runs=1, process alive
(pid 246), zero new .ips. The dispatch_once abort was keychain-store
dependent - a persistent, readable keychain was the missing precondition.
Resolved as a free consequence of this work, no code change.

**Remaining known limits (unchanged from the design):** software keys
protect nothing against the device operator; no cross-device sync semantics;
backup keybag paths pass through to stock behavior; non-device keybags are
never intercepted.

## Wi-Fi E2E via the real keychain: PROVEN (2026-11-04 15:58-16:05, all [V])

**The last Phase 7 claim, closed.** With l8wifi disabled (enable marker
renamed to .liter8-wifi-credentials.disabled on the sealed System volume;
its gate makes the whole shim pure pass-through, so its Data-volume plist
store is unreachable dead code):

1. Fresh join after boot: genp grew 79 -> 120 rows, 46 rows carry L8KC
   content - the Wi-Fi credential stack's many records stored cleanly
   through the interposer for the first time.
2. Full tethered reboot -> **the device auto-reconnected** (en0 active,
   IP acquired, no manual password entry).
3. Live demonstration with zero doubt about the source: restarted BOTH
   securityd (new pid, no in-memory state) and wifid while capturing;
   `l8keychain: unwrapped class 7, 88 -> 32 bytes` fired as the fresh
   wifid re-joined, isConnected Yes, en0 active. The only reachable copy
   of the password was the keychain blob.

**The class-7 finding that made it work:** wifid's AirPort password add is
an 'oe' of keyclass 7 (key_class_ck), not 6 - measured from securityd's
own -25291 add-failure log at the first retirement attempt, plus class 10
(cku) failures from another client. The served set is now {6, 7, 10, 39};
device-key classes (8 dk, 11 dku, 12 akpu) stay deliberately unserved.
Commit 7a2b24f.

**l8wifi disposition:** retired in place - marker stays off (rename, not
delete); its dylib remains weak-loaded into wifid but inert. The plist
side-store stays on Data as an unreachable relic. Formal removal from
provisioning (fetch_payloads wifi member + wifid structural load) is a
future cleanup decision, not needed for correctness.

## Phase 8 regression matrix (2026-11-04 16:15, current boot, all [V])

| Surface | Check | Result |
|---|---|---|
| Boot | 6 tethered boots this task (fw boot, reviewed backup-e06 set) | all clean |
| SSH | dropbear + sshdev, whole session | up throughout |
| Keychain | e01probe add+read on this boot | add=0, read returns item |
| Keychain persistence | e01probe readback after full reboot | items survived |
| Wi-Fi | real-keychain E2E (join, reboot, auto-reconnect, live restart demo) | proven, l8wifi off |
| MKB | mkbprobe: instant, MKBDeviceUnlockedSinceBoot=1, kMobileKeyBagDisabled | identical to baseline |
| AKS wedge absence | mkbprobe + a full day of keychain traffic after the 2026-11-04 wedge | no wedge |
| E06 selector-10 | kernel = reviewed backup-e06 boot set, unpatched flow intact, e01probe green end-to-end | non-regression |
| Pairing/CoreDevice | idevicepair validate SUCCESS; ideviceinfo ProductType/ProductVersion/ActivationState=Activated | intact (l8pair + remotepairing + coreauthd stack) |
| Bootstrap | provision verify: lhook deny policy OK, tweak loader set OK, tweak destinations safe, launchd cache 735 daemons | healthy |
| asd | SIGABRT loop on the 14:33 boot | RESOLVED on the 16:02 boot: state=running, runs=1, no new .ips - the persistent keychain was the missing precondition |

No regressions from the l8keychain work. Open items: passcode-set milestone,
E06 selector-11 consistency review, formal l8wifi provisioning removal
(marker already retired in place).
