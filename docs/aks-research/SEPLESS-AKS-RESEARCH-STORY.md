# Bringing the System Keychain (and Wi-Fi) Back Without a Secure Enclave
## A research story from the Liter8 iPhone 11 project

*iPhone 12,1 (iPhone 11), iOS 27.2 build 24B119, XNU xnu-13432.42.3~28,
custom "Liter8" tethered boot without a SEP — research state, February-era
build 2026. All findings below were verified live on hardware unless noted.*

---

## 1. The starting point

On an iPhone boot with no Secure Enclave Processor, the system keychain is
dead. Every `SecItemAdd` fails with:

```
-25291 errSecMissingEntitlement
"ks_crypt: <status> failed to 'oe' item (class 6, bag: 0)"
"No key available for class."
```

The reason is precise: the keychain's item encryption needs per-class keys
(`key_class_ak` for item secrets, `key_class_ck` for always-available
secrets, a metadata key for the store itself), and those keys live in the
system **keybag** — a store the SEP/effaceable-storage stack normally
provisions and holds. No SEP, no keybag, no class keys, no keychain.

The community consensus (Discord, jailbreak research circles) was: "if you
implement enough of AKS it should be possible to connect to Wi-Fi or even
set a passcode". This document is the story of testing that claim to its
measurable limit on real hardware.

## 2. What we already had

The Liter8 boot chain already contained a kernel shim for
`AKSUserClient::externalMethod` selector 7 (keybag-state query: reports
`noPin|beenUnlocked`), extended in an earlier iteration (E06) with a
coherent selector-10 wrap reply. Without it, `aks_wrap_key` consumed
uninitialized stack and securityd wrote corrupt rows into the keychain
database — an even worse failure mode.

Crucially, an earlier research iteration had established that the **userspace
layer** was the right interception point: securityd's item crypto funnels
into one C function — plain `ks_crypt` — whose contract was verified live
with hardware breakpoints (10 arguments: operation CFString "oe"/"od",
keybag handle, backup keypair, keyclass, length, source, actual_class out,
CFMutableDataRef destination, use_backup flag, CFErrorRef out).

## 3. The keychain milestone (l8keychain v2)

**Design.** A dyld interposer loaded into securityd intercepts five
`aks_*` client functions (create/unwrap/save/configuration/unload) and
implements software keybag semantics: item class keys are random per bag,
wrapped with keys derived from a persisted master key
(PBKDF2-HMAC-SHA256 + AES-256-CTR + HMAC-SHA256), the same
explicit "protects nothing against the device operator" stance as the
Wi-Fi credential fallback that preceded it. Marker-gated: delete one file
and the shim is fully inert.

**Results, all verified on hardware:**

| Test | Result |
|---|---|
| SecItemAdd (plain / system / data-protection shapes) | **osstatus 0** |
| SecItemCopyMatching returns the stored secret | **0** |
| update + read-verify | bytes equal |
| delete + query | clean -25300 not-found |
| **full tethered reboot, readback** | **items survived** |
| Wi-Fi join → reboot → auto-reconnect via real keychain | **proven, live-captured** |

The Wi-Fi proof was end-to-end: with the previous workaround (l8wifi, a
credential side-store) disabled, a network joined after a full reboot
reconnected from the keychain — demonstrated by restarting BOTH securityd
and wifid while capturing the unwrap calls that fed the rejoin.

**The debugging lessons that mattered (each cost real time):**

- **Fat arm64+arm64e TweakInject dylibs with `-Wl,-undefined,dynamic_lookup`**
  get every process that loads them killed by AMFI with
  `KERN_CODESIGN_ERROR` (exit 50). The same flag in an arm64-only build
  loads cleanly; fat builds *without* the flag load fine. When the corpse
  quota is exhausted, no `.ips` files are generated — diagnose through
  oslog, not the crash-reporter directory.
- **securityd's sandbox denies `/var/root` entirely** (both create and
  read; kernel `Sandbox: securityd(N) deny(1)` lines). The keybag master
  key lives in `/private/var/Keychains/` — securityd's own directory.
- **Rebuilding a TweakInject tweak can produce a binary AMFI rejects at
  load** (same exit 50) while the previous build of the same source
  loaded — and a retry after the first failed launch may load it. The
  stale-code-identity race is real; verify with process liveness, not one
  launch.
- The debugserver one-client rule, the "killing debugserver kills the
  target" rule, and the "first launch after a tweak push dies" race are
  documented in the E04 research note.

## 4. What the keychain fixed along the way

- **asd** (App Store daemon) had been SIGABRT-crash-looping every second
  since before any of our changes. On the first boot with a persistent
  keychain: `state=running, runs=1`, no new crash reports. The daemon was
  keychain-store dependent all along.
- **Wi-Fi password persistence** moved from the unencrypted side-store to
  the real keychain; the side-store shim (l8wifi) is retired in place.
- Item crypto, metadata-key persistence, and the full CRUD surface work
  for the three keychain classes the system actually uses
  (6/7/10 plus the metadata key 39).

## 5. The passcode milestone: how far it goes, and the wall

With keybagd's two skip-gates neutralized (each was load-bearing
elsewhere: one flag for the data volume's APFS behavior, the other for the
lockdown/USB/pairing stack — both measured by booting without them), the
system creates **real Apple-format keybag state**:
`/var/keybags/usersession.kb` (the mobile user session registry) and
`persona.kb` (the persona manifest), in the genuine Apple keybag plist
format, plus the `LACSExtractablePassword` creation machinery runs.

The passcode-set flow was decoded end-to-end through the dyld shared
cache (extracted from the IPSW cryptex, loaded into IDA):

```
Settings → Face ID & Passcode
  → LAContext deviceOwnerAuth sheet
  → code entered
  → -[LAPSPasscode initWithPasscode:type:]
  → -[LACSExtractablePassword initWithData:error:]   (Swift)
  → LACSContext creation
  → "obtain encryption size" query
  → AppleCredentialManager answers -3
  → NSException → Settings SIGABRT
```

The live error, captured at the moment of the crash:

```
Failed to create LACSExtractablePassword: Error
Domain=com.apple.LocalAuthentication Code=-1001
"Failed to obtain encryption size -3"
```

**The wall is in AppleCredentialManager (ACM).** Binding a passcode
requires the ACM context to supply encryption materials — and ACM holds
its credential context in the SEP. Without it, ACM answers -3 and every
layer above (LACS, LAPSPasscode, Settings) throws.

This is one layer *below* anything hookable from userspace: Settings,
LAContext, even the LA EmbeddedUI are all above the ACM query. The verdict
is honest: "set a passcode" requires emulating the ACM context encryption
layer — a project comparable in size to the entire keychain arc, with
real unknowns about what ACM feeds downstream.

## 6. The scorecard

| Community claim | Status on this boot |
|---|---|
| "connect to Wi-Fi" | ✅ **done** — via the real system keychain, reboot-persistent, live-proven |
| keychain items work | ✅ full CRUD + reboot persistence |
| daemons that need the keychain (asd) | ✅ unblocked |
| "even set a passcode" | ⛔ wall reached: ACM context encryption query requires the SEP |

## 7. What this means

The claim splits in two at a measurable line. Everything that flows
through **securityd's item crypto** is recoverable with one well-placed
userspace interposer: keychain, Wi-Fi, and every daemon that was crashing
for lack of the keychain. Everything that flows through **the SEP-backed
credential identity** (ACM context, passcode binding) hits a wall that no
existing interposer crosses.

That line — securityd item crypto vs. ACM credential identity — is the
practical definition of "enough of AKS" on a SEP-less boot, measured on
hardware.

## 8. Research artifacts

- `docs/aks-research/E04-securityd-classkey-provider.md` — the keychain
  arc: ABI captures, incident analyses, deployment, full-pass results
- `docs/aks-research/E07-passcode-milestone-recon.md` — the passcode arc:
  gate decode, flag blast-radius experiments, creation-flow decode, the
  ACM wall
- `device/keychainprobe/l8keychain.m` — the keychain interposer
- `device/keybagfix/` — the keybagd patcher and l8keybag interposer
- `device/localauthfix/l8localauth.m` — the LA policy translator
- All changes on branch `research/aks-userclient` (local only)
