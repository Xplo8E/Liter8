# iPad 8 (A12, iPadOS 26.7.1) port — research note

Status (2026-10-02): **experimental; CFW restore succeeded, SSHRD SSH works,
provisioning is running. Normal SEP-less iOS boot remains unconfirmed.**

Confirmed findings:

- Generic LZFSE (Compression algorithm `0x801`) generated kernel/iBEC streams
  that macOS decoded but iBoot rejected with decompression error `0x40040028`.
  `FirmwareArtifact` now uses and verifies iBoot LZFSE (`0x891`) and preserves
  the complete PAYP DER child. Recompressing the clean kernel reproduced the
  IPSW compressed bytes. Modified images now reach kernel and launchd startup.
- The old proposal to bypass the caller at iBEC `0x27f58` was incorrect. That
  patch is absent from the current CFW; no additional image-auth patch was
  needed to fix decompression.
- `get-rd` now completes. Its two host failures were background-terminal
  ownership at sudo and a root-owned image silently mounted read-only.
- Both SSHRD and the first CFW attempt reached launchd but failed to launch
  modified `restored_external` (`OS_REASON_EXEC`). SSH/Restore USB did not
  start; the CFW attempt timed out before ASR or any system-image write.
- The T8020 PPL loaded-trust-cache policy was missing from the port. The
  sibling PongoOS commit `031e5cc` includes it. On this kernel the helper is at
  `0x324da20`, the boolean result at `0x324da64`, and its caller at `0x324d5d4`
  assigns trust level 9. Liter8 now resolves the full helper and checks that
  caller, then changes only `CSET W0,EQ` to `MOV W0,#1`. Selection is limited
  to the registered 23H30 profile. The corrected live attempt completed the full CFW restore (exit 0, `Status: Restore Finished`); the corrected SSHRD now provides SSH.

`restore` now has 21 records and `boot-public` 118. The previous 117 normal-boot
records are unchanged. Exact-build fixtures bind the PPL patch and composite
output. CFW construction and artifact verification pass. XCTest could not run
with the installed Command Line Tools; release compilation and CLI checks run.

The user explicitly authorized erase restore. Continue the normal Liter8
sequence: CFW restore, SSHRD provisioning, then normal boot with SEP-less
kernel/userland patches. The remaining sections document the earlier static
inventory; historical counts below predate the additional PPL record.

## Why this is not a normal port

Every previously supported Liter8 build uses iPhone 11 `n104ap`, A13 `T8030`,
and iOS 27. This target changes the device, SoC, and OS family while retaining
the user's existing usbliter8 transport:

| Axis | Supported today | iPad 8 target |
| --- | --- | --- |
| Device | iPhone 11 `n104ap` | iPad 8 `j171aap` (Wi-Fi), `j172aap` (Cellular) |
| SoC | A13 `T8030` (`0x8030`) | A12 `T8020` (`0x8020`) |
| OS | iOS 27 (XNU 13432.x) | iPadOS 26.7.1 (XNU 12377.x, Darwin 25.6.0) |
| DFU transport | `usbliter8ctl` | `usbliter8ctl` (user-selected) |

The support guide's two worked cases are "another build, same device" and "new
device, same build." This is neither. Treat it as a new platform bring-up that
happens to reuse Liter8's resolver and workflow machinery.

## Target identity (measured from the IPSW)

Source: `iPad_10.2_2020_26.7.1_23H30_Restore.ipsw`, `BuildManifest.plist` /
`Restore.plist`, `j171aap` **Erase** identity (`Customer Erase Install`).

| Field | Value |
| --- | --- |
| Product version | 26.7.1 |
| Build | `23H30` |
| Product types | `iPad11,6` (Wi-Fi), `iPad11,7` (Cellular) |
| Board (this note) | `j171aap` — Wi-Fi |
| Cellular board | `j172aap` |
| Platform | `t8020` (A12) |
| ApChipID (CPID) | `0x8020` |
| ApBoardID (BDID) | `0x24` (Wi-Fi), `0x26` (Cellular) |
| Kernel fingerprint | `xnu-12377.162.13.700.38~2/RELEASE_ARM64_T8020` |
| Root filesystem | `141-38001-023.dmg.aea` (AEA-encrypted cryptex) |

### Clean inputs (decompressed payloads resolvers were run against)

| Component | im4p SHA-256 | decompressed SHA-256 | size |
| --- | --- | --- | --- |
| `kernelcache.release.ipad11b` | `d480d026…0ba0112` | `eee662eb…83c334be` | 59 031 552 |
| `DeviceTree.j171aap.im4p` | `011cd8d2…ee0789a` | `7eee7250…078cc290` | 193 756 |
| `iBSS.ipad11b.RELEASE` | `bde78f35…25aab820` | `07061a53…08f2188b` | 2 190 896 |
| `iBEC.ipad11b.RELEASE` | `849ab082…b251c2d6` | `07061a53…08f2188b` | 2 190 896 |

Notes:

- **iBSS and iBEC decompress to byte-identical images** on this device.
- **iBSS/iBEC ship unencrypted** (LZFSE only, no KBAG), so iBoot resolvers can
  run host-side. This is different from older A12 firmware and is good news.
- The rootfs is an **AEA-encrypted image**. It was subsequently mounted, and
  the `launchd`, service-cache, and Setup.app guards were measured below.

## Structural differences from the n104/iOS 27 model

1. **No SPTM, no TXM.** The `j171aap` manifest has no `SPTM`/`TXM` components.
   The entire `Resolvers/TXM/` layer and the `SPTM.img4`/`TXM.img4` entries in
   `scripts/device_boot.py:FIRMWARE_SEQUENCE` do not apply to this device. The
   workflow now selects artifacts from its BuildManifest component set. The
   A12/iOS 26 boot chain is the classic iBSS→iBEC→DeviceTree→SEP→kernelcache.
2. **Cryptex1 system/app volumes.** iOS 26 splits the OS across
   `Cryptex1,SystemOS` / `Cryptex1,AppOS` with their own trust caches. Liter8's
   provisioning (`rootfs.py`, `device_provision.py`) was written for the iPhone
   11 layout. The mounted 23H30 System image contains the expected launchd,
   Setup.app, coreauthd, ctkd, mobileactivationd, and staged-system-app paths;
   the live `/dev/disk1s*` mount mapping still needs verification on the iPad.
3. **Different normal-boot firmware set.** `j171aap` ships
   `ANE, AOP, AVE, GFX, ISP, SIO` but **not** `SPTM, TXM, PMP, WCH`. The boot
   `FIRMWARE_SEQUENCE` is now filtered by this board's manifest.
4. **DFU handoff is live-tested on T8020** (see next section).

## Exploit transport

The user selected the existing usbliter8 hardware transport for this iPad.
`scripts/device_boot.py` sends the raw patched iBSS with
`usbliter8ctl boot iBSS.raw`; subsequent artifacts use `irecovery`. The
attached yoloDFU and PongoOS projects are reference material only. The
T8020 usbliter8 transitioned this iPad from `PWND: usbliter8` DFU through
patched iBSS and iBEC into Recovery. The remaining failure is after the
restore kernel transfer and `bootx`.

## Phase A inventory (host-side resolver baseline)

Command form: `.build/release/liter8 resolve <component> <plan> <clean-input>`.
"Candidates" means the resolver produced records; it does **not** mean the
records are correct. Correctness is Phase C (static review) + Phase D
(fixtures). "Needs work" is the real porting backlog.

### Kernel — `kc.raw`

| Plan | Result | Classification |
| --- | --- | --- |
| `restore` | 20 records (identity, panic×4, amfi trust-cache×5, launch-constraints, debugger, developer-mode, post-validation, dyld-policy) | candidates — review |
| `boot-policy` | 4 records (persona uid/gid zero, usb restore-mode result/return) | candidates — review |
| `aks` | candidates | review |
| `sep`, `sep-silence` | candidates | review |
| `boot-public` | 117 records, exact-build fixture | host build passes; device review pending |
| `boot` | stops at scoped vnode-open cave | not used by normal boot workflow |
| `diagnostic` | identity records (+ diagnostic path) | candidates — review |
| `credential-manager` | 50 records at 25 distinct entries, exact-build fixture | host build passes; device review pending |
| `sandbox-public` | 11 records, exact-build fixture | selected by `boot-public` |
| `sandbox` | no candidate ("completed function immediately before Sandbox executable cave") | scoped shim still unavailable |

### DeviceTree — `dt.raw`

| Plan | Result |
| --- | --- |
| `restore` | removes `/defaults/content-protect` (−36 bytes) — works |
| `normal` | content-protect removal + `no-effaceable-storage`, `boot-ios-diagnostics`, `ephemeral-storage` edits (+44 bytes) — works |

DeviceTree resolvers are semantic and ported cleanly. Verify the edit set is
complete for A12/iOS 26 (the n104 set may differ).

### iBoot — `ibss.raw` / `ibec.raw`

| Plan | Result | Classification |
| --- | --- | --- |
| `ibss-validate` | 2 records at `0x25070` (ASN.1 branch + result) — the sig-check bypass | candidate — review |
| `ibss-bootargs` | **now resolves uniquely at `0x28828`** (string slot `0xb0da0`) | FIXED — see B2 |
| `ibss-restore`, `ibss-normal` | **now fully resolve** (ASN.1 + boot-args) | candidates — review |
| `ibss-ramdisk` | depends on bootargs | re-check |
| `ibss-skip-display-init` | no candidate | **rework (may be N/A for this display)** |
| `ibec-restore` | 6 records including nonce-cache branch `0x31a08`, exact-build fixture | host build passes; device review pending |
| `ibec-ignore-pinot-failure` | no candidate | diagnostic only; not selected by CFW |

### B2 — iBoot boot-args (done)

The boot-args `snprintf` site on this iBoot is identical to n104 except the
destination buffer is `SUB X0, X29, #imm` (frame-pointer-relative) instead of
`ADD X0, SP, #imm`. `IBSSBootArgsResolver.findCallSites` now accepts both forms;
the `MOV W1,#0x400` capacity constant and the isolated-`%s` check still pin it
to the single site (`0x28828` here), so uniqueness is not weakened. This is a
locator-only guard — the patch (redirecting the X2 format pointer) is unchanged.
Verify on n104 with fixtures (`make test-fixtures`) once XCTest is available, to
confirm the added `SUB X0,X29` form does not match a second site there.

### B2 — sandbox scope

The `boot-public` workflow uses the established 11-record sandbox subset; it
resolves and has a 23H30 fixture. The wider `sandbox` plan still needs a new
location for its scoped vnode-open shim:
  - the hardcoded MACF operation indices (36/87/88/91/120/258/267) match the
    published [XNU 12377.1.9](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/security/mac_policy.h)
    and [12377.81.4](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.81.4/security/mac_policy.h)
    headers. Apple has not published the exact 12377.162.13 header used by this
    kernel, so target validation against this binary is still required.
  - the scoped vnode-open code-cave predecessor (a specific function tail) does
    not exist in this kernel. The Sandbox `__TEXT_EXEC` file range
    `0x27bba50…0x27f4714` contains no 132-byte zero run for the shim. A new,
    owned executable location and the process-name checks need validation.
The wider plan remains deferred; it is not part of `boot-public`.

### Userland — against the mounted System volume

Mounted with `ipsw mount fs …` (full System volume, 23H30). The restore
ramdisk was separately extracted from the IPSW's `141-38026-025.dmg` IM4P;
its `/usr/sbin/asr` has SHA-256
`0871b0a3fc7ef35664150c76d918059f42f704b2013459eb672ccfb7bf4af7f2`.

| Resolver | Target | Result |
| --- | --- | --- |
| `coreauthd` | `LocalAuthentication.framework/Support/coreauthd` | candidate (dto-ratchet start-controller) |
| `ctkd` | `CryptoTokenKit.framework/ctkd` | 2 candidates (sep-key-server return-nil + return) |
| `mobileactivationd` | `/usr/libexec/mobileactivationd` | 5 records, exact-build fixture; host resolve passes |
| `asr` | restore ramdisk `/usr/sbin/asr` | one candidate: branch `0x24b8c`, original `80310035` → NOP; review needed |

`mobileactivationd` retains the Objective-C method
`-[MobileActivationDaemon getActivationStateWithCompletionBlock:]` at VM
address `0x100001d0c` in this Mach-O. Its migration gate is `TBZ W22,#0` at
`0x100001d6c`. The resolver now branches to its existing one-entry
`NSDictionary` fallback and changes only the value load at `0x100001e28`
to the `Activated` CFString. The key load remains unchanged. The five records
and full output hash are fixed in the 23H30 fixture.
| Setup.app | `/Applications/Setup.app/Setup` | `device/patch_setup.py` parses it cleanly: **58** class-owned `controllerNeedsToRun` |

### Pre-boot guards — measured from the mounted System volume

| Guard | Value |
| --- | --- |
| `launchdSHA256` | `1b37dae048542729a622a1a3f4b77ec8829d32e918f0d6a0c0c037f32d9e84b1` |
| `launchdCacheSHA256` | `af9183685525a0833fea7a16c7a81b3f85e14372ea33d49f3e1ec6ab1a90ca4f` |
| `launchdCacheDaemonCount` | 672 |
| `setupControllerMethodCount` | 58 |

## Code changed in this pass

The release build compiles and `make integration` passes (38 Python tests,
2 skipped). The XCTest unit/fixture tiers **could not be run** in this
environment: the installed Command Line Tools toolchain has no `XCTest`
module and there is no full Xcode. Run `make check` where XCTest is available
before relying on these changes.

1. **`Resolvers/Kernel/KernelIdentityResolver.swift` — made SoC-agnostic.** It
   hard-coded `/RELEASE_ARM64_T8030`, which was the *only* reason `restore`,
   `boot`, `boot-public` and `diagnostic` could not even start on a T8020
   kernel. It now reads the SoC token (`T8020`, `T8030`, …) from the binary and
   rewrites `RELEASE`→`PATCHED` (same length, no data moved) for whatever
   platform it finds. For a T8030 kernel the derived token is `T8030`, so the
   records are byte-identical to before — no n104 regression by construction.
   Still requires exactly two occurrences.
2. **`Profiles/FirmwareProfile.swift` — registered the T8020 kernel.** Added a
   `KernelResolverProfile` (`ios26-23H30-j171aap`) keyed on the real embedded
   fingerprint, with an **empty** `resolverVariants` map. The artifact is now
   identified instead of "unidentified," but no per-resolver support is claimed
   — credential-manager stays correctly unsupported until its signature family
   is recovered.
3. **`Firmware/IPSWManifest.swift` — added an experimental
   `DeviceWorkflowProfile`** (`ipad11,6-j171aap-23H30`) for the Wi-Fi board,
   `validationState: .experimental`. Its four pre-boot guards are the measured
   values above. `bootPlan` uses empty arrays because no additional iBSS
   display patch has been verified. Every `fw` action requires
   `--experimental`; host-side `prepare` and `make-cfw` now complete.
4. **Boot and CFW Python workflows — selected firmware from BuildManifest.**
   The j171aap boot artifact builder and sender omit SPTM, TXM, PMP, and WCH
   because they are absent from its erase identity. TXM patching in normal,
   SSHRD, and CFW paths requires a complete SPTM/TXM pair. The iPhone 11
   manifest still selects its previous firmware set.
5. **ACM, sandbox-public, iBEC, mobileactivationd, and asr.** These now
   resolve on the attached build and have exact-build fixtures. The normal
   `boot-public` kernel plan resolves 117 records. Device validation remains.

## B1 progress — AppleCredentialManager (credential-manager resolver)

The class is present and unchanged in identity (`AppleCredentialManager.cpp`).
Probing the `ios27-24A435-acm-v1` shapes against this kernel initially reported
18/26 exact shapes. The 23H30 research variant now records eight more entries
from direct-call, argument, and diagnostic-string analysis. Its probe reports
26/26 inherited shapes, but `updateAnalytics` falsely collides with
`unlockItem` at `0x1b23058`. The 23H30 roster omits that duplicate and binds
**25 distinct entries** to a 50-record fixture. The resolver requires unique
offsets but allows this variant's relocated `setPowerStateGated`. It preserves
the BTI landing pad on the PAC-less logging-level leaf.

ACM `__text` anchor map (exact matches, file offsets):

```
0x1b1ff20 sepManagerMatchedThreadCallHandler   0x1b23058 unlockItem
0x1b21244 _performKernelControl                0x1b2350c handleSEPMessage
0x1b215f8 _performCommand                      0x1b237f4 readFromSEPBuffer
0x1b21820 processSCRDResponsePayload           0x1b23954 writeToSEPBuffer
0x1b21a8c scheduleDblClickDeferredAck          0x1b23f34 clearSEPBuffer
0x1b226e8 _setPropertiesGated                  0x1b240d0 getSEPEndpoint
0x1b22b70 performDoubleClickQueryGated         0x1b24d10 powerOffActionGated
0x1b22c60 performLoggingLevelQueryGated        0x1b24fc4 sepManagerMatchedGated
0x1b22e2c lockItem
```

New 23H30 entries (file offsets):

| Method | Entry | Evidence |
| --- | --- | --- |
| `callPlatformFunction` | `0x1b203a8` | Receives x0…x6 and dispatches to the V2/V3 context handlers |
| `cmdContextV2` | `0x1b20584` | Copies a V2 context from x4 and schedules the callback at `0x1b20880` |
| `cmdContextV3` | `0x1b2066c` | Reads the V3 byte at x4+12 and schedules the same callback |
| `performCommandGated` | `0x1b20880` | Five-argument gated body directly calls `_performKernelControl` |
| `performSCRDInitialization` | `0x1b21bac` | Self-only state check calls the next command entry |
| `sendSEPCommand` | `0x1b21db0` | Eight-argument body calls SEP buffer and message functions |
| `sendSEPMessage` | `0x1b23cfc` | Five-argument message body calls `getSEPEndpoint` |
| `setPowerStateGated` | `0x1b311f4` | Takes self and power state; directly references its own diagnostic string at `0x56a23b` |

The prior iometa conclusion was too broad: its vtable dump did not name these
entries, but direct-call disassembly did. `updateAnalytics` may have been
inlined or removed; there is no distinct entry between
`scheduleDblClickDeferredAck` and `performSCRDInitialization`. The exact
build's 25-entry patch roster intentionally does not write a second patch to
the `unlockItem` entry. Whether another analytics path matters to actual
boot behavior remains a device-validation question.

## Remaining device work

- Complete the CFW restore with the added PPL trust-cache patch.
- Boot SSHRD and validate the actual APFS volume mapping before provisioning.
- Provision bootstrap and the firmware-specific userland fixes.
- Load the 118-record normal-boot kernel and verify a usable SEP-less iOS boot.
- The wider scoped sandbox shim is outside the public `boot-public` plan.

Current restore and build logs are retained under the selected work directory's
`audit/` and `logs/`. See [the runbook](../runs/IPAD8_J171AAP_23H30_RUNBOOK.md).
