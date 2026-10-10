# How the cellular patches work

Reference for the five changes that take this CFW from "no modem at all" to working phone calls and SMS. Read the scope before the detail: calls come up over IMS carried by **WiFi Calling**, not over VoLTE, because the cellular data bearer is still not raised. See "What these do not fix". [BASEBAND_AND_CELLULAR.md](BASEBAND_AND_CELLULAR.md) is the investigation: how each problem was found, what was tried and what failed. This file is the other half, for someone reviewing or re-deriving the patches: what each one targets, how it is located, what it changes, why that is safe, and how to check it on a device.

Device throughout: iPhone 11, `iPhone12,1` / `n104ap`, iOS 27.2 `24B5099f`. Offsets are quoted for that build only, and they are **outputs**. Every one is rediscovered from the binary on each run; none is an input to anything.

## Four things have to be true

Cellular is not one feature. These are independent, they fail independently, and each hides the next:

1. **The modem has firmware.** The AP pushes it on every cold boot; there is no usable copy in the modem's own flash. Patch 1.
2. **The modem has calibration.** Per-unit RF trim, sealed in FactoryData against an identity this device can no longer reproduce. Patches 2 and 3.
3. **CommCenter will allocate a data context.** Gated on an activation record this CFW does not have. Patches 4 and 5.
4. **IMS registers.** Follows from 3. LTE has no circuit-switched voice, so a call has to be IP. IMS will take either transport: a cellular bearer (VoLTE) or an IPsec tunnel to the carrier over WiFi (VoWiFi, "WiFi Calling"). On this device only the second one comes up, so patches 4 and 5 get you calls, and they need WiFi.

Fix 1 and the modem boots but has no calibration. Fix 2 and it registers but cannot call. Fix 3 and calls work. Nothing about the earlier symptoms tells you the later problems are there, which is why this took three rounds.

## The inventory

All five apply by default. There are no cellular flags: a plain `fw make-cfw`,
restore, `sshrd_provision.sh` and boot gets you a working modem, and calls over WiFi Calling.

| # | record / artifact | component | what it does |
|---|---|---|---|
| 1 | *(four records **deleted**)* | `restored_external` | nothing any more, and that is the fix. They used to claim "no baseband" |
| 2 | `restored-external.fdr-result` | `restored_external` | forces FDR recovery to report success without doing it |
| 3 | `l8fdr.dylib` + `CommCenter.load-l8fdr` | `CommCenter` | answers libFDR's three demotion-state queries so the sealed calibration unseals |
| 4 | `commcenter.data-connection.context-index` | `CommCenter` | stops `canActivateWithoutOverrides` refusing before it evaluates |
| 5 | `commcenter.data-settings.activation-status` | `CommCenter` | stops `canActivateDataSettings` refusing on activation status |

Patch 1 reads backwards and is worth stating plainly: **there was never a patch to add for the baseband, only a patch to stop applying.** Patches 4 and 5 live in one resolver, `CommCenterDataActivationResolver`, because they are two gates on one path.

---

## 1. Let the baseband updater run: stop lying about the baseband

**The problem.** `RestoredExternalResolver` used to patch both baseband-presence predicates in `restored_external` to answer "no baseband". That was deliberate, on the theory that `restored_external` consulting the real answer during a CFW restore was a failure mode.

The cost was total. `restored` skipped every baseband step, `update_baseband` and `update_baseband_legacy` returned success in under 100 ms without ever requesting `BasebandData`, nothing was staged under `<preboot>/usr/standalone/firmware/Baseband/`, and the modem had no firmware to load:

```
CommCenter: modem boot up failure [Baseband Firmware Path Not Found]
ACIPC bootstage = 0
```

**What changed.** Four records are gone from the resolver entirely:

```
restored-external.baseband.present            report that the device has no baseband
restored-external.baseband.present-return     return immediately from that predicate
restored-external.baseband.legacy             same, legacy predicate
restored-external.baseband.legacy-return      return immediately from the legacy predicate
```

so the predicates answer truthfully and the updater runs. `RestoredExternalResolver` now emits exactly one record, the FDR one, and a unit test asserts that count so a resurrected baseband patch fails the suite rather than silently shipping a CFW with no modem firmware.

**Why they were removed rather than kept behind a flag.** They were behind an opt-in `--keep-baseband` for a while, which inverted the sense: you had to pass a flag to *get* cellular. Then the premise turned out to be wrong. n104ap 24B5099f completes an erase restore with the predicates left alone, `Status: Restore Finished` with zero errors, the updater runs for real across two personalization rounds, `bbticket.der` lands beside the images, and the modem goes on to boot, register and carry calls. Suppressing them was never necessary on this build.

`--keep-baseband` and `--keep-fdr` are therefore retired, along with `LITER8_KEEP_BASEBAND` and `LITER8_KEEP_FDR`. Passing either flag now **fails** rather than being ignored, deliberately: a silently-ignored flag in somebody's script is indistinguishable from it working, and the consequence here is a phone with no cellular.

The usual caveat applies in the other direction now. This is one device and one build, and the failure modes are asymmetric: suppressing the predicates cost cellular, while a baseband updater that fails takes the whole restore with it. If it misbehaves on a board nobody has tested, that is the thing to look at first.

---

## 2. FDR recovery, and why letting it run is not the fix

`restored-external.fdr-result` forces `RestoredFDRRecover` to report success without doing the work. It is always applied. This section is about why you might think it should not be, and why that is wrong, because it looks like the obvious answer to the calibration problem.

**Why the real thing is wanted.** FDR data is sealed against an instance identity that, for the `bbcl` (baseband calibration) class, embeds the AP's AKS system key public. The copy in this device's FactoryData holds a **65-byte key stored raw**, because `AMFDRDataCreateSikPubDigestIfNecessary` only digests at 66 bytes and above. The running OS gets a key of at least 66 bytes from `aks_system_key_get_public`, so it presents its **SHA-384, 48 bytes**. 65 raw against 48 digested cannot match:

```
_AMFDRDecodeInstPropertyMatching: kFDRTag_inst propertyLength (sik) (130) != sikLength (96)
AMFDRDecodeTrustEvaluation bbcl:... returned code=0x40004000      (AMFDRError 18)
BBU: kBBUReturnFDRDataValidationFailed
```

The step that reconciles them is FDR recovery and **re-sealing**, which `restored_external` runs as `fdr_recover`, `fdr_auto_challenge_claim`, `verify_fdr_data` and `fdr_verify_sealed_manifest`.

**Why it does not work.** Re-sealing a `sik` instance is a `PUT` to Apple's FDR service (`AMFDRAppendPermissionsString with ActionPUT sik instance for Claim`). It needs that service reachable and willing during the restore, which is exactly what the patch exists to route around. If it fails, the restore fails. Measured: `fdr_recover` does not re-seal on this path.

So calibration has to be unsealed on the **booted** device instead, which is patch 3.

---

## 3. Unseal the calibration: `l8fdr.dylib`

The one genuinely interesting patch. It changes no instructions.

**The seam.** libFDR decides whether to enforce the `sik` match by asking MobileGestalt three questions:

```c
v0 = AMFDRSealingMapCallMGCopyAnswer("CertificateSecurityMode",     0);
v1 = AMFDRSealingMapCallMGCopyAnswer("EffectiveSecurityModeSEP",    0);
v2 = AMFDRSealingMapCallMGCopyAnswer("EffectiveProductionStatusAp", 0);
// non-default demotion state == v0 && v1 && !v2
```

and if the AP is in a non-default demotion state, it skips the comparison entirely. The device is not demoted, so it answers no.

`AMFDRSealingMapCallMGCopyAnswer` consults a **provider registry** first:

```c
provider = lookup(key);
if (provider != NULL) return provider(key, error, context);
```

and that registry is populated by an **exported** function, `AMFDRSealingMapRegisterCustomQueryProvider`. So the override is a supported extension point, not a patch.

**What the dylib does.** `l8fdr.c` runs a `__attribute__((constructor))`, resolves that symbol with `dlsym`, and registers three providers:

| key | answer |
|---|---|
| `CertificateSecurityMode` | `true` |
| `EffectiveSecurityModeSEP` | `true` |
| `EffectiveProductionStatusAp` | `false` |

libFDR then computes "non-default demotion state", skips `sik` verification, and the sealed calibration unseals. Delivered by adding one `LC_LOAD_WEAK_DYLIB` to `CommCenter` (`CommCenter.load-l8fdr`), the same mechanism `lockdownd` and `coreauthd` already use.

**Why not interpose, and why not patch the vtable.** Both were tried and measured. Interposing `os_variant_is_recovery` never fires, because the call is bound inside the dyld shared cache and `__DATA,__interpose` cannot reach it. Patching a vtable at runtime fails because `__DATA_CONST` loses write from its `max_protection` once dyld has applied fixups, and the device boots SPTM/TXM, so `vm_protect` returns `KERN_PROTECTION_FAILURE` and the process cannot grant itself write. Hooking at the library's own registry, above both, is what works.

**Scope and the recovery handle.** Three guards, all required:

1. the host process must be `CommCenter`;
2. `/usr/lib/.liter8-fdr-sik-bypass` must exist, root-owned `0600`;
3. only those three keys are answered — every other query falls through to stock.

The marker is deliberately the switch rather than the dylib. A boot where CommCenter misbehaves is recovered by deleting **one empty file** from SSHRD, instead of restoring a 40 MB re-signed binary.

**Why `/usr/lib`, which costs a DFU cycle per change.** The injected dylib has to sit on the sealed System volume. `/var/jb/usr/lib` was tried: dyld silently declines to load it into `CommCenter`, with no AMFI or dyld message anywhere, while the same adhoc-signed file at `/usr/lib` loads and the same file on Data loads fine into an unrestricted process. Inference: a restricted platform binary may only load dylibs from the sealed System volume. The System volume cannot be remounted writable on a booted device, so every iteration costs a DFU trip.

---

## 4 and 5. Let CommCenter allocate a data context

Patches 3 and earlier get the modem booting, the SIM reading and the device registering. They do not get a phone call. These two do.

### Why a registered modem still cannot call

Registration is the radio layer. Voice on LTE has to be IP, signalled over **IMS**, and IMS needs a bearer to run over. Without any:

```
kDataNotSupported{ActivationStatus failed in DataSettings }
kDataNotSupported{context is not assigned }
IMS APN: false      ims '' QS:kNotConfigured
dialed over CS because of no IMS reg     Call ended. VoIP: false
```

voice falls back to circuit-switched, and on a network that has retired 2G/3G for this subscriber there is nowhere to fall back to. The operator tells the caller the number is unreachable.

### Why there is no bearer

CommCenter does not believe the device is activated. `mobileactivationd` is patched to short-circuit its activation *state*, which satisfies `lockdownd` and Setup because those only ask for the state. CommCenter asks for more: it reads an `ActivationStatus` whose default construction is `fManifestResult = 2, State = 3` with both flags clear, and nothing fills it in.

Completing a real activation is not available, and that is measured rather than assumed. `CreateTunnel1SessionInfoRequest` needs a SEP-attested signing key:

```
ctkd:              <sepk:*(d) kid=da39a3ee5e6b4b0d> generated for mobileactivationd
mobileactivationd: SecKeyCreateRandomKey failed: -25300 <- CryptoTokenKit -7
                   -[MACollectionInterface signingKey]: Failed to create ref key
                   Failed to collect signing key attestation
```

`CryptoTokenKit -7` is `TKErrorCodeTokenNotFound`: ctkd has no Secure Enclave token registered. The token id in that handle is `*` and `da39a3ee5e6b4b0d` is SHA-1 of the empty string, so it was computed over nothing. A control test (software key, then three Secure Enclave variants) shows the software path works and every Secure Enclave path fails identically, so this is neither entitlements nor that one daemon. The consumer gets patched instead.

### The two gates are in series

**This is the part worth reading before touching either.** Each deploy costs a DFU cycle.

```
canActivateWithoutOverrides                                 0x92340
    index = -1
    fetchContextIndex(&index, ...)                          0x921f8
    if (index == -2) {
        status = -3
        reason = "context is not assigned"
        return                                              <-- gate 4, OUTER
    }
    settings = this->vtable[0x90](1)  -> canActivateDataSettings   <-- gate 5, INNER
    settings = this->vtable[0x90](0)  -> canActivateDataSettings   <-- gate 5, INNER
```

Fix only the inner gate and **nothing observable changes**, because the outer one returns first. That happened: the inner patch was correct, deployed and verified in the binary, and the device behaved identically. The reason counts said so the whole time — the outer reason fired **80** times per boot, the inner one **14**.

### Gate 4: `commcenter.data-connection.context-index`

`-2` means no PDP context index is allocated for this connection. Allocation is not broken in general: `OTAActivation` and `BootstrapRoamingInternetBypass` each hold a context and each is published as a network agent. Those two are the bootstrap data path, which exists so an unactivated iPhone can reach Apple over cellular. `Internet` holds none, and cannot be given one while activation is refused. That circle is the bug.

```
0x92390  3100091f  cmn   w8, #2          ; index == -2 ?
0x92394  54000201  b.ne  0x923d4         ; no -> evaluate        PATCH THIS
0x92398  12800048  mov   w8, #-3
0x9239c  d0010609  adrp  x9, "context is not assigned"
```

**Change:** `b.ne 0x923d4` becomes an unconditional `b 0x923d4`, so the function evaluates instead of returning.

```
0x92394  54000201  ->  14000010
```

Two reasons that is safe rather than merely convenient:

- The fetched index is read **exactly once** in all 265 instructions of the function, by the comparison being patched, and never again. Checked by grepping every access to the stack slot: one store, one load. Nothing downstream can index anything with a negative value.
- The replacement is a **branch, not a `NOP`**. NOPing a conditional branch does not skip the block it guards, it falls into it — the failure block is the fall-through here, so a NOP would fail every time. And the preceding instruction is a load, which sets no flags, so the condition after a NOP would be whatever the last call left in NZCV. Retargeting to the branch's own destination is deterministic.

General rule: **NOP a branch when the branch causes the bad path; retarget it when the bad path is the fall-through.**

### Gate 5: `commcenter.data-settings.activation-status`

The second of two gates inside `canActivateDataSettings`:

```c
if (a1->fFatalActivationBlocker[a2] == 1) { code = 67; ... }   // passes
if ((vtable[1216](a1, a2) & 1) == 0)      { code = -3; ... }   // fails here
```

```
0x936e4  d73f0910  blraa x8, x16         ; the ActivationStatus virtual call
0x936e8  36000460  tbz   w0, #0, <fail>  ; PATCH THIS -> nop
```

**Change:** `tbz w0,#0` becomes `nop`, so the function falls through to its success path whatever the Registry-resolved `DataServiceInterface` answered.

```
0x936e8  36000460  ->  1f2003d5
```

Here a `NOP` *is* right, because this branch is what enters the failure block.

---

## How both CommCenter sites are located

No offsets are inputs. `CommCenterDataActivationResolver` anchors on structure.

CommCenter keeps its ten temporary-failure reason strings in one contiguous run, and **each has exactly one ADRP+ADD xref**, which is what makes them usable anchors:

```
0x2154a4b  connection is down
0x2154a5e  Default temporary failure state for DataConnection
0x2154a91  Not allowed on Satellite system
0x2154ab1  No settings
0x2154abd  Currently is not allowed on the SIM (current)
0x2154aeb  Temporary unavailable due to DataConnectionState
0x2154b1c  context is not assigned                            <- gate 4 anchor
0x2154b34  Default in canActivateWithoutOverrides
0x2154b5b  NESession not started yet
0x2154b75  Incompatible Data Mode
```

**Gate 4** requires: the unique `"context is not assigned"` literal, its unique ADRP+ADD xref, then `MOVN W8,#2` one instruction back and `CMN W8,#2` three back, then that the branch between them is a `B.NE`. Requiring the `CMN` is what makes it unambiguous: ten reason strings each have one xref, but only this one is reached by a comparison against `-2`. The replacement displacement is computed from the branch's own decoded target, so it cannot drift.

**Gate 5** requires: the unique `"ActivationStatus failed in DataSettings"` literal, its unique ADRP+ADD xref, the `MOVN W8,#2` that begins the failure block, and then the single `TBZ W0,#0` anywhere in an executable range that targets that block **and** is immediately preceded by a `BLRAA`. The `BLRAA` requirement is what separates this branch from the unconditional jump the FatalActivationBlocker path uses to reach the same block's shared tail.

Two ARM64 details that matter when reading this:

- `CMN Wn,#imm` is `ADDS WZR,Wn,#imm`; there is no separate CMN encoding. `cmn w8,#2` is `0x3100091F` and sets Z when `w8 == -2`, which is why the compiler used CMN rather than CMP.
- `MOV Wn,#-3` is `MOVN Wn,#2`, `0x12800048`. Searching for a literal `-3` finds nothing.

Anything that fails to resolve uniquely throws rather than guessing: `missingAnchor`, `ambiguousAnchor`, `noCandidate`, `ambiguousCandidate`.

---

## Applying and deploying

Nothing here needs a flag. Patches 1 and 2 are baked into the CFW when the restore ramdisk is built; patches 3, 4 and 5 are deployed from SSHRD, because the System volume is read-only on a normal boot.

```bash
# 1, 2. the restore ramdisk. No cellular flags: the baseband updater runs
#       because the records that used to suppress it no longer exist.
liter8 fw make-cfw

# ... restore, then boot SSHRD: fw get-rd, fw boot-rd

# 3, 4, 5. l8fdr.dylib, the patched CommCenter and the marker.
#          The cellular step is in the default step list, so a bare
#          ./device/sshrd_provision.sh does this too.
./device/sshrd_provision.sh cellular
```

The `cellular` step does three things: `deploy_fdr_library`, `deploy_userland_daemon CommCenter`, `enable_fdr_bypass`. The CommCenter binary is rebuilt from the device's own `.orig`, re-signed with its original identifier and entitlements, deployed, and read back and hash-compared. The `verify` step independently re-resolves from the `.orig` and byte-compares against what is live, reporting `CommCenter patch OK` or `MISMATCH`.

To resolve without applying:

```bash
liter8 resolve userland commcenter <CommCenter> --json
```

which prints both records with their offsets, original and replacement words, and the evidence that selected each site.

## Checking it worked, on the device

The **structural check is better than any log grep** and needs no control test. Read the network agents off the interface:

```
$ ifconfig pdp_ip0
```

- Only `OTAActivation` and `BootstrapRoamingInternetBypass`: CommCenter thinks the device is not activated. Gate 4 is still refusing.
- `Internet` present: the gates are open.
- `IMS` present on an `UP,RUNNING` interface: IMS has registered and calls will work. **Check which interface**, because it decides the transport. On `ipsec0`, beside a `TelephonyIPSec` agent, it is VoWiFi and needs WiFi Calling. On a `pdp_ip*` it is VoLTE. On this device it is always `ipsec0`.

For a call, the one line that matters is `VoIP`:

```
CommCenter: Call State changed from (Active: true, VoIP: true) to (Active: false, VoIP: false)
CommCenter: Voice Call ended. VoIP: true
```

`VoIP: true` means the call was carried over IMS. It does **not** tell you which radio carried it, which is a trap: VoLTE and VoWiFi both log `VoIP: true`, and the transport only shows up in which interface holds the IMS agent. `VoIP: false, CS: true` is circuit-switched fallback, meaning IMS is not up at all.

For calibration, these should all be **zero** once patch 3 is live:

```
CAL:  not found in FDR          (note: two spaces, a one-space grep returns 0 and reads as success)
boot failed due to
```

and you should see, within about two seconds of CommCenter starting:

```
l8fdr: loaded in CommCenter, registered 3 of 3 demotion-state answers
AMFDRSealingMapCallMGCopyAnswerInternal: Overriding query for CertificateSecurityMode
_AMFDRSealingMapPrepareAMFDRForCopyLocalData: AP is in NeRD or non-default
    demotion state, ignore sik verification                 (x3: Cal, PROV, Pac)
```

**Always grep for something that must be present before believing something is absent.** Three separate times in this work a tool returned a false zero that was briefly believed: the on-device `strings` cannot read these binaries and returns 0 for `CoreTelephony` in a CoreTelephony binary; baseband log messages are privacy-redacted to `[bbu] <private>` by default, which looks exactly like the updater never running; and the two-space `CAL:` string above.

## Undoing any of it

Each patch has its own handle, in increasing cost:

| patch | undo |
|---|---|
| 3 (`l8fdr`) | delete `/usr/lib/.liter8-fdr-sik-bypass` from SSHRD. The dylib stays loaded and inert. |
| 4, 5 (CommCenter) | restore `CommCenter.orig`, kept beside the binary, from SSHRD. |
| 1, 2 (`restored_external`) | no runtime handle. They are decided when the ramdisk is built, so undoing them means editing `RestoredExternalResolver`, rebuilding the CFW and restoring again. |

## What these do not fix

**Cellular data, and VoLTE with it. These are one problem with two symptoms, and it is the open one.**

The `Internet` agent is published on `pdp_ip0` and no longer refused, but its bearer is never raised: `flags=8010` rather than `UP,RUNNING`, no inet address on any `pdp_ip*`, and no cellular route in the table at all. Only `en0` has one.

That is also why calls need WiFi Calling. IMS will take either transport, and with no cellular bearer there is only one left:

```
ipsec0  UP,POINTOPOINT,RUNNING
        agent domain:TelephonyIPSec type:TelephonyIPSec  "CommCenter: TelephonyIPSec"
        agent domain:Cellular       type:IMS             "CommCenter: IMS.0"
pdp_ip0 POINTOPOINT,MULTICAST                             <- published, never raised
        agent domain:Cellular type:Internet flags:0x59
pdp_ip1 UP,RUNNING -> Em.0, Em.1 only                     <- emergency, not IMS
```

IMS sits on `ipsec0` beside a `TelephonyIPSec` agent, which is an IPsec tunnel to the carrier's ePDG over WiFi. So the observed behaviour is exactly what that predicts: calls and SMS work with WiFi connected and WiFi Calling enabled, and fail with either one off. Raise the cellular bearer and IMS gets a second transport, which is VoLTE.

Not diagnosed, and the obvious explanations are ruled out. **Cellular Data and Data Roaming are both on**, checked in Settings on the device. WiFi being connected is reason for iOS to *prefer* WiFi for traffic, but not reason for the bearer never to be raised at all, and an IMS connection does come up, so CommCenter is willing to activate some data connections and not this one. Whatever stops `Internet` is specific to it.

Also not fixed:

- **Push, and so iMessage and FaceTime.** `apsd: APSSystemTokenInfo no token info found in keychain`. Minting a token needs a real activation record, which needs a SEP-attested key, which is the wall above. Not expected to work without SEP.
- **SEP and passcode**, unchanged and by design.

## Validation state

Patches 1 to 3: device-validated 2026-10-09. Modem boots, `BasebandVersion 8.00.00`, SIM `kCTSIMSupportSIMStatusReady`, carrier bundle matched, registered. Calibration unseals on **every** bring-up, not once.

Patches 4 and 5: device-validated 2026-10-10, same device and build. Incoming calls ring and connect, confirmed by the caller, and SMS arrives. Before these patches the log read `IMS APN: false  ims '' QS:kNotConfigured` and calls failed in both directions, so IMS was not registering at all; `canActivateWithoutOverrides` gates every data connection including the IMS one, and opening it is what let IMS come up.

Reason counts from a live capture with 3721 CommCenter lines in the window as the control: `context is not assigned` 80 to 0, `ActivationStatus failed in DataSettings` 14 to 0, `Default in canActivateWithoutOverrides` 70 to 0, `no IMS reg` present to 0.

**Scope, stated precisely, because an earlier revision of this document got it wrong.** These patches deliver calls and SMS over IMS on the WiFi transport. They do not deliver VoLTE, and `VoIP: true` in the log was read as VoLTE when it only ever meant "over IMS". The transport is visible in which interface holds the IMS agent, nowhere else, and here it is always `ipsec0`.

One refusal survives and is correct: `DATA.Connection.Internet.2` is SIM slot two, and slot two is empty.
