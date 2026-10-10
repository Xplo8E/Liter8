# Baseband and cellular on a Liter8 CFW

Short version: a Liter8-restored iPhone 11 used to have **no cellular** out of the box, deliberately. Four patches changed that and they all apply by default now, no flags. As of 2026-10-10 the modem works and **phone calls work over VoLTE**. Cellular data does not. Push, and so iMessage and FaceTime, does not and is not expected to.

A note on reading this, because it will otherwise mislead you: `--keep-baseband` and `--keep-fdr` appear throughout and **both flags have since been retired**. Keeping the baseband predicates is now the only behaviour, so the flag it was hidden behind is gone and passing it fails. Mentions below are historical, kept because they are how the argument developed.

This document is the **investigation**, in the order it happened. It keeps its wrong conclusions in place and corrects them in later sections, because the wrong turns are most of the value here: SEP was blamed and then cleared twice, a patch that was entirely correct appeared to do nothing, and a post-restore workaround that looked like a dead end turned out to be the answer.

If you want the patches rather than the story — what each one targets, the exact instruction it changes, why that change is safe, how it is located without hardcoding an offset, and how to verify it on a device — read [CELLULAR_PATCHES.md](CELLULAR_PATCHES.md) instead.

All of it was measured on n104ap / iOS 27.2 `24B5099f`.

## What Liter8 patches

**Historical, and the starting point for everything below.** `RestoredExternalResolver` *used to* emit five records against the restore ramdisk's `usr/local/bin/restored_external`. It now emits only the first of them. One is the FDR fix the resolver is named for. The other four overwrote the first two instructions of each of the two baseband-presence predicates with `MOV X0, #0` + `RET`, and those four are the reason there was no cellular:

| id | effect |
|---|---|
| `restored-external.baseband.present` | the modern predicate answers "no baseband" |
| `restored-external.baseband.present-return` | returns immediately |
| `restored-external.baseband.legacy` | the legacy predicate answers "no baseband" |
| `restored-external.baseband.legacy-return` | returns immediately |

They exist because `restored_external` consulting the real answer during a CFW restore is a failure mode the single FDR patch did not cover.

## What that costs

`restored` believes the device has no modem, so it runs both baseband checkpoints as no-ops:

```
Checkpoint started   id: 0x1303 (update_baseband_legacy)
Checkpoint completed id: 0x1303 result=0      <- 83 ms, no output
Checkpoint started   id: 0x131B (update_baseband)
Checkpoint completed id: 0x131B result=0      <- 91 ms, no output
```

`result=0` means "did not fail", not "did something". No `BasebandData` request is ever made, while `update_stockholm` and `update_rose` in the same restore both log `Updating <X>` and transfer bytes.

The consequence is visible on the booted device:

- `<preboot>/<boot-manifest-hash>/usr/standalone/firmware/` contains FUD, Savage, Rose, Veridian, SLAM, nfrestore, `sep-firmware.img4` and `devicetree.img4` — and no `Baseband/`. `updater_output/` likewise has Savage, Rose, T200 and SE but no baseband entry.
- `/var/wireless/baseband_data` is empty and `root:wheel` while its siblings are `_wireless`-owned.
- CommCenter persists `kKeyStatsBootFailedReason = "modem boot up failure [Baseband Firmware Path Not Found]"` and logs `Firmware dead: false -> true`.
- `ioreg -n AppleConvergedIPCICEBBControl` reports `"bootstage" = 0` and `"image_table" = No`: the firmware was never offered to the modem.
- The SIM reads `absent` even with a card inserted, because the card reader is driven by the modem.

## Where the firmware is supposed to come from

`libTelephonyCapabilities.dylib`, `capabilities::radio::personalizedFirmwarePath()`:

```
path = lookupPathForPersonalizedData(<vendor flag>, buf, 0x400)
     + ("/Baseband" only if capabilities::radio::initium() || capabilities::radio::dal())
     + capabilities::radio::firmwarePathSuffix()
```

`firmwarePathSuffix()` has no string constant; it is built inline and decodes to `"/ICE19"`. `/Baseband` is appended only for initium/dal radios, not ICE. The base path comes from MobileSoftwareUpdate, which is why it is preboot-relative. On this device the result is:

```
/private/preboot/<hash>/usr/local/standalone/firmware/Baseband/ICE19
```

The loader itself is `libBasebandManagerICE.dylib`, which owns both `Failed to find the firmware in "%s"` and `Baseband Firmware Path Not Found`. Neither string is in any on-disk binary, which is why grepping `CommCenter`, `abm-helper`, `abmlite` and `WirelessRadioManagerd` finds nothing.

## Why you cannot just copy the firmware in

Staging the unpacked `ICE19-8.00.00.Release.bbfw` at that path, fixing the `drwx------` on `<preboot>/<hash>/usr/local/standalone` so `_wireless` can traverse it, and creating `/var/wireless/baseband_data/bbfs` so the NVM store can be generated, gets the modem all the way to powered-on with a live transport:

```
Loaded PSI / PSI2 / RestorePSI / RestorePSI2 / EBL file
Loaded NVM file .../static.nvm, .../dynamic.nvm
Loaded binary file 'bbcfg.bin'
Loaded download file 'SYS_SW.elf' 'upc.elf' 'ant_cfg_data.elf' 'custpack.elf' 'TPCU.elf' 'RFFW.elf' 'legacy_rat_fw.elf'
Loaded MRC file .../mrc.dat
AppleBasebandI19::radioOnGated: baseband power changing: off -> on
AppleBasebandI19::enablePCIPort: enable: 1, ret: 0x00000000
BBUICE16Communication: TelephonyBasebandPCITransportCreate returns: success
BBUpdaterController: Finish preparing at first
```

and then stops dead:

```
BBUICE16UpdateSource::: chipID:0x68 certID:0x1F3F5BDF
3:  END(kBBUReturnUnPersonalizedImageError): bootup
boot failed due to output did not return done
```

The modem reports its chip ID (0x68, matching `BbChipID` in the BuildManifest) and its gold cert ID, and refuses firmware that was not personalized against them. The IPSW's bbfw is unpersonalized by design; the function is called `personalizedFirmwarePath` for a reason. Personalization is a TSS signing step keyed to the baseband's gold cert ID, serial and nonce — exactly the work `restored` skips.

**So no amount of file staging substitutes for a BBTicket.**

## Using --keep-baseband

**Historical. The flag is gone**: dropping those four records is now unconditional, so this is just what `liter8 fw make-cfw --work-dir <dir>` does. Kept because the measured result below is what justified removing the flag.

```sh
liter8 fw make-cfw --work-dir <dir> --keep-baseband   # retired, see above
```

It drops the four records and leaves the FDR record in place, so `restored` runs the baseband updater and asks for `BasebandData`. Liter8's TSS proxy already forwards baseband TSS requests upstream to Apple unmodified and only captures the reply containing `ApImg4Ticket`, so a BBTicket should be obtainable for a real ECID.

### Measured result, n104ap 24B5099f, 2026-10-09

Device-validated. The erase restore finished clean (`Status: Restore Finished`, zero errors) and the baseband updater ran for real:

```
Updating baseband (19)
restore_handle_data_request_msg: type = BasebandData
Sending Baseband TSS request...        -> Received Baseband SHSH blobs
restore_sign_bbfw: keeping psi_ram.bin / SYS_SW.elf / RFFW.elf / ... in bbfw
Sending BasebandData now... Done sending BasebandData
(second TSS request, carrying BbNonce)
Updating Baseband completed.
await_update_baseband result=0   baseband_postseal result=0
```

21 seconds across two personalization rounds, against 83 ms and 91 ms of nothing with the records applied. `bbticket.der` now lands beside the images in `<preboot>/<hash>/usr/local/standalone/firmware/Baseband/ICE19/`, the path chain is created `755` rather than `700`, and the baseband updater writes a real 1.5 MB `bbfs/static.nvm` instead of a generated stub.

**So the four records were the entire reason the modem had no firmware, and removing them does not break the restore.**

### Cellular still does not work, for a different reason

The modem now reaches ACIPC `bootstage = 1` (was 0) and the failure reason moves from `Baseband Firmware Path Not Found` to `output did not return done`. The BBU channel gets past firmware load, power-on, transport, and the chip identity query (`chipID:0x68 certID:0x1F3F5BDF`, now with no `kBBUReturnUnPersonalizedImageError`), and then fails on **calibration**:

```
could not locate .../bbfs/calib.nvm  ->  CAL: searching in FDR  ->  Identifier: bbcl
AMFDRDataApTicketIsTrusted returning true
_AMFDRDecodeVerifyChain: PKI: check payload hash with signature (success)
_AMFDRDecodeInstPropertyMatching: kFDRTag_inst propertyLength (sik) (130) != sikLength (96)
AMFDRDecodeTrustEvaluation bbcl:... returned code=0x0000000040004000
BBUFDRUtilities: The root cause of the AMFDR failure is NOT missing bbxx file
3: Fatal error 3 in FDR data validation/decode
```

The calibration blob is present in FactoryData and its PKI chain and payload signature both verify. Only the instance identity match fails. Parsing `mandev-bbcl-*` shows the `inst` tag is `sik-00000068-<...>-04 9B2387...` — a 130-hex-character, 65-byte, `04`-prefixed value, while the device computes 96 hex characters (48 bytes).

Inference, not directly proven: a `04`-prefixed 65-byte value is an uncompressed EC public key, so the FDR identity is a key the device cannot reproduce, and it is substituting something SHA-384-sized. `chosen/SEPFW` is empty on the booted device, and Liter8 neuters SEP and AppleCredentialManager with roughly fifty kernel records. The `sik` is the kind of value SEP holds.

**Cellular is therefore gated behind SEP, not behind this patch.** Fixing SEP is the honest route. The only other opening is that the loader checks `/var/wireless/baseband_data/bbfs/calib.nvm` before falling back to FDR, so a valid `calib.nvm` obtained some other way would skip the sealed path entirely; whether the modem accepts calibration that did not come through FDR is unknown.

Full measurements, including the dead-end hand-staging attempt, are in the private research tree under `research/cellular/`.

Full investigation, including the dead ends and the device-side technique notes, is in the private research tree under `research/cellular/`.

## The calibration gate, and `--demote-ap`

`--keep-baseband` fixes firmware provisioning. What stops cellular after that is **calibration**, and the gate is now identified precisely.

`libFDR.dylib` will not unseal the factory calibration blob (`bbcl`, present in FactoryData, PKI chain and payload signature both verifying) because the FDR instance identity is a SEP key attestation:

```
aks_sik_attest failed : %d      _aks_sik_attest      ___der_key_op_sik_attest
kFDRTag_inst propertyLength (sik) (130) != sikLength (96)
```

`aks_*` is the Apple Key Store, so the `sik` is SEP-held. With SEP neutered the device cannot reproduce it: 130 hex characters stored, 96 computed. (This also rules out effaceable storage, so `no-effaceable-storage=1` is not implicated.)

The same library skips the check entirely when `AMFDRIsNonDefaultDemotionState` holds. Disassembled, that function makes three MobileGestalt reads and no SEP call:

```
isNonDefaultDemotionState = CertificateSecurityMode
                         && EffectiveSecurityModeSEP
                         && !EffectiveProductionStatusAp
```

logging `AP is in non-default demotion state, ignore sik verification`.

### Why it takes two different patches

Those answers come from `/chosen`. **Every one of these properties is zero in the DeviceTree image, and iBoot overwrites most of them at boot from the chip's real fusing state**, which was measured rather than assumed:

| property | DT image | live | who wins |
|---|---|---|---|
| `certificate-security-mode` | 0 | 1 | iBoot (already what we need) |
| `effective-production-status-ap` | 0 | 1 | iBoot |
| `effective-security-mode-sep` | 0 | 0 | DeviceTree — iBoot never writes it |

So a DeviceTree-only patch is inert for the production status, and that is exactly what a first attempt showed (`[already-applied]`, because the template is already 0). `--demote-ap` therefore does two things:

1. **`IBootProductionStatusResolver`** suppresses the publish in iBoot. The publish is conditional, so declining to publish leaves the template's 0 intact:

   ```
   ADRP X8, name@page ; ADD X8, X8, name@pageoff   ; "effective-production-status-ap"
   STP  X8, X8, [SP,#imm] ; ADD X8, X8, #len
   BL   <evaluate>
   TBZ  W0, #0, <next property>                    ; low bit clear = do not publish
   ```

The `TBZ` becomes an unconditional branch **to its own target**, read from the instruction being replaced rather than computed, so a shifted layout fails loudly instead of mispatching. On 24B5099f this resolves to `0x24118`, `360000e0 -> 14000007`; the record is verified against the beta-4 iBSS fixture too, so it is semantic rather than pinned to one build.

2. The `normal` DeviceTree plan sets `/chosen/effective-security-mode-sep` to 1.

`certificate-security-mode` already reads 1, so no third patch is needed.

### Using it

```sh
liter8 fw get-boot --demote-ap    # plus --serial if you want the UART console
liter8 fw boot
```

`get-boot` owns both the normal-boot iBoot and the DeviceTree, so it is the only action that takes the flag. Default output is byte-identical without it, and the pinned fixtures are unaffected.

**This is experimental and unvalidated.** It rewrites the device's advertised security state, which far more than AMFDR reads, and no boot has been shown to survive the claim on a production-fused part (`CPFM:03`). It is tethered, so a failed boot costs a pwn DFU and another `get-boot`/`boot`, but budget for that.

What to look for, in order:

1. `AP is in non-default demotion state, ignore sik verification` in the CommCenter log. That single line means the gate flipped.
2. BBU should then unseal `bbcl` and write a genuine `calib.nvm` itself. Do not pre-place a hand-extracted file; the point is to get the real one.
3. Watch the first boot attempt. If `boot state changing Booted -> Resetting` repeats, stop: a modem crash-loop can reach a kernel assertion at `ICEBBControl.cpp:314` and panic the device. Remove the files from SSHRD rather than letting it run.

There is also a hardware route: `usbliter8ctl demote` sends a single control transfer from pwned DFU and changes the chip state at source, which would set all six properties without any firmware patch. It is one command, but its persistence and its effect on SEP, AMFI and Secure Boot are unknown, so the patched route above is the one that is version-tracked and reversible.

### Measured: `--demote-ap` does not boot

Tested on n104ap 24B5099f. Both patches applied as designed — `0x24118` `360000e0 -> 14000007` in iBSS and iBEC, and `/chosen/effective-security-mode-sep [updated]` — the chain was accepted through `bootx`, and then the kernel panicked before it finished initialising:

```
panic(cpu 0 caller 0xfffffff0383b35b0): "LLC PIO error (addr map hole/size mis-match)
  from snoop: FAR=0xffffffe6c6554000
  LLC_ERR_STS/ADR/INF=0x11000ffc00000200/0x148400210010fb0/0x2003
  addr=0x210010fb0 cmd=0x48(acc_biuafi_cmd_ncwrincr_do)"
  @AppleLightningErrorHandler.cpp:413
OS release type: Not set yet
OS version: Not set yet
```

A PIO write to an unmapped SoC register, in early kernel init. Note this is a **different** panic from the `ICEBBControl.cpp:314` modem-crash-loop assertion — the demotion claim itself is what fails, not anything baseband.

Most likely cause, not isolated: `effective-security-mode-sep = 1` on a device whose SEP is neutered. Claiming SEP security mode is active makes a driver take the secure path and touch a register block that is not there. `effective-production-status-ap` being suppressed is the less likely half, since demotion normally relaxes checks rather than enabling hardware access.

**The consequence is that this route is probably dead.** The gate needs all three terms, so `EffectiveSecurityModeSEP` must be true, and making it true is what appears to panic. These six `/chosen` properties are a mutually consistent set that the whole driver stack reads; faking one of them in isolation is not the same as being demoted.

The flag and `IBootProductionStatusResolver` are kept because the resolver is correct and the finding is reusable, but the help text now says plainly that it does not boot. Recovery is one pwn DFU plus `fw get-boot --serial` and `fw boot` with the flag off, which was verified.

**What remains is Route A, real hardware demotion** — `usbliter8ctl demote`, a single control transfer from pwned DFU. That changes the chip state so iBoot publishes a *consistent* set of properties rather than a contradictory one, which is exactly the difference that matters here. It is also a chip-state change rather than a file, with unknown persistence and unknown interaction with the existing SEP and AMFI patches, so it deserves a deliberate decision rather than being bundled into a flag.

## Correction: it is an unmigrated FDR seal, not a missing SEP capability

The section above concluded cellular was gated behind SEP. **That was wrong.** Decompiling `libFDR.dylib` rather than reading its strings gives the real answer.

`__AMFDRDecodeInstPropertyMatchingWithType` only compares the sik when one is supplied:

```c
result = 1;
if (a6 != 0 && a5 != 0) {               // sikLength, sikValue
    if (a6 == v14 + ~a4) { memcmp(...) }
    else error "propertyLength (sik) (%d) != sikLength (%zu)";
}
return result;                          // sikLength == 0  =>  SUCCESS
```

A device that produced *no* sik would pass. Ours fails the other way: a sik was produced and its length is wrong. Confirmed by absence — `sik is NULL`, `Unable to get sik`, `aks_sik_attest failed`, `sik_pub_key is NULL` and `aksStatus is %d` appear in none of the captures, so `aks_system_key_get_public` succeeded.

The two lengths are two encodings. `AMFDRDataCreateSikPubDigestIfNecessary`:

```c
if (sikPubLen < 0x42) return as-is;              // < 66 bytes: raw pub
alloc 48; digest(sikPub, sikPubLen, buf);        // >= 66 bytes: SHA-384
```

| | bytes | hex chars | form |
|---|---|---|---|
| stored in `mandev-bbcl-*` | 65 | 130 | raw pub, and it begins `04` |
| computed now | 48 | 96 | SHA-384 of a pub ≥ 66 bytes |

65 bytes is an uncompressed P-256 point; a pub of ≥66 bytes that digests to 48 fits P-384. `AMFDRDeviceCopySikPub` takes it from `aks_system_key_get_public(1, 1, …)`, the AKS system key. And `iPhone12,1`'s sealing-map entry (`0ac5773f7883fdce0cf94de5a9a1fd4a518dda47`) carries no `SikOverride` and no `AllowSikPubMissingWhenUnseal` for `bbcl`, so that key is what gets used:

```json
{ "Tag": "bbcl", "DataInstanceIdentifier": "BasebandUniqueId",
  "Attributes": ["RequiredToPerformManifestCheck","StoreCombined","RequiredToSeal"],
  "MaxSize": 786432 }
```

**So the factory-sealed `bbcl` identity embeds the AP's AKS system key as it was at manufacture, and the device now presents a different form of it. Nothing is broken on either side; the seal was never migrated.**

### What migrates it

`restored_external` runs the reconciliation during restore, as distinct stages:

```
fdr_recover                    "failed to recover FDR data"
fdr_auto_challenge_claim       "failed to AutoChallengeClaim FDR data"
verify_fdr_data                "failed to seal/verify FDR data"
fdr_verify_sealed_manifest     "failed to verify sealed manifest with the baseband"
update_firmware_post_sealing   "failed post-sealing updater"
```

The host side demonstrably happens — our restore log has `Sending FDR Trust data now... Done sending FDR Trust Data` — but `restored-external.fdr-result` forces `RestoredFDRRecover` to report success without doing the work. It is the one record `--keep-baseband` deliberately keeps, and the last Liter8 patch in this path.

### `--keep-fdr`

**Historical. This flag is also gone**, and this section is why: it only ever enabled an FDR recovery that was then measured not to re-seal, so its one possible effect was failing a restore for nothing.

```sh
liter8 fw make-cfw --keep-baseband --keep-fdr --serial
```

Drops `restored-external.fdr-result` so FDR recovery actually runs. Combined with `--keep-baseband` the resolver emits **zero** records and `restored_external` is left byte-identical to stock (verified by SHA-256), which `apply` handles without error.

Off by default. **Tested on n104ap 24B5099f, and it does not fix cellular.** It is kept because it establishes two facts, not because it helps.

The restore itself was clean: no error line anywhere in 2293 log lines, and every FDR stage returned `result=0`, including `fdr_recover` (0x634) and `fdr_verify_sealed_manifest` (0x63D). Baseband also ran in full, two `BasebandData` rounds and `Updating Baseband completed.`

But `mandev-bbcl-00000068-...` on FactoryData was **byte-identical** afterwards, both copies SHA-256 `3ba1e16ceda6f40baa7bcf57759ac927fb90725599db16ecea49fcddeb0feceb`. So `fdr_recover` reports success and does not re-seal `bbcl`. Recovery is not a re-sealing operation on this path.

The two facts worth keeping:

1. **The FDR patch is not load-bearing for a CFW restore.** The restore completed with the record absent, which is the opposite of the assumption the resolver was named for. Anything built on "removing it may simply fail the restore" can be dropped.
2. Combined with `--keep-baseband`, the resolver emits **zero** records and `restored_external` is left byte-identical to stock, which `apply` handles without error. That is a useful property to have proven for any future opt-out.


What actually addresses the sealed-calibration problem lives in userspace, in the one process that performs the unseal. See the next section.

## The sealed-calibration fix: `l8fdr.dylib`

`device/fdrfix/l8fdr.c` -> `/usr/lib/l8fdr.dylib`, built by `fetch_payloads.sh cellular` and deployed by the `cellular` step of `sshrd_provision.sh`.

### What it is for

With `--keep-baseband` the modem gets real firmware, but calibration never loads:

```
BBUICE16UpdateSource: CAL: searching in FDR
BBUFDRUtilities: DataClass: bbcl, DataInstance: "00000068-65F6E48C9D07BE4500000000"
BBULog: _AMFDRDecodeVerifyChain: PKI: verify cert was issued by trusted root 0 (success)
BBULog: _AMFDRDecodeVerifyChain: PKI: check payload hash with signature (success)
BBULog: _AMFDRDecodeInstPropertyMatching:
        kFDRTag_inst propertyLength (sik) (130) != sikLength (96)
BBUICE16UpdateSource: CAL: not found in FDR
```

The certificate chain and the payload signature both verify. The only failure is the data *instance identity*. FDR names each sealed instance after the AP sealing identity key, and `AMFDRDataCreateSikPubDigestIfNecessary` keeps that key verbatim below 66 bytes but SHA-384s it at 66 or more. FactoryData was sealed with a 65-byte key, 130 hex characters; this device's `aks_system_key_get_public` returns 66 bytes or more, so it computes a 48-byte digest, 96 hex characters. The device is not failing to produce an identity, it produces a newer one than the seal was made with, and nothing on the device turns one into the other.

### How it works

`_AMFDRDecodeInstPropertyMatchingWithType` guards its sik comparison with `if (sikLength != 0 && sikValue != NULL)` and returns a match when neither is supplied. `_AMFDRSealingMapPrepareAMFDRForCopyLocalData` decides whether to supply them:

```c
if (AMFDRIsNonDefaultDemotionState(amfdr) ||
    os_variant_is_recovery("com.apple.libFDR")) {
    log("AP is in NeRD or non-default demotion state, ignore sik verification");
    AMFDRSetOption(amfdr, <skip sik>, kCFBooleanTrue);
}
```

Only the instance-name component is dropped. The PKI chain and payload signature are still checked. The gate exists because the restore OS has no AP sealing identity either and still has to read sealed data.

`AMFDRIsNonDefaultDemotionState` is three MobileGestalt queries and no SEP call:

```c
result = CertificateSecurityMode && EffectiveSecurityModeSEP && !EffectiveProductionStatusAp;
```

and `AMFDRSealingMapCallMGCopyAnswerInternal` consults a provider registry *before* asking MobileGestalt:

```c
if (provider != 0) {
    log("Overriding query for %@", key);
    return provider(key, error, context);
}
```

That registry is filled by `AMFDRSealingMapRegisterCustomQueryProvider`, which libFDR exports. So the dylib answers those three keys through libFDR's own published interface: no interposing, no binary patching, nothing in the boot chain.

This is the same three values the `--demote-ap` work tried to change, and it is worth being explicit about why it succeeds where that failed. Those attempts changed the values *underneath* MobileGestalt, in the DeviceTree, in iBoot and in hardware, and all three are closed. The values were always reachable from above.

### Two approaches that do not work, and why

**Interposing `os_variant_is_recovery` does not fire.** libFDR and libsystem_darwin both live in the dyld shared cache and that call is bound inside the cache, where a `__DATA,__interpose` section in a dylib loaded late by `LC_LOAD_WEAK_DYLIB` does not reach it. Measured on 24B5099f: the constructor logged on all four CommCenter launches and the replacement logged zero times, with `ignore sik verification` absent from 497624 lines of unredacted CommCenter log. `build.sh` fails if an `__interpose` section reappears, so this cannot regress silently.

**`AMFDRSealingMapSetMGCopyAnswer` is a stub.** It decompiles to a single `JUMPOUT` into the logging function. Despite the name it installs nothing.

### Scope

The process is `CommCenter`, from device logs rather than inference. Three guards, each of which alone reduces the dylib to stock behaviour:

1. the host process must be `CommCenter`, resolved once in the constructor;
2. `/usr/lib/.liter8-fdr-sik-bypass` must exist, root-owned and not group/other writable;
3. only those three keys are answered, from a table, with the answer carried in the provider context rather than looked up by name.

Every other MobileGestalt query in the process is untouched and no other process is affected, so nothing else starts believing the AP is demoted. Guard 2 is the recovery handle: deleting one file restores stock behaviour without re-deploying a 40 MB re-signed binary, which matters because CommCenter failing to start is hard to diagnose from a boot log.

### Why `/usr/lib`, and the cost of it

The dylib and its marker sit in `/usr/lib` beside `l8pair` and `l8remotepairing`. That volume is APFS-sealed and read-only on a booted device (`mount -uw /` fails with `mount_apfs: volume could not be mounted: Operation not permitted`), so every change to this dylib needs an SSHRD trip, which on a tethered boot is two DFU cycles.

Putting it on the Data volume at `/var/jb/usr/lib/` to avoid that was tried and **does not work**. dyld silently declines to load it into CommCenter: no `l8fdr` line in 1775821 lines of boot log and no AMFI, dyld or code-signature message anywhere, while the load command was verified present in the deployed binary by raw byte search, the file and marker were in place, and the identical file loaded fine from that path into an unrestricted process under `DYLD_INSERT_LIBRARIES`. Inference: a restricted platform binary may only load dylibs from the sealed system volume.

So budget for the DFU cycles instead, and put as much verification as possible in `fdrfix/build.sh` rather than discovering problems on the device.

`DYLD_INSERT_LIBRARIES` is not an alternative for loading it without the load-command patch either: dyld strips `DYLD_*` for a platform binary with restricted entitlements, which is why Liter8 patches load commands in the first place.

### Delivery

No new mechanism. `CommCenter` is in `userland_fixups.py`'s `structural_loads`, so it gets one `LC_LOAD_WEAK_DYLIB` appended by `launchdhook/patch_launchd.py` plus an entitlement-preserving re-sign, with no instruction patch. Verified on the built artifact: appended last, arm64e matching CommCenter, 222 entitlement keys preserved, signing identifier still `com.apple.coretelephony`. The patched binary launches, ARI comes up and `Set Policy request for sim[0]` round-trips, so library validation is not an obstacle here.

```sh
liter8 fw provision            # includes the cellular step
./sshrd_provision.sh cellular  # or the step alone, from the staged workflow directory
```

### Reading the result

Baseband log messages are **privacy-redacted by default**, so a marker missing from the log proves nothing until private data is enabled:

```sh
# on the device, then: launchctl kickstart -k system/com.apple.logd
/Library/Preferences/Logging/com.apple.system.logging.plist
    Enable-Logging = true, Enable-Private-Data = true
```

`idevicesyslog` is live only and the window that matters is about 90 seconds into boot. To read history instead, the device's own `abmlite` dumps the persisted log:

```sh
abmlite logdump oslog 500000 /var/jb/tmp/cc.txt -p CommCenter
```

The first argument is a size, not a duration, and it needs CommCenter's ABM server running, so it must be retried after a CommCenter restart.

### Validation state

**Device-validated on 2026-10-09**, iPhone 11 (`iPhone12,1` / `n104ap`), iOS 27.2 `24B5099f`. Cellular works: SIM ready, IMSI and phone number read, carrier bundle matched, registered on the network.

```
BasebandStatus: BBInfoAvailable        BasebandVersion: 8.00.00
SIMStatus:      kCTSIMSupportSIMStatusReady
SIMTrayStatus:  kCTSIMSupportSIMTrayInsertedWithSIM
MCC/MNC: 405 / 854                     CarrierBundleInfoArray[1]
Registration status: kTrue (at least one slot registered)
```

The chain is logged end to end, in two seconds:

```
09:01:06  l8fdr: loaded in CommCenter, registered 3 of 3 demotion-state answers
09:01:08  AMFDRSealingMapCallMGCopyAnswerInternal: Overriding query for CertificateSecurityMode
09:01:08  l8fdr: answering CertificateSecurityMode = true so FDR treats the AP as demoted
09:01:08  _AMFDRSealingMapPrepareAMFDRForCopyLocalData: AP is in NeRD or non-default
          demotion state, ignore sik verification          (x3: Cal, PROV, Pac)
```

Attribution comes from splitting one 887779-line CommCenter log at the point the working provider registered. Same device, same build, same log; the only variable is whether the provider is installed:

| marker | before | after |
|---|---|---|
| `CAL:  not found in FDR` | 48 | 0 |
| `boot failed due to` | 80 | 0 |
| `ignore sik verification` | 0 | 3 |

That also answers the question the previous revision of this document left open. The modem boot failure was downstream of the missing calibration: give the modem its calibration and it boots, reads the SIM and registers. There is no second, independent problem.

Full readings: `research/cellular/WORKING-READINGS.txt`, analysis in `research/cellular/README.md` section 17.

## Voice: the two data-activation gates in CommCenter

`l8fdr.dylib` gets the modem booting, the SIM reading and the device registering. It does not get you a phone call. Registration is the radio layer; a call needs a voice path on top of it, and on LTE that means VoLTE, which means IMS, which means a data bearer. Without one the log reads:

```
kDataNotSupported{ActivationStatus failed in DataSettings }
kDataNotSupported{context is not assigned }
IMS APN: false      ims '' QS:kNotConfigured
dialed over CS because of no IMS reg     Call ended. VoIP: false
```

so voice falls back to a circuit-switched path, and on a network that has retired 2G/3G for this subscriber there is nowhere to fall back to. The operator says the number is unreachable.

### Why there is no data bearer

Because CommCenter does not believe the device is activated. `mobileactivationd` is patched to short-circuit its activation *state*, which satisfies lockdown and Setup, since those only ask for the state. CommCenter asks for more: it reads an `ActivationStatus` whose default construction is `fManifestResult = 2, State = 3` with both flags clear, and on this device nothing ever fills it in.

Completing a real activation is not available, and that is measured rather than assumed. The modern flow, `CreateTunnel1SessionInfoRequest`, needs a SEP-attested signing key, and SEP key generation fails for every process on this CFW:

```
ctkd:              <sepk:*(d) kid=da39a3ee5e6b4b0d> generated for mobileactivationd
mobileactivationd: SecKeyCreateRandomKey failed: -25300 <- CryptoTokenKit -7
                   -[MACollectionInterface signingKey]: Failed to create ref key
                   Failed to collect signing key attestation
```

`CryptoTokenKit -7` is `TKErrorCodeTokenNotFound`: ctkd has no Secure Enclave token registered. The token identifier in that handle is `*` and `da39a3ee5e6b4b0d` is SHA-1 of the empty string, so the handle was formed over an empty token id. A four-case control test (software key, then three Secure Enclave variants) confirms the software path works and every Secure Enclave path fails the same way, so this is not entitlements and not this one daemon. The consumer has to be patched instead.

### Two gates, in series

This is the part worth reading, because getting it wrong costs a DFU cycle per attempt. There are two refusals on the path and the outer one returns before the inner one is reached, so fixing the inner one alone changes nothing you can observe.

```
canActivateWithoutOverrides
  index = -1
  fetchContextIndex(&index, ...)
  if (index == -2) { status = -3; reason = "context is not assigned"; return }   <- outer
  settings = this->vtable[0x90](1)  ->  canActivateDataSettings                  <- inner
  settings = this->vtable[0x90](0)  ->  canActivateDataSettings                  <- inner
```

`canActivateDataSettings` is where `ActivationStatus failed in DataSettings` comes from. The counts show the ordering plainly: the outer reason fired 80 times in a boot, the inner one 14.

`-2` means no PDP context index has been allocated for this connection. Allocation is not broken in general. `OTAActivation` and `BootstrapRoamingInternetBypass` each hold a context and each is published as a network agent. Those two are the bootstrap data path, the one that exists so an unactivated iPhone can reach Apple over cellular. `Internet` holds no context, and cannot be given one while activation is refused, which is the circle both patches break.

`CommCenterDataActivationResolver` resolves both:

```
commcenter.data-connection.context-index      0x92394  54000201 -> 14000010
commcenter.data-settings.activation-status    0x936e8  36000460 -> d503201f
```

The outer one becomes an unconditional branch to the conditional branch's own target, not a `NOP`. The instruction before it is a load, which sets no flags, so a `NOP` would leave the condition undefined and fall into the failure block every time, which is backwards. Falling through is safe because the fetched index is read exactly once in the whole function, by the comparison being patched, and never again, so nothing downstream can index anything with a negative value.

Both are anchored on their own reason string, its unique ADRP+ADD xref, and the exact instruction shape around it. CommCenter keeps ten of these reason strings in one table and each has exactly one xref, but only the outer gate's is reached by a comparison against `-2`, which is what makes `CMN W8,#2` a usable discriminator. No offsets are inputs.

### Validation state

**Device-validated on 2026-10-10**, same device and build. Incoming calls ring and connect, confirmed by the caller, and the log shows the call on IMS rather than CS:

```
CommCenter: Call State changed from (Active: true, VoIP: true) to (Active: false, VoIP: false)
CommCenter: Voice Call ended. VoIP: true
```

`VoIP: true` is the result. The structural change is on the interfaces, one boot apart, same SIM:

```
before   pdp_ip0: OTAActivation, BootstrapRoamingInternetBypass        (nothing else)
after    pdp_ip0: Internet, WirelessModemTraffic, WirelessModemAuthentication,
                  OTAActivation, EntitlementTraffic,
                  BootstrapRoamingInternetBypass, InternetProbe, LLWirelessModemTraffic
         pdp_ip1: IMS, Em      flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> rtref 1
```

`pdp_ip1` carrying IMS and being `UP,RUNNING` is the part that makes voice work: SIP registration finally has a PDN to run over.

Reason counts from a live 24-second capture on the booted device. The control is stated first on purpose, because during this investigation a tool returned a false zero three separate times and was believed: 3721 CommCenter lines in the window, so the zeros below are real absences.

| reason | before | after |
|---|---|---|
| `context is not assigned` | 80 | 0 |
| `ActivationStatus failed in DataSettings` | 14 | 0 |
| `Default in canActivateWithoutOverrides` | 70 | 0 |
| `Currently is not allowed on the SIM (current)` | 10 | 1 |
| `no IMS reg` | present | 0 |
| `CAL:  not found in FDR` | 0 | 0 |
| `boot failed due to` | 0 | 0 |

The surviving refusal is `DATA.Connection.Internet.2`, which is SIM slot two, and slot two is empty. Refusing a data context on a slot with no SIM in it is correct. The last two rows re-check the calibration fix, because this trip also replaced `l8fdr.dylib` with a build that drops a dead constructor; calibration still unseals.

Supporting state, deduped over the window:

```
  32  VoLTE enabled: 1, IMS_preference: 1, vLQM: 100, Attached:1
  25  kCTRegistrationStatusRegisteredRoaming
   5  kCTRegistrationStatusRegisteredHome
```

`RegisteredRoaming` is expected, not a fault: the SIM is MNC 45 and the network is MNC 49 on the same operator, so this is national roaming, and `kOperatorRoamingInfo_3GPP_Roaming` is still `false` for the active slot.

### What still does not work

**Cellular data.** The `Internet` agent is published and the gate no longer refuses it, but the interface is not `RUNNING` and no `pdp_ip*` holds an inet address, so the bearer has not been activated. WiFi was connected throughout, which is on its own enough reason for iOS not to bring cellular data up, and the Settings cellular-data and data-roaming toggles have not been checked on this device. Treat that as unfinished rather than as a third gate: the gate answered "may this connection be activated", and it now answers yes.

**iMessage and FaceTime.** They need push, and `apsd` has no token (`APSSystemTokenInfo no token info found in keychain`) for the same Secure Enclave reason above. These are not expected to work without SEP.

**SMS** is untested since the fix.

Full measurements in the private research tree, `research/cellular/README.md` sections 19 to 21.
