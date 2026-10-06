# iPad 8 Wi-Fi, iPadOS 26.7.1 / 23H30

Experimental workflow for `iPad11,6` / `j171aap`, A12 / T8020. The original
2026-10-02 run note reports a completed CFW erase restore and working SSHRD
SSH. Normal iPadOS boot, provisioning completion, finalization and repeat boot
remain unverified. The current upstream integration has not been run on device.

Only the Wi-Fi board has a workflow profile. The kernel profile also identifies
`j172aap`, which shares the kernel; that does not enable Cellular device support.

## Identity and guards

Measured from the `Customer Erase Install` identity in
`iPad_10.2_2020_26.7.1_23H30_Restore.ipsw`, rather than its filename:

| Field | Value |
| --- | --- |
| Product / board | `iPad11,6` / `j171aap` |
| Build / version | `23H30` / `26.7.1` |
| CPID / BDID | `0x8020` / `0x24` |
| Kernel | `kernelcache.release.ipad11b`, 59,031,552 decompressed bytes |
| XNU fingerprint | `xnu-12377.162.13.700.38~2/RELEASE_ARM64_T8020` |
| Clean kernel SHA-256 | `eee662eba10dc9302a8999677361adf12ce86a61078ed387181ab9a183c334be` |
| System image | `141-38001-023.dmg.aea` |
| launchd SHA-256 | `1b37dae048542729a622a1a3f4b77ec8829d32e918f0d6a0c0c037f32d9e84b1` |
| Service-cache SHA-256 | `af9183685525a0833fea7a16c7a81b3f85e14372ea33d49f3e1ec6ab1a90ca4f` |
| LaunchDaemons / Setup methods | 672 / 58 |

Input sizes, full clean/output hashes, preimages and replacements are in
`fixtures/23H30/j171aap/`. These are historical exact-build oracles, not runtime
lookup tables. Private firmware is needed to reproduce their verification.

## Resolver changes and evidence

| Family | Selection and behavior |
| --- | --- |
| Kernel identity | Exactly two equal `/RELEASE_ARM64_T...` tokens; replace RELEASE with PATCHED without changing length. Missing, inconsistent or unterminated tokens fail. |
| Boot arguments | Accept `SUB X0,X29,#imm` as well as `ADD X0,SP,#imm` for the stack buffer. Still require the unique isolated `%s`, X2 format pointer and `MOV W1,#0x400`. |
| iBEC nonce | The same nonce-cache MMIO address can be formed by a direct-call leaf ending in RET, instead of inline MOV/MOVK/MOVK. The original load, cache-bit branch, generator and cached-nonce destination checks remain. |
| ACM | 25 distinct entries, 50 records. Reuse unchanged 24A435 shapes, replace eight drifted entries and preserve the PAC-less leaf's BTI. Only this variant permits the relocated method order. |
| PPL trust cache | Unique complete CDHash-copy/type-2-query/canary function and unique caller assigning trust level 9. Change only `CSET W0,EQ` to `MOV W0,#1`; query, authenticated frame and return remain. |
| MobileActivationD | Unique `getActivationStateWithCompletionBlock:` method. Its migration gate targets a one-entry dictionary block; preserve the key, replace the value with the unique Activated CFString. |
| Public sandbox | Existing 11 MACF records. The scoped vnode-open cave is absent; the full sandbox/boot plans still fail rather than guess a cave. |

ACM's command graph links `callPlatformFunction` (`0x1b203a8`) to
`cmdContextV2` (`0x1b20584`) / `cmdContextV3` (`0x1b2066c`), then the common
five-argument `performCommandGated` (`0x1b20880`) and `_performKernelControl`
(`0x1b21244`). `performSCRDInitialization` (`0x1b21bac`) calls the eight-argument
`sendSEPCommand` (`0x1b21db0`), whose body calls the buffer writer and
`sendSEPMessage` (`0x1b23cfc`). `setPowerStateGated` (`0x1b311f4`) references its
own diagnostic string at `0x56a23b`. The old updateAnalytics shape aliases
unlockItem at `0x1b23058`; it is omitted, not patched twice. Its remaining
behavior is a device-validation question.

The PPL helper is at `0x324da20`, its result at `0x324da64`, its trust-level-9
caller at `0x324d5d4`. These numbers are comparisons after resolution. The
PPL correction follows the trust-cache policy in PongoOS commit `031e5cc`.

Fixtures cover kernel credential-manager (50), sandbox-public (11),
ppl-trust-cache (1), boot-public (118), ibec-restore (6), mobileactivationd (5)
and asr (1). Restore composition has 21 records. The 118-record public plan
explicitly omits upstream's Valeria repair on this exact kernel profile: its
executable cave is unvalidated. Other profiles keep the upstream repair.
Standalone Valeria and the full boot plan still require their own evidence.

## Containers and workflow

Generic LZFSE (`0x801`) round-tripped on macOS but failed in this iBoot with
`0x40040028`. Repacking uses and checks iBoot-compatible LZFSE (`0x891`) and
copies the complete PAYP DER child. The abandoned iBEC caller bypass at
`0x27f58` is not part of the port. No image-auth bypass was added for that error.

`DeviceBootPlan` declares the required firmware components and normal trust
cache. Python uses manifest paths and that policy, with no product/board branch.
For this identity: RestoreLogo, ANE, AOP, AVE, GFX, ISP, SIO and SEP;
StaticTrustCache for normal boot, RestoreTrustCache for SSHRD. SPTM/TXM, PMP
and WCH are absent. Missing required firmware, a partial monitor pair or a pair
inconsistent with the profile fails before building/uploading. Existing iPhone
profiles retain their complete component set and RestoreTrustCache behavior.
Context schema 3 requires this explicit policy; old context files are rejected.

`CFW-iBSS.raw` is kept outside `Ramdisk`, so rebuilding normal/SSHRD artifacts
cannot overwrite the erase-restore transport payload. APFS Preboot is selected
by its ioreg role: the recorded iPad mapping is System disk1s1, Data disk1s2,
Preboot disk1s5, Update disk1s6. The `/mnt6` mountpoint remains unchanged.

23H30 launchd has only 40 bytes of load-command padding. `/usr/lib/lhook` fits
in a 40-byte weak dependency command; the previous path needs 48 bytes. The
install name, hook self-path, provisioner and verifier use the same short path.
The reverted ElleKit/two-stage injection changes remain reverted.

## Validation still required

Run `make check` on macOS with Swift 6 and XCTest. macOS CI exercises synthetic
resolver cases and container/workflow integration without Apple binaries.
Set `LITER8_FIXTURE_ROOT` to a private tree containing `offsets/23H30/` to
verify the original exact-build oracles. Tests skip each unavailable binary
separately; a skip is not confirmation of that resolver or output hash.

Repeat restore, SSHRD, provisioning, normal boot, finalization and repeat boot
on the integrated branch. Investigate scoped sandbox and Valeria separately.
Keep the workflow experimental until that complete acceptance sequence passes.
See [the runbook](../runs/IPAD8_J171AAP_23H30_RUNBOOK.md).
