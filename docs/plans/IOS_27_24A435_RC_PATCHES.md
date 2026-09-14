# iOS 27 RC `24A435` (iPhone 11 / n104ap): patch-by-patch port from beta 4

Extension document for adding `24A435` support to a tree that already supports `24A5390f`. For every patch the beta-4 build uses, it records the RC offset, whether the opcode changed, what changed, and how it is patched.

Branch: `ios-27-rc-support`

## Status

**RC resolves all 198 patch records the beta-4 fixtures cover, all 18 have exact-build oracles, and the complete workflow is device-validated.** An erase restore, SSHRD provisioning, normal boot and repeat boot passed on an iPhone 11 (`n104ap`). Post-boot checks confirmed root SSH, Procursus, persona 99, the icon token and the persistent PosterBoard wallpaper repair watcher.

|                    | beta 4 `24A5390f` | RC `24A435` |
| ------------------ | ----------------: | ----------: |
| Fixture plans      |                18 |      **18** |
| Patch records      |               198 |     **198** |
| Fixtures verifying |                18 |      **18** |

Both builds are resolved with the same resolver binary, so the two sides are directly comparable.

| Category                                            | Count |
| --------------------------------------------------- | ----: |
| `offset only` — opcode byte-identical, offset moved |   158 |
| `ORIG CHANGED` — RC original bytes differ           |    12 |
| `REPL CHANGED` — replacement is build-derived       |     4 |
| `ORIG+REPL` — both differ                           |     4 |
| `identical` — same offset _and_ bytes               |     2 |
| `NOT RESOLVED`                                      | **0** |

Two composite plans that have no fixture of their own also resolve: `kernel boot` (154 records) and `kernel boot-public` (119 records).

### Regression state

All 18 beta-4 fixtures verify unchanged, including `testCompatibilityKernelPlanCompositionAgainstBeta4Oracle`, which pins byte-for-byte agreement with the independent public Python `apply_patches.py` output. **No beta-4 fixture was modified**; see [the landing-pad decision](#decision-beta-4-stays-byte-identical-rc-keeps-its-pads).

### Workflow validation

The RC profile is registered as reviewed after exact-device validation on 2026-09-13. Normal firmware commands select it without `--experimental`.

## How to read the tables

Both builds were resolved with the same resolver binary, so the two sides are directly comparable.

| Category | Meaning | Action |
| --- | --- | --- |
| `offset only` | RC original bytes byte-identical to beta 4 | None |
| `ORIG CHANGED` | RC original bytes differ | Never transplant the beta-4 word; the pre-image guard would reject it |
| `REPL CHANGED` | Replacement is re-encoded per build | None; it is computed |
| `ORIG+REPL` | Both differ | As above |

---

## The defining RC change: BTI is enabled in the kernelcache

Apple turned on Branch Target Identification for the RC kernelcache. Most functions now begin with a `BTI C` landing pad (`0xD503245F`) **one word before** the `PACIBSP` that every resolver treated as the function start.

| Build | `BTI C` immediately followed by `PACIBSP` | total `PACIBSP` |
| --- | --: | --: |
| beta 4 `24A5390f` | **0** | 112050 |
| RC `24A435` | **87629** | 109000 |

IDA's own analysis of the RC kernelcache agrees and puts it more strongly: of 190337 functions it recognises, **140862 start with `BTI C`** and only 13233 start with `PACIBSP`. The higher number is expected — it includes functions that have a pad but no PAC prologue.

```asm
; beta 4                    ; RC 24A435
pacibsp                     bti     c          <- a BL lands HERE now
sub     sp, sp, #N          pacibsp
                            sub     sp, sp, #N
```

One beta-4 exception is worth knowing: `performLoggingLevelQueryGated` already began with `BTI C` on beta 4. BTI is not new to the architecture, only newly pervasive.

TXM did **not** change this way. All nine TXM patches resolve unchanged.

### Two different addresses, and the distinction that matters

A BTI build splits one concept into two:

|  | Address | Used for |
| --- | --- | --- |
| **entry** | the `BTI C` | what a `BL` targets, what a function pointer stores, boundary arithmetic |
| **prologue** | the `PACIBSP` | where a two-instruction stub must be written |

Conflating them breaks things in _both_ directions, and both were observed:

- Using the prologue as the entry collapses scan windows and makes predecessor checks read the pad. That was the original cause of two blockers.
- Using the entry as the stub target **destroys the landing pad**, which under BTI enforcement faults on the first indirect branch.

`ARM64.functionEntry` / `ARM64.functionStart` answer the first question, `ARM64.stubStart` answers the second. On a build without pads both collapse back to the same address, which is why beta 4 is unaffected.

### Is BTI actually enforced?

**Not determined.** Enforcement lives in `SCTLR_EL1.BT0`/`BT1`, and the RC kernelcache contains no writes to `SCTLR_EL1` — on SPTM-era devices that register is programmed by SPTM, which is a separate binary not present here.

So the risk of overwriting a pad is **unquantified, not disproven**. Every stub in this tree now preserves pads regardless, because doing so is free: the patched function becomes `bti c; <stub>` instead of `<stub>`, which is correct either way.

---

## Blocker 1 (resolved): AMFI post-validation compare had inverted polarity

**This was the one place where the beta-4 replacement word would have been actively wrong on RC.**

### Locating it

The anchor `AMFI: code signature validation failed` occurs exactly once in RC, at `0x65143d`. Its three ADRP+ADD references all sit in one function at `0x1f05b58` (1645 words, 71 direct callees). Searching RC for the beta-4 shape `tbz w?,#0x1a ; mov x0,x23 ; bl` returns exactly one hit, `0x1f0896c`, inside callee `0x1f0892c`.

### Why the resolver had found nothing

`KernelAMFIResolver` scanned each callee with `cursor = callee + 8` up to `nextFunctionStart(after: callee, 0x200)`. In RC the callee is the `BTI C` and `nextFunctionStart` looked only for `PACIBSP`, four bytes later — so `end` landed before `cursor` and the loop never ran.

IDA confirms the boundary independently: it reports the function as `0xfffffff008f0c92c .. 0xfffffff008f0ca64`, i.e. **starting at the BTI**, exactly the address the resolver was treating as belonging to the previous function.

### Correspondence evidence

Beta-4 `0x1f3c708` and RC `0x1f0892c` are the same function:

- identical argument shuffle `x19=x6, x20=x5, x22=x4, x25=x3, x24=x2, x23=x1, x21=x0`
- identical `tbz w2, #0x1a` gate on the same bit
- identical authenticated dispatch, including PAC discriminators `movk x17,#0xcda1,lsl#48` and `movk x16,#0x2e3b,lsl#48`, and vtable displacement `mov x17,#0x138`
- same diagnostic string family: `com.apple.private.oop-jit.loader`, `%s: %s disallowed due to OOP-JIT loader entitlement.`, `%s: %s disallowed due to OOP-JIT runner entitlement.`
- IDA independently resolves the fallthrough string reference as `aSHashTypeIsSha ; "%s: Hash type is SHA1"`

Only the frame size differs (`#0x70` beta 4, `#0x60` RC).

### The semantic change

```asm
; beta 4, site 0x1f3c750               ; RC, site 0x1f08978
tbz     w2, #0x1a, 0x1f3c758           tbz     w2, #0x1a, 0x1f08990
mov     x0, x23                        mov     x0, x23
bl      0x1f550f0                      bl      0x1f21878
cmp     w0, #2          <- SITE        cmp     w0, #1          <- SITE
b.ne    0x1f3c800   ; -> REJECT        b.ne    0x1f08990   ; -> ACCEPT
                                       str     x22, [sp]
                                       adrp    x3, "%s: Hash type is SHA1."
                                       b       0x1f08a34   ; -> REJECT
```

Beta 4 rejects when the hash type is **not** SHA256. RC rejects when it **is** SHA1. The branch sense is reversed.

Beta 4's replacement `cmp w0,w0` (`1f00006b`) sets Z, so `b.ne` is never taken and control falls through to accept. The identical word at the RC site also sets Z, `b.ne` is still never taken — but in RC the fallthrough **is** the SHA1 rejection block, so the patch would refuse every binary.

### Fix

`postValidationCompare` now derives the replacement from the branch sense rather than assuming beta 4's. It inspects the six words after the conditional branch: a rejection block materialises a format string with an `ADRP` and then branches to the shared logging tail, while the accept path continues into an authenticated vtable dispatch and contains neither.

| Build | Fallthrough | Replacement |
| --- | --- | --- |
| beta 4 | accept path | `1f00006b` — `cmp w0,w0`, forces EQ (unchanged) |
| RC | reject path | `ff070071` — `cmp wzr,#1`, forces NE so the accept branch is taken |

`0x710007FF` is `SUBS WZR, WZR, #1`: `0 - 1` leaves Z clear, so the `b.ne` at `0x1f0897c` is unconditional.

## Blocker 2 (resolved): `isDeviceInRestoreMode`

The anchor was always healthy — the cluster `…111\0rd\0rootdev\0-restore\0%02X` occurs exactly once, at `0x810e11`, and its `rd` literal has three ADRP+ADD references.

`KernelBootPolicyResolver` required `RETAB` at `functionStart - 4`. In RC that word is the `BTI C` pad for all three candidates, so all three were rejected:

| Candidate   | `start - 8`       | `start - 4`          | `start`            |
| ----------- | ----------------- | -------------------- | ------------------ |
| `0x28053d0` | `d65f0fff` retab  | `d503245f` **bti c** | `d503237f` pacibsp |
| `0x28a628c` | `d4200020` brk #1 | `d503245f` **bti c** | `d503237f` pacibsp |
| `0x28aa0cc` | `d65f0fff` retab  | `d503245f` **bti c** | `d503237f` pacibsp |

IDA confirms all three: `starts_at_BTI: true` for every one.

Fixed by routing the search through `ARM64.functionStart`, which returns the pad as the entry, so `entry - 4` reads the previous function's terminator again.

## Blocker 3 (resolved): `current_thread_ro` — an over-constrained signature

Not a BTI problem. The 8-word signature matched beta 4 uniquely at `0x32a2b80` and RC zero times. Bisecting: 5 words matched RC uniquely at `0x323590c`, 8 did not. Exactly one word differed:

```text
ok   0x323590c  want d503237f/ffffffff  found d503237f
ok   0x3235910  want a9bf7bfd/ffffffff  found a9bf7bfd
ok   0x3235914  want 910003fd/ffffffff  found 910003fd
ok   0x3235918  want d538d080/ffffffff  found d538d080
ok   0x323591c  want f9400001/ffc003ff  found f9420401
ok   0x3235920  want 90000008/9f00001f  found d0fecca8
DIFF 0x3235924  want 9107c108/ffffffff  found 91034108
ok   0x3235928  want a9402109/ffffffff  found a9402109
```

```asm
; beta 4                        ; RC
adrp x8, 0xbc3000               adrp x8, 0xbcb000
add  x8, x8, #0x1f0             add  x8, x8, #0xd0
ldp  x9, x8, [x8]               ldp  x9, x8, [x8]
```

The global moved pages. `MaskedInstructionPattern` already masked the ADRP page, but `allowDataLayoutDrift` relaxed only unsigned-offset `LDR`/`STR`, so the signature pinned the low 12 bits of an address that is free to move.

Fixed by extending `allowDataLayoutDrift` to `ADD (immediate, 64-bit, LSL #0)` with the same `0xFFC003FF` mask already used for load/store displacements.

**IDA cross-check:** `sub_FFFFFFF00A23990C` (file offset `0x323590c`) has **771 callers** — a hot leaf helper, which is what `current_thread_ro` should be.

A second, independent break then appeared in the same plan: the `mpc_ops` slots store the address a call lands on, which in RC is the pad, so the resolver's `PACIBSP` guard on `file_check_mmap` failed. Every one of those five hooks is reached _only_ through that table, i.e. always indirectly, so the stubs now start at the prologue and keep their pads.

## Blocker 4 (resolved): AppleCredentialManager, all 26 methods

Located in RC by masked prologue matching, then verified in IDA.

- **Segment:** every hit lies in `com.apple.driver.AppleSEPCredentialManager:__text`.
- **Order:** the 26 RC offsets appear in exactly beta 4's relative order. That is the cross-check that this is the same set and not 26 coincidences.
- **Match quality:** 21 of 26 matched their full beta-4 signature exactly and uniquely. `updateAnalytics` and `unlockItem` share an identical 32-word prologue and were separated by position. `performCommandGated` (12/16), `sendSEPCommand` (27/32) and `setPowerStateGated` (19/32) matched partially and were placed by the resolver's existing neighbour-bounded scoring.

**All 26 RC methods carry a `BTI C` pad, and ten of them have zero direct branch references** — they are reached only through a taken address:

`sepManagerMatchedThreadCallHandler`, `callPlatformFunction`, `cmdContextV2`, `performCommandGated`, `_setPropertiesGated`, `performDoubleClickQueryGated`, `performLoggingLevelQueryGated`, `handleSEPMessage`, `powerOffActionGated`, `sepManagerMatchedGated`.

For those ten the beta-4 approach of overwriting the first two instructions would remove the only legal indirect-branch target. All 26 stubs now start at the prologue instead.

The RC signature family `ios27-24A435-acm-v1` is recorded in `Sources/Liter8Core/Profiles/KernelCredentialManagerSignatures.swift` and its `pendingResearch` gate is lifted. The families deliberately stay separate rather than being merged behind a looser mask.

## Blocker 5 (resolved): iBSS normal boot-args slot

`ibss-restore` and `ibss-ramdisk` resolved a slot at `0x26cfc0`; `ibss-normal` did not.

### What the runs actually look like

Every zero run ending on a 4 KiB boundary, both builds:

|  | largest run | runner-up | total page-tail runs |
| --- | --- | --- | --: |
| beta 4 `24A5390f` | `0xd0e24..0xd1000`, **476 bytes** | `0x119fdd..0x11a000`, 35 bytes | 62 |
| RC `24A435` | `0x26cfb1..0x26d000`, **79 bytes** | `0x125fdd..0x126000`, 35 bytes | 42 |

| Plan | Literal | Bytes with NUL | Runs with room (incl. 8-byte guard) |
| --- | --- | --: | --- |
| restore | `-v wdt=-1 rd=md0 -restore` | 26 | **2** on both builds |
| SSHRD | `rd=md0 -v wdt=-1 debug=0x2014e backlight-level=1024` | 52 | 1 |
| normal | `-v debug=0x2014e launchd_unsecure_cache=1 wdt=-1 backlight-level=1024` | 70 | 1 |

### Two bugs, not one

The original code computed `writeOffset = (runStart + 8 + 15) & ~15` and kept every run where the literal then fitted, requiring the survivor to be unique.

1. On RC that 16-byte-aligned position leaves 64 usable bytes in a 79-byte run, so the 70-byte normal literal did not fit and no slot was found.
2. Relaxing the alignment to fix (1) exposed a second, worse problem. The strict 16-byte rule had been acting as a **selectivity filter**, not just an alignment convention: `0x119fdd + 8` rounded up to 16 is `0x119ff0`, and `0x119ff0 + 26` overruns `0x11a000`, so the 35-byte runner-up was excluded from the restore plan _by arithmetic accident_. With a narrower alignment it fitted, two candidates appeared, and `ibss-restore` began failing on **both** builds with an ambiguity error.

### The semantic fix

Identify the run by what it is — the section-tail padding, i.e. the uniquely largest page-boundary zero run — and only then place the literal inside it. Selection no longer depends on literal length at all, which is what made it unstable. Both payloads have one clearly dominant run (476 vs 35; 79 vs 35), so requiring a unique maximum is a stronger identity than any fit test.

Placement inside that run keeps the 8-byte guard after the last real section contents and then takes the widest alignment from 16, 8, 4, 2, 1 that fits. Alignment is a convention rather than a requirement: the slot holds a NUL-terminated C string read by a byte copy, and ADRP+ADD addresses any byte in the page. The guard gap is never traded away.

### Result

| Plan    | beta 4    | RC         |
| ------- | --------- | ---------- |
| restore | `0xd0e30` | `0x26cfc0` |
| SSHRD   | `0xd0e30` | `0x26cfc0` |
| normal  | `0xd0e30` | `0x26cfba` |

Beta 4 is unchanged on all three — the roomy run still satisfies 16-byte alignment. RC's normal literal lands at 2-byte alignment and ends exactly on the page boundary.

## Decision: beta 4 stays byte-identical; RC keeps its pads

Preserving landing pads initially moved one beta-4 record, and I first decided to regenerate the fixture. That was wrong, and the test that caught it says why:

> This digest was produced independently by the public Python `apply_patches.py kc-boot` table. Matching it proves that the Swift compatibility plan changes the same bytes, not merely 119 bytes.

The beta-4 byte sequence is not merely "what we shipped" — it is an independent cross-implementation check between the Swift resolvers and the public Python patcher. Breaking it to guard against unproven BTI enforcement on a _different_ build is a bad trade.

### The discriminator

`BTI C` **followed by `PACIBSP`** is a landing pad the compiler emitted in front of a prologue. A bare `BTI C` that begins a PAC-less leaf is the function's own first instruction.

```asm
; a pad in front of a prologue      ; a PAC-less leaf whose first
; -- the stub goes after it         ; instruction happens to be BTI C
bti     c                           bti     c
pacibsp                             cbz     x1, <end>
sub     sp, sp, #N                  mov     w0, #0
```

`ARM64.stubStart` only skips the first shape. That single condition gives both properties at once.

### Result

|  | outcome |
| --- | --- |
| beta 4 `24A5390f` | **byte-identical**, all 13 available fixtures verify, Python cross-check intact |
| RC `24A435` — `kernel restore` | 20 records, **0** overwrite a pad |
| RC — `kernel boot-policy` | 4 records, **0** overwrite a pad |
| RC — `kernel sandbox` | 46 records, **0** overwrite a pad |
| RC — `kernel credential-manager` | 52 records, **1** overwrites a pad |

### The one residual case

`performLoggingLevelQueryGated` has the PAC-less-leaf shape on **both** builds (`bti c; cbz x1; mov w0,#0; …`), so on RC its stub is still written at the `BTI`. On RC that method has zero direct branch references and one address-taken reference, so it is reached indirectly — which under enforced BTI would fault.

This is a known, bounded risk rather than an oversight:

- beta 4 patches this exact method the same way and boots.
- BTI enforcement could not be confirmed either way (see [open questions](#open-questions)).
- Making it pad-safe requires either a three-word stub or shifting the record, and both change beta 4.

If RC turns out to enforce BTI, this is the first place to look, and the fix is local to one method.

## Why the workflow profile is reviewed

The 18 fixtures pin all 198 patch records and their output hashes. The profile also pins the stock launchd hash, service-cache hash and daemon count, and the class-owned Setup method count. The remaining gate was physical validation; on 2026-09-13 the iPhone 11 completed erase restore, SSHRD provisioning, normal boot and repeat boot. `finalize --check` then confirmed root SSH, bootstrap shells, persona 99, the icon token and the PosterBoard watcher.

## Tests added

All synthetic, so they run without any firmware present. Each pins a rule rather than a build's offsets.

| Suite | Cases | Covers |
| --- | --: | --- |
| `ARM64BoundaryTests` | 11 | `functionEntry` with and without a pad; `functionStart` returning the call target rather than the prologue; `nextFunctionStart` refusing to report a function's own prologue (the window collapse); `stubStart` skipping a pad only when a `PACIBSP` follows it, and leaving a bare `BTI C` leaf alone |
| `MaskedInstructionPatternDriftTests` | 4 | `ADD (immediate)` drift accepted with `allowDataLayoutDrift`, rejected without it, and rejected for a changed register or a shifted `ADD` |
| `AMFIPostValidationPolarityTests` | 4 | both polarities of the post-validation compare, that the two replacements differ, and that a zero immediate is refused rather than silently emitting a no-op |
| `IBSSBootArgsSlotTests` | 10 | page-boundary-only run detection, dominance over the runner-up run, literal length not affecting run choice, tied runs refused, widest-alignment preference, narrowing only when the run demands it, and the guard gap never being traded away |
| `FirmwareProfileTests` | profile coverage | the RC ACM family is distinct and both device-validated workflows remain reviewed |
| `ReleaseFixtureTests` | 2 | all 18 RC fixtures rediscover their sites and output hashes; RC and beta-4 manifests cover the same patch-id set per resolver |

## Per-patch tables

RC offsets are payload-relative against the decompressed payloads hashed below.

### iBSS / iBEC

The boot-args slot and the ADRP/ADD that point at it differ per plan, so those rows are listed per plan rather than once.

| plan | patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ibss-validate` | `ibss.validate-asn1.branch` | `0x23728` | `0x236e8` | `01070054` | `01070054` | offset only | `1f2003d5` |
| `ibss-validate` | `ibss.validate-asn1.result` | `0x2372c` | `0x236ec` | `e00314aa` | `e00314aa` | offset only | `000080d2` |
| `ibss-restore` | `ibss.validate-asn1.branch` | `0x23728` | `0x236e8` | `01070054` | `01070054` | offset only | `1f2003d5` |
| `ibss-restore` | `ibss.validate-asn1.result` | `0x2372c` | `0x236ec` | `e00314aa` | `e00314aa` | offset only | `000080d2` |
| `ibss-restore` | `ibss.boot-args.adrp` | `0x2aa28` | `0x2aa0c` | `620800f0` | `620800f0` | REPL CHANGED | `021200d0` |
| `ibss-restore` | `ibss.boot-args.add` | `0x2aa2c` | `0x2aa10` | `423c0791` | `423c3091` | ORIG+REPL | `42003f91` |
| `ibss-restore` | `ibss.boot-args.string` | `0xd0e30` | `0x26cfc0` | `000000000000000...` | `000000000000000...` | offset only | `2d76207764743d2...` |
| `ibss-ramdisk` | `ibss.validate-asn1.branch` | `0x23728` | `0x236e8` | `01070054` | `01070054` | offset only | `1f2003d5` |
| `ibss-ramdisk` | `ibss.validate-asn1.result` | `0x2372c` | `0x236ec` | `e00314aa` | `e00314aa` | offset only | `000080d2` |
| `ibss-ramdisk` | `ibss.boot-args.adrp` | `0x2aa28` | `0x2aa0c` | `620800f0` | `620800f0` | REPL CHANGED | `021200d0` |
| `ibss-ramdisk` | `ibss.boot-args.add` | `0x2aa2c` | `0x2aa10` | `423c0791` | `423c3091` | ORIG+REPL | `42003f91` |
| `ibss-ramdisk` | `ibss.boot-args.string` | `0xd0e30` | `0x26cfc0` | `000000000000000...` | `000000000000000...` | offset only | `72643d6d6430202...` |
| `ibss-normal` | `ibss.validate-asn1.branch` | `0x23728` | `0x236e8` | `01070054` | `01070054` | offset only | `1f2003d5` |
| `ibss-normal` | `ibss.validate-asn1.result` | `0x2372c` | `0x236ec` | `e00314aa` | `e00314aa` | offset only | `000080d2` |
| `ibss-normal` | `ibss.boot-args.adrp` | `0x2aa28` | `0x2aa0c` | `620800f0` | `620800f0` | REPL CHANGED | `021200d0` |
| `ibss-normal` | `ibss.boot-args.add` | `0x2aa2c` | `0x2aa10` | `423c0791` | `423c3091` | ORIG+REPL | `42e83e91` |
| `ibss-normal` | `ibss.boot-args.string` | `0xd0e30` | `0x26cfba` | `000000000000000...` | `000000000000000...` | offset only | `2d7620646562756...` |
| `ibss-skip-display-init` | `ibss.display.skip-initialization` | `0x351c8` | `0x35230` | `75850194` | `db850194` | ORIG CHANGED | `20008052` |
| `ibec-ignore-pinot-failure` | `ibec.pinot.zero-panel-id.return-success` | `0x9e504` | `0x9e6d4` | `080c0034` | `080c0034` | offset only | `c80b0034` |

### TXM

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `txm.developer-mode.publish` | `0x2ba58` | `0x2fa88` | `69000036` | `69000036` | offset only | `1f2003d5` |
| `txm.secure-channel.return-one` | `0x2bcd4` | `0x2fd04` | `a90200b0` | `a90200b0` | offset only | `200080d2` |
| `txm.secure-channel.return` | `0x2bcd8` | `0x2fd08` | `29c13691` | `29c13691` | offset only | `c0035fd6` |
| `txm.query-module.0` | `0x39e28` | `0x3df48` | `65faff97` | `65faff97` | offset only | `000080d2` |
| `txm.query-module.1` | `0x39f90` | `0x3e0b0` | `0bfaff97` | `0bfaff97` | offset only | `000080d2` |
| `txm.query-module.2` | `0x3a124` | `0x3e244` | `a6f9ff97` | `a6f9ff97` | offset only | `000080d2` |
| `txm.constraints.restricted-entitlements` | `0x3f624` | `0x43744` | `20fdff54` | `20fdff54` | offset only | `1f2003d5` |
| `txm.constraints.signature-type-range` | `0x3f690` | `0x437b0` | `a3000054` | `a3000054` | offset only | `1f2003d5` |
| `txm.constraints.signature-type-null` | `0x3f698` | `0x437b8` | `690000b4` | `690000b4` | offset only | `1f2003d5` |

### Kernel: identity and panic guards

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `identity.0` | `0x3f2c4` | `0x3f2be` | `2f52454c4541534...` | `2f52454c4541534...` | offset only | `2f5041544348454...` |
| `identity.1` | `0x3f330` | `0x3f324` | `2f52454c4541534...` | `2f52454c4541534...` | offset only | `2f5041544348454...` |
| `panic.seal-broken` | `0x2fc0cec` | `0x2f58ed4` | `60017037` | `60017037` | offset only | `1f2003d5` |
| `panic.root-snapshot` | `0x3052800` | `0x2fec20c` | `28062837` | `28062837` | offset only | `1f2003d5` |
| `panic.unencrypted-data-volume` | `0x3053c10` | `0x2fed640` | `a8000037` | `a8000037` | offset only | `1f2003d5` |
| `panic.rootvp-authentication` | `0x36d5b48` | `0x366924c` | `00130035` | `00130035` | offset only | `1f2003d5` |

### Kernel: AMFI

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `amfi.trust-cache.0` | `0x1f2ffc8` | `0x1efbe84` | `7f2303d5` | `7f2303d5` | offset only | `5f2403d5` |
| `amfi.trust-cache.1` | `0x1f2ffcc` | `0x1efbe88` | `ffc300d1` | `ffc300d1` | offset only | `200080d2` |
| `amfi.trust-cache.2` | `0x1f2ffd0` | `0x1efbe8c` | `f44f01a9` | `f44f01a9` | offset only | `430000b4` |
| `amfi.trust-cache.3` | `0x1f2ffd4` | `0x1efbe90` | `fd7b02a9` | `fd7b02a9` | offset only | `600000f9` |
| `amfi.trust-cache.4` | `0x1f2ffd8` | `0x1efbe94` | `fd830091` | `fd830091` | offset only | `c0035fd6` |
| `amfi.launch-constraints.result` | `0x1f34bf0` | `0x1f00bb8` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `amfi.launch-constraints.return` | `0x1f34bf4` | `0x1f00bbc` | `ff0306d1` | `ff0306d1` | offset only | `c0035fd6` |
| `amfi.post-validation.compare` | `0x1f3c750` | `0x1f08978` | `1f080071` | `1f040071` | ORIG+REPL | `ff070071` |
| `amfi.dyld-policy.0` | `0x1f3ccb0` | `0x1f08ee4` | `70610094` | `c5620094` | ORIG CHANGED | `20008052` |
| `amfi.dyld-policy.1` | `0x1f3ccbc` | `0x1f08ef0` | `2bdfff97` | `8bdeff97` | ORIG CHANGED | `20008052` |
| `amfi.developer-mode.result` | `0x376351c` | `0x36f4cd8` | `68a5feb0` | `28a9fe90` | ORIG CHANGED | `20008052` |
| `amfi.developer-mode.return` | `0x3763520` | `0x36f4cdc` | `083140f9` | `08c545f9` | ORIG CHANGED | `c0035fd6` |

### Kernel: boot policy, USB, debugger

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `usb.restore-mode-result` | `0x28a5bdc` | `0x28053d0` | `7f2303d5` | `7f2303d5` | offset only | `200080d2` |
| `usb.restore-mode-return` | `0x28a5be0` | `0x28053d4` | `ff4301d1` | `ff4301d1` | offset only | `c0035fd6` |
| `persona.uid-zero` | `0x3710dec` | `0x36a21a4` | `e8000034` | `e8000034` | offset only | `1f2003d5` |
| `persona.gid-zero` | `0x3710df4` | `0x36a21ac` | `a8000034` | `a8000034` | offset only | `1f2003d5` |
| `debugger.result` | `0x3a1c748` | `0x39abbfc` | `4892fe90` | `0896fed0` | ORIG CHANGED | `200080d2` |
| `debugger.return` | `0x3a1c74c` | `0x39abc00` | `e00000b4` | `e00000b4` | offset only | `c0035fd6` |

### Kernel: AKS

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `aks.start.sep-call` | `0x212fb30` | `0x20e629c` | `10093fd7` | `10093fd7` | offset only | `1f2003d5` |
| `aks.external-method.selector7.0` | `0x213ac04` | `0x20f13a4` | `ff8306d1` | `ff8306d1` | offset only | `3f1c0071` |
| `aks.external-method.selector7.1` | `0x213ac08` | `0x20f13a8` | `fc6f14a9` | `fc6f14a9` | offset only | `c1010054` |
| `aks.external-method.selector7.2` | `0x213ac0c` | `0x20f13ac` | `fa6715a9` | `fa6715a9` | offset only | `e20100b4` |
| `aks.external-method.selector7.3` | `0x213ac10` | `0x20f13b0` | `f85f16a9` | `f85f16a9` | offset only | `481040f9` |
| `aks.external-method.selector7.4` | `0x213ac14` | `0x20f13b4` | `f65717a9` | `f65717a9` | offset only | `a80100b4` |
| `aks.external-method.selector7.5` | `0x213ac18` | `0x20f13b8` | `f44f18a9` | `f44f18a9` | offset only | `482840b9` |
| `aks.external-method.selector7.6` | `0x213ac1c` | `0x20f13bc` | `fd7b19a9` | `fd7b19a9` | offset only | `1f050071` |
| `aks.external-method.selector7.7` | `0x213ac20` | `0x20f13c0` | `fd430691` | `fd430691` | offset only | `41010054` |
| `aks.external-method.selector7.8` | `0x213ac24` | `0x20f13c4` | `f50302aa` | `f50302aa` | offset only | `492440f9` |
| `aks.external-method.selector7.9` | `0x213ac28` | `0x20f13c8` | `f40301aa` | `f40301aa` | offset only | `090100b4` |
| `aks.external-method.selector7.10` | `0x213ac2c` | `0x20f13cc` | `f60300aa` | `f60300aa` | offset only | `485040b9` |
| `aks.external-method.selector7.11` | `0x213ac30` | `0x20f13d0` | `b70302d1` | `b70302d1` | offset only | `1f050071` |
| `aks.external-method.selector7.12` | `0x213ac34` | `0x20f13d4` | `c86cfff0` | `c86efff0` | ORIG CHANGED | `a1000054` |
| `aks.external-method.selector7.13` | `0x213ac38` | `0x20f13d8` | `08cd46f9` | `087940f9` | ORIG CHANGED | `c80080d2` |
| `aks.external-method.selector7.14` | `0x213ac3c` | `0x20f13dc` | `080140f9` | `080140f9` | offset only | `280100f9` |
| `aks.external-method.selector7.15` | `0x213ac40` | `0x20f13e0` | `a88319f8` | `a88319f8` | offset only | `000080d2` |
| `aks.external-method.selector7.16` | `0x213ac44` | `0x20f13e4` | `b8168052` | `b8168052` | offset only | `ff0f5fd6` |
| `aks.external-method.selector7.17` | `0x213ac48` | `0x20f13e8` | `1845b072` | `1845b072` | offset only | `40588052` |
| `aks.external-method.selector7.18` | `0x213ac4c` | `0x20f13ec` | `ff3f0239` | `ff3f0239` | offset only | `0000bc72` |
| `aks.external-method.selector7.19` | `0x213ac50` | `0x20f13f0` | `d96cfff0` | `d96efff0` | ORIG CHANGED | `ff0f5fd6` |
| `aks.external-method.log-call` | `0x213ae38` | `0x20f15d8` | `66970094` | `01990094` | ORIG CHANGED | `1f2003d5` |

### Kernel: SEP

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `sep.did-timeout.result` | `0x2182208` | `0x2139aa4` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sep.did-timeout.return` | `0x218220c` | `0x2139aa8` | `ffc300d1` | `ffc300d1` | offset only | `c0035fd6` |
| `sep.power-notification.result` | `0x2182b8c` | `0x213a43c` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sep.power-notification.return` | `0x2182b90` | `0x213a440` | `ff4305d1` | `ff4305d1` | offset only | `c0035fd6` |
| `sep.notify-active` | `0x2185858` | `0x213d194` | `200d00b4` | `200d00b4` | offset only | `1f2003d5` |
| `sep.panic-check.result` | `0x2185a00` | `0x213d340` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sep.panic-check.return` | `0x2185a04` | `0x213d344` | `f44fbea9` | `f44fbea9` | offset only | `c0035fd6` |
| `sep.set-power-a` | `0x2186894` | `0x213e1fc` | `801200b4` | `801200b4` | offset only | `1f2003d5` |
| `sep.set-power-b` | `0x21868c4` | `0x213e22c` | `201100b4` | `201100b4` | offset only | `1f2003d5` |
| `sep.prng-reseed` | `0x2186e4c` | `0x213e7c4` | `80010054` | `80010054` | offset only | `1f2003d5` |

### Kernel: sandbox

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `sandbox.vnode-check-exec.target` | `0x10fafb8` | `0x10cf850` | `385ef902` | `f0d9f202` | ORIG+REPL | `f819f202` |
| `sandbox.vnode-check-open.target` | `0x10fb000` | `0x10cf898` | `38acf702` | `2423f102` | ORIG+REPL | `80d49f03` |
| `sandbox.vnode-check-open.metadata` | `0x10fb004` | `0x10cf89c` | `86153080` | `86153080` | offset only | `86153080` |
| `sandbox.vnode-check-rename.result` | `0x2f82c58` | `0x2f1a480` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sandbox.vnode-check-rename.return` | `0x2f82c5c` | `0x2f1a484` | `e923ba6d` | `e923ba6d` | offset only | `c0035fd6` |
| `sandbox.mount-check-unmount.result` | `0x2f87bdc` | `0x2f1f45c` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sandbox.mount-check-unmount.return` | `0x2f87be0` | `0x2f1f460` | `fc6fbca9` | `fc6fbca9` | offset only | `c0035fd6` |
| `sandbox.mount-check-remount.result` | `0x2f87f40` | `0x2f1f7c8` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sandbox.mount-check-remount.return` | `0x2f87f44` | `0x2f1f7cc` | `f85fbca9` | `f85fbca9` | offset only | `c0035fd6` |
| `sandbox.mount-check-mount.result` | `0x2f8810c` | `0x2f1f998` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sandbox.mount-check-mount.return` | `0x2f88110` | `0x2f1f99c` | `fc6fbda9` | `fc6fbda9` | offset only | `c0035fd6` |
| `sandbox.file-check-mmap.result` | `0x2f89fd8` | `0x2f219fc` | `7f2303d5` | `7f2303d5` | offset only | `000080d2` |
| `sandbox.file-check-mmap.return` | `0x2f89fdc` | `0x2f21a00` | `fc6fbda9` | `fc6fbda9` | offset only | `c0035fd6` |
| `sandbox.vnode-check-open.shim.0` | `0x3a6d480` | `0x39fd480` | `00000000` | `00000000` | offset only | `7f2303d5` |
| `sandbox.vnode-check-open.shim.1` | `0x3a6d484` | `0x39fd484` | `00000000` | `00000000` | offset only | `fd7bbda9` |
| `sandbox.vnode-check-open.shim.2` | `0x3a6d488` | `0x39fd488` | `00000000` | `00000000` | offset only | `fd030091` |
| `sandbox.vnode-check-open.shim.3` | `0x3a6d48c` | `0x39fd48c` | `00000000` | `00000000` | offset only | `e00701a9` |
| `sandbox.vnode-check-open.shim.4` | `0x3a6d490` | `0x39fd490` | `00000000` | `00000000` | offset only | `e20f02a9` |
| `sandbox.vnode-check-open.shim.5` | `0x3a6d494` | `0x39fd494` | `00000000` | `00000000` | REPL CHANGED | `1ee1e097` |
| `sandbox.vnode-check-open.shim.6` | `0x3a6d498` | `0x39fd498` | `00000000` | `00000000` | offset only | `000c40f9` |
| `sandbox.vnode-check-open.shim.7` | `0x3a6d49c` | `0x39fd49c` | `00000000` | `00000000` | offset only | `400200b4` |
| `sandbox.vnode-check-open.shim.8` | `0x3a6d4a0` | `0x39fd4a0` | `00000000` | `00000000` | REPL CHANGED | `34eaf297` |
| `sandbox.vnode-check-open.shim.9` | `0x3a6d4a4` | `0x39fd4a4` | `00000000` | `00000000` | offset only | `080040f9` |
| `sandbox.vnode-check-open.shim.10` | `0x3a6d4a8` | `0x39fd4a8` | `00000000` | `00000000` | offset only | `49aa8cd2` |
| `sandbox.vnode-check-open.shim.11` | `0x3a6d4ac` | `0x39fd4ac` | `00000000` | `00000000` | offset only | `69eeadf2` |
| `sandbox.vnode-check-open.shim.12` | `0x3a6d4b0` | `0x39fd4b0` | `00000000` | `00000000` | offset only | `89cdcef2` |
| `sandbox.vnode-check-open.shim.13` | `0x3a6d4b4` | `0x39fd4b4` | `00000000` | `00000000` | offset only | `a94ceef2` |
| `sandbox.vnode-check-open.shim.14` | `0x3a6d4b8` | `0x39fd4b8` | `00000000` | `00000000` | offset only | `1f0109eb` |
| `sandbox.vnode-check-open.shim.15` | `0x3a6d4bc` | `0x39fd4bc` | `00000000` | `00000000` | offset only | `40010054` |
| `sandbox.vnode-check-open.shim.16` | `0x3a6d4c0` | `0x39fd4c0` | `00000000` | `00000000` | offset only | `c92c8dd2` |
| `sandbox.vnode-check-open.shim.17` | `0x3a6d4c4` | `0x39fd4c4` | `00000000` | `00000000` | offset only | `89adacf2` |
| `sandbox.vnode-check-open.shim.18` | `0x3a6d4c8` | `0x39fd4c8` | `00000000` | `00000000` | offset only | `094ecef2` |
| `sandbox.vnode-check-open.shim.19` | `0x3a6d4cc` | `0x39fd4cc` | `00000000` | `00000000` | offset only | `e9cdeef2` |
| `sandbox.vnode-check-open.shim.20` | `0x3a6d4d0` | `0x39fd4d0` | `00000000` | `00000000` | offset only | `1f0109eb` |
| `sandbox.vnode-check-open.shim.21` | `0x3a6d4d4` | `0x39fd4d4` | `00000000` | `00000000` | offset only | `80000054` |
| `sandbox.vnode-check-open.shim.22` | `0x3a6d4d8` | `0x39fd4d8` | `00000000` | `00000000` | offset only | `00008052` |
| `sandbox.vnode-check-open.shim.23` | `0x3a6d4dc` | `0x39fd4dc` | `00000000` | `00000000` | offset only | `fd7bc3a8` |
| `sandbox.vnode-check-open.shim.24` | `0x3a6d4e0` | `0x39fd4e0` | `00000000` | `00000000` | offset only | `ff0f5fd6` |
| `sandbox.vnode-check-open.shim.25` | `0x3a6d4e4` | `0x39fd4e4` | `00000000` | `00000000` | offset only | `e00741a9` |
| `sandbox.vnode-check-open.shim.26` | `0x3a6d4e8` | `0x39fd4e8` | `00000000` | `00000000` | offset only | `e20f42a9` |
| `sandbox.vnode-check-open.shim.27` | `0x3a6d4ec` | `0x39fd4ec` | `00000000` | `00000000` | offset only | `fd7bc3a8` |
| `sandbox.vnode-check-open.shim.28` | `0x3a6d4f0` | `0x39fd4f0` | `00000000` | `00000000` | offset only | `ff2303d5` |
| `sandbox.vnode-check-open.shim.29` | `0x3a6d4f4` | `0x39fd4f4` | `00000000` | `00000000` | offset only | `d0071eca` |
| `sandbox.vnode-check-open.shim.30` | `0x3a6d4f8` | `0x39fd4f8` | `00000000` | `00000000` | offset only | `5000f0b6` |
| `sandbox.vnode-check-open.shim.31` | `0x3a6d4fc` | `0x39fd4fc` | `00000000` | `00000000` | offset only | `208e38d4` |
| `sandbox.vnode-check-open.shim.32` | `0x3a6d500` | `0x39fd500` | `00000000` | `00000000` | REPL CHANGED | `8953d417` |

### Kernel: AppleCredentialManager

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `acm.sepmanagermatchedthreadcallhandler.result` | `0x2109b98` | `0x20bfd50` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.sepmanagermatchedthreadcallhandler.return` | `0x2109b9c` | `0x20bfd54` | `ff0301d1` | `ff0301d1` | offset only | `c0035fd6` |
| `acm.callplatformfunction.result` | `0x210a260` | `0x20c0434` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.callplatformfunction.return` | `0x210a264` | `0x20c0438` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.cmdcontextv2.result` | `0x210a2e4` | `0x20c04bc` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.cmdcontextv2.return` | `0x210a2e8` | `0x20c04c0` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.cmdcontextv3.result` | `0x210a36c` | `0x20c0548` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.cmdcontextv3.return` | `0x210a370` | `0x20c054c` | `ff4302d1` | `ff4302d1` | offset only | `c0035fd6` |
| `acm.performcommandgated.result` | `0x210a640` | `0x20c0824` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.performcommandgated.return` | `0x210a644` | `0x20c0828` | `ff4305d1` | `ff4305d1` | offset only | `c0035fd6` |
| `acm.performkernelcontrol.result` | `0x210b1c4` | `0x20c1314` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.performkernelcontrol.return` | `0x210b1c8` | `0x20c1318` | `ff4302d1` | `ff4302d1` | offset only | `c0035fd6` |
| `acm.performcommand.result` | `0x210b580` | `0x20c16d4` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.performcommand.return` | `0x210b584` | `0x20c16d8` | `ffc302d1` | `ffc302d1` | offset only | `c0035fd6` |
| `acm.processscrdresponsepayload.result` | `0x210b7a8` | `0x20c1900` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.processscrdresponsepayload.return` | `0x210b7ac` | `0x20c1904` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.scheduledblclickdeferredack.result` | `0x210b9d4` | `0x20c1b30` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.scheduledblclickdeferredack.return` | `0x210b9d8` | `0x20c1b34` | `ff4301d1` | `ff4301d1` | offset only | `c0035fd6` |
| `acm.updateanalytics.result` | `0x210baf4` | `0x20c1c54` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.updateanalytics.return` | `0x210baf8` | `0x20c1c58` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.performscrdinitialization.result` | `0x210bc58` | `0x20c1dbc` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.performscrdinitialization.return` | `0x210bc5c` | `0x20c1dc0` | `ff0302d1` | `ff0302d1` | offset only | `c0035fd6` |
| `acm.sendsepcommand.result` | `0x210bf1c` | `0x20c2084` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.sendsepcommand.return` | `0x210bf20` | `0x20c2088` | `ff4304d1` | `ff4304d1` | offset only | `c0035fd6` |
| `acm.setpropertiesgated.result` | `0x210c994` | `0x20c2b00` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.setpropertiesgated.return` | `0x210c998` | `0x20c2b04` | `ff0302d1` | `ff0302d1` | offset only | `c0035fd6` |
| `acm.performdoubleclickquerygated.result` | `0x210ce1c` | `0x20c2f8c` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.performdoubleclickquerygated.return` | `0x210ce20` | `0x20c2f90` | `ff4301d1` | `ff4301d1` | offset only | `c0035fd6` |
| `acm.performlogginglevelquerygated.result` | `0x210cf10` | `0x20c3080` | `c10000b4` | `c10000b4` | offset only | `00008052` |
| `acm.performlogginglevelquerygated.return` | `0x210cf14` | `0x20c3084` | `00008052` | `00008052` | offset only | `c0035fd6` |
| `acm.lockitem.result` | `0x210d33c` | `0x20c34b8` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.lockitem.return` | `0x210d340` | `0x20c34bc` | `ffc301d1` | `ffc301d1` | offset only | `c0035fd6` |
| `acm.unlockitem.result` | `0x210d568` | `0x20c36e8` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.unlockitem.return` | `0x210d56c` | `0x20c36ec` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.handlesepmessage.result` | `0x210da1c` | `0x20c3bac` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.handlesepmessage.return` | `0x210da20` | `0x20c3bb0` | `ff0302d1` | `ff0302d1` | offset only | `c0035fd6` |
| `acm.readfromsepbuffer.result` | `0x210dd04` | `0x20c3e98` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.readfromsepbuffer.return` | `0x210dd08` | `0x20c3e9c` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.writetosepbuffer.result` | `0x210de64` | `0x20c3ffc` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.writetosepbuffer.return` | `0x210de68` | `0x20c4000` | `ff4302d1` | `ff4302d1` | offset only | `c0035fd6` |
| `acm.sendsepmessage.result` | `0x210e20c` | `0x20c43a8` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.sendsepmessage.return` | `0x210e210` | `0x20c43ac` | `ff4302d1` | `ff4302d1` | offset only | `c0035fd6` |
| `acm.clearsepbuffer.result` | `0x210e444` | `0x20c45e4` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.clearsepbuffer.return` | `0x210e448` | `0x20c45e8` | `ff8301d1` | `ff8301d1` | offset only | `c0035fd6` |
| `acm.getsependpoint.result` | `0x210e5e0` | `0x20c4784` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.getsependpoint.return` | `0x210e5e4` | `0x20c4788` | `ff4302d1` | `ff4302d1` | offset only | `c0035fd6` |
| `acm.poweroffactiongated.result` | `0x210f220` | `0x20c53d0` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.poweroffactiongated.return` | `0x210f224` | `0x20c53d4` | `ff0302d1` | `ff0302d1` | offset only | `c0035fd6` |
| `acm.sepmanagermatchedgated.result` | `0x210f4d4` | `0x20c5688` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.sepmanagermatchedgated.return` | `0x210f4d8` | `0x20c568c` | `ff0302d1` | `ff0302d1` | offset only | `c0035fd6` |
| `acm.setpowerstategated.result` | `0x211b7fc` | `0x20d1b2c` | `7f2303d5` | `7f2303d5` | offset only | `00008052` |
| `acm.setpowerstategated.return` | `0x211b800` | `0x20d1b30` | `ffc301d1` | `ffc301d1` | offset only | `c0035fd6` |

### Userland

Extracted from the RC restore ramdisk (`043-69915-775.dmg`, IM4P `rdsk`) and the decrypted root filesystem (`043-70213-656.dmg.aea`).

| patch id | beta-4 offset | RC offset | beta-4 original | RC original | opcode | RC replacement |
| --- | --- | --- | --- | --- | --- | --- |
| `restored-external.fdr-result` | `0x7e558` | `0x7e848` | `e0031aaa` | `e0031aaa` | offset only | `000080d2` |
| `asr.signature-mismatch-branch` | `0x1f654` | `0x1f670` | `20310035` | `20310035` | offset only | `1f2003d5` |
| `coreauthd.dto-ratchet.start-controller` | `0x95c0` | `0x95c0` | `08d10094` | `18d10094` | ORIG CHANGED | `1f2003d5` |
| `ctkd.sep-key-server.return-nil` | `0x1b38` | `0x1b38` | `7f2303d5` | `7f2303d5` | identical | `000080d2` |
| `ctkd.sep-key-server.return` | `0x1b3c` | `0x1b3c` | `ff0303d1` | `ff0303d1` | identical | `c0035fd6` |
| `mobileactivationd.should-hactivate` | `0x2ec2d8` | `0x2ec368` | `00504039` | `00504039` | offset only | `20008052` |
| `mobileactivationd.activation-state.migration-gate` | `0x329b60` | `0x329be8` | `76050036` | `76050036` | offset only | `1f2003d5` |
| `mobileactivationd.activation-state.adrp` | `0x329bc0` | `0x329c48` | `08050090` | `28050090` | ORIG CHANGED | `200600d0` |
| `mobileactivationd.activation-state.add` | `0x329bc4` | `0x329c4c` | `08410c91` | `08410c91` | offset only | `00e01b91` |
| `mobileactivationd.activation-state.dereference` | `0x329bc8` | `0x329c50` | `000140f9` | `000140f9` | offset only | `1f2003d5` |

Note `coreauthd.dto-ratchet.start-controller` sits at the **same offset** on both builds with a **different** `BL` displacement, and both `ctkd` records are identical in offset and bytes. Neither is a reason to transplant: the guarded applier checks the pre-image, and a resolver that happened to be right here would still be wrong on the next build.

---

## RC fixtures

All 18 exact-build oracles live in `fixtures/24A435/n104ap/`. Each binds the clean input SHA-256, every resolved offset with its original and replacement bytes, and the SHA-256 of the complete patched output.

They are generated by `liter8 fixture`, which runs the same resolver and the same `GuardedPatchApplier` the CLI uses everywhere else, then reloads the manifest and verifies it against the input before reporting success. Nothing in a fixture is hand-transcribed.

```sh
liter8 fixture kernel restore <kernelcache> fixtures/24A435/n104ap/kernel-restore-n104-24A435.json \
    --device "iPhone 11" --board n104ap --build 24A435 \
    --component-name kernelcache.release.iphone12b
```

| resolver | component | size | records | input SHA-256 | output SHA-256 |
| --- | --- | --: | --: | --- | --- |
| `asr-signature` | `asr` | 380192 | 1 | `e08524a9bc61c3f5…` | `422869780fb1da89…` |
| `coreauthd` | `coreauthd` | 467744 | 1 | `b12b67d59787d723…` | `a094e0e35a988f7e…` |
| `ctkd` | `ctkd` | 321616 | 2 | `2f5861e1deaac8c4…` | `b63d9a5dfe792689…` |
| `ibec-diag-ignore-pinot-id-failure` | `iBEC diagnostic` | 2563464 | 1 | `0a595a23eb3f7e2b…` | `30522daf258c4b40…` |
| `ibss-normal` | `iBSS` | 2563464 | 5 | `0a595a23eb3f7e2b…` | `ce9d5f729bbf2888…` |
| `ibss-ramdisk` | `iBSS` | 2563464 | 5 | `0a595a23eb3f7e2b…` | `9f2c553fc0442ece…` |
| `ibss-restore` | `iBSS` | 2563464 | 5 | `0a595a23eb3f7e2b…` | `337b8b490cbcb02b…` |
| `ibss-skip-display-init` | `iBSS only` | 2563464 | 1 | `0a595a23eb3f7e2b…` | `28c39feae57a0d39…` |
| `ibss-validate-asn1` | `iBSS` | 2563464 | 2 | `0a595a23eb3f7e2b…` | `813064f30f02034d…` |
| `kernel-boot-policy` | `kernelcache.release.iphone12b` | 67534848 | 4 | `fdaf5ccc03bd6e24…` | `dee766a78f6075d0…` |
| `kernel-credential-manager` | `kernelcache.release.iphone12b` | 67534848 | 52 | `fdaf5ccc03bd6e24…` | `ab2b49d18fa6ae28…` |
| `kernel-restore` | `kernelcache.release.iphone12b` | 67534848 | 20 | `fdaf5ccc03bd6e24…` | `dcec52ccdfb4a344…` |
| `kernel-sandbox` | `kernelcache.release.iphone12b` | 67534848 | 46 | `fdaf5ccc03bd6e24…` | `0665f02b7382e059…` |
| `kernel-sep` | `kernelcache.release.iphone12b` | 67534848 | 32 | `fdaf5ccc03bd6e24…` | `7d7d8f077709a237…` |
| `mobileactivationd` | `mobileactivationd` | 4658208 | 5 | `89233513ce696cd0…` | `1ced1ddfee7613d0…` |
| `restored-external-fdr` | `restored_external` | 3356976 | 1 | `09527d92d9381d7a…` | `ed74233454f9acdf…` |
| `txm-boot` | `TXM` | 557088 | 9 | `e058931840ac000f…` | `4102141819c6100e…` |
| `txm-restore` | `TXM` | 557088 | 6 | `e058931840ac000f…` | `ba74d36e434a8fc8…` |

**198 records total.** Truncated hashes above are for reading; the manifests carry them in full.

`ReleaseFixtureTests` verifies every one and additionally checks that the RC and beta-4 manifests describe the same patch-id set per resolver, that each RC manifest pins an output hash, and that no RC manifest accidentally points at a beta-4 binary. It sits in the slow tier with `KernelFixtureTests`:

```sh
LITER8_FIXTURE_ROOT=/path/to/private/research make test-fixtures
```

Apple binaries stay out of the repository. The suite reads them from `<fixture root>/offsets/24A435/` and skips cleanly when they are absent.

---

## Clean RC inputs

### IM4P / container SHA-256

| Component | Size | SHA-256 |
| --- | --: | --- |
| `Firmware/dfu/iBSS.n104.RELEASE.im4p` | 1645578 | `79f7f0f0343412390849ca0fb88a9ce461cc15c4e28a70d5dcc1913612a609cd` |
| `Firmware/dfu/iBEC.n104.RELEASE.im4p` | 1645578 | `4453c5a886e851fd8c5878a915addfce9f6654490784d4540d0dfd5c37c78923` |
| `Firmware/all_flash/DeviceTree.n104ap.im4p` | 45332 | `2e3011750e72532e61263d6d19ab4bb5ba17f07198fc7a0245ecb7af5ac7d7ab` |
| `Firmware/txm.iphoneos.release.im4p` | 223884 | `b81fb0c2db25d77055639bfdf8d1dc4610f31cde914f77d873e757c7405c65ff` |
| `kernelcache.release.iphone12b` | 21800371 | `97c8924fdba3c3911ec6c5b6e5d64f8b5d2f54d88345951419ad1c726d783e42` |
| `043-69915-775.dmg` | 243269659 | `03768f01e4093f3f31a7aaca96f3abeebd744d2ffff980158d15e9a028b59a86` |
| `BuildManifest.plist` | 637306 | `6bf6412d06e5770b77b08d8d79a955a9171907e6003ff07c6858c6679c436f1a` |

### Decompressed payload SHA-256 — the offset reference frame

| Payload | Size | RC SHA-256 | beta-4 SHA-256 |
| --- | --: | --- | --- |
| `iBSS.n104.RELEASE.bin` | 2563464 | `0a595a23eb3f7e2b2145d5ea4e9df419635b6cf527b11c3d24a480c6a8285bf8` | `6cf70de60debc66dbd13b135935359254965a4e1d4eabb996ce59265f552ebf5` |
| `iBEC.n104.RELEASE.bin` | 2563464 | `0a595a23eb3f7e2b2145d5ea4e9df419635b6cf527b11c3d24a480c6a8285bf8` |  |
| `DeviceTree.n104ap.bin` | 234956 | `de5be64d10f643fb3a8d30a63157e538452d339256ec69c189f063a3228e520f` | `700db86697e80986f4bcf93022f436d4ac8d1db3e1b7b518ace56d5e52add7a0` |
| `txm.iphoneos.release.bin` | 557088 | `e058931840ac000f6d050578fd7fc4ddb8c640125d92a713f61433be793fbf04` | `75a6b02c1a2d0f43bfe85942b5c205e2e9afe692231de0d361dbc85d4fc63cf9` |
| `kernelcache.release.iphone12b.bin` | 67534848 | `fdaf5ccc03bd6e2415c00d0fd91ee1e81a72ac89e974c692ea53dce01761be3e` | `023cd1efa2e9bbb04e73dde6fa19c6f85eb58954848debff2931f92178347163` |

**iBSS and iBEC are byte-identical on RC**, as on beta 4. Verified by matching SHA-256 and by `cmp` finding no differing byte. The container hashes differ only because the IM4P wrappers carry different four-character types.

### Fingerprints

| Artifact | Value |
| --- | --- |
| XNU | `xnu-13432.2.10~2/RELEASE_ARM64_T8030`, built Thu Aug 13 21:55:30 PDT 2026 |
| Kernelcache UUID | `62AAADC9-CAB8-B6B2-A51B-AA53186A8BC1` |
| TXM | `TrustedExecutionMonitor_Guarded-217.0.2`, `AppleImage4_txm-374~7022` |
| TXM UUID | `9F80F5EC-09C8-3E9F-A196-13A6250C04E0` |
| iBoot banner | `iBoot for n104 Copyright 2007-2026, Apple Inc.` |

`liter8 profile` on the RC kernelcache selects `ios27-24A435-n104ap` unaided, and the embedded XNU fingerprint matches the value already in the profile.

### Kernelcache segment map

| Segment            | Virtual address      | File range             | Exec |
| ------------------ | -------------------- | ---------------------- | ---- |
| `__TEXT`           | `0xfffffff007004000` | `0x0..0x8000`          |      |
| `__PRELINK_TEXT`   | `0xfffffff00700c000` | `0x8000..0xbbc000`     |      |
| `__DATA_CONST`     | `0xfffffff007bc0000` | `0xbbc000..0x10f8000`  |      |
| `__DATA_SPTM`      | `0xfffffff0080fc000` | `0x10f8000..0x1144000` |      |
| `__TEXT_EXEC`      | `0xfffffff008148000` | `0x1144000..0x3a04000` | X    |
| `__TEXT_BOOT_EXEC` | `0xfffffff00aa08000` | `0x3a04000..0x3a0c000` | X    |
| `__PRELINK_INFO`   | `0xfffffff00aa10000` | `0x3a0c000..0x3c34000` |      |
| `__DATA`           | `0xfffffff00ac38000` | `0x3c34000..0x3fb0000` |      |
| `__LINKEDIT`       | `0xfffffff00afb4000` | `0x3fb0000..0x4068000` |      |

Derived three ways that agree: `otool -l`, `liter8 inspect segments`, and IDA. The kernelcache is stripped — `nm` reports 728 symbols, none of them targets — so every kernel patch is recovered by code shape.

## DeviceTree

No offsets required. All five worksheet changes apply with the existing resolvers.

| Plan | Change | Result |
| --- | --- | --- |
| restore | remove `/defaults/content-protect` | removed, `234956 -> 234920` (`-36`) |
| normal | remove `/defaults/content-protect` | removed |
| normal | set `/defaults/no-effaceable-storage` | added |
| normal | set `/product/boot-ios-diagnostics` | added |
| normal | update `/chosen/ephemeral-storage` | updated, `234956 -> 235000` (`+44`) |

## Repository changes on this branch

| File | Change |
| --- | --- |
| `Binary/ARM64.swift` | `pacibsp`/`btiC` constants; `functionEntry`, `functionStart`, `nextFunctionStart`, `stubStart` |
| `Binary/MaskedInstructionPattern.swift` | `allowDataLayoutDrift` now also relaxes `ADD (immediate)` |
| `Binary/BinaryInspector.swift` | new; read-only diagnostics over the same primitives the resolvers use |
| `Liter8CLI/main.swift` | new `liter8 inspect` subcommand and its argument helpers |
| `Resolvers/iBoot/IBSSBootArgsResolver.swift` | slot chosen by dominant page-tail run; alignment ladder for placement |
| `Resolvers/Kernel/KernelAMFIResolver.swift` | shared boundary helpers; polarity-aware post-validation replacement; pad-safe launch-constraint stub |
| `Resolvers/Kernel/KernelBootPolicyResolver.swift` | entry-aware predecessor check; pad-safe restore-mode stub |
| `Resolvers/Kernel/KernelSandboxResolver.swift` | pad-safe `mpc_ops` stubs |
| `Resolvers/Kernel/KernelCredentialManagerResolver.swift` | pad-safe ACM stubs |
| `Profiles/KernelCredentialManagerSignatures.swift` | new `release24A435V1` family, all 26 methods |
| `Profiles/FirmwareProfile.swift` | `pendingResearch` gate lifted for `ios27-24A435-acm-v1` |
| `Firmware/IPSWManifest.swift` | exact `24A435` workflow profile and pre-boot guards; initially experimental, promoted to reviewed after device validation |
| `Tests/.../ARM64BoundaryTests.swift` | new, 19 cases across three suites |
| `Tests/.../IBSSBootArgsSlotTests.swift` | new, 10 cases |
| `Tests/.../FirmwareProfileTests.swift` | RC ACM family and workflow-gate assertions |
| `Tests/.../ReleaseFixtureTests.swift` | new; verifies all 18 RC fixtures and their parity with beta 4 |
| `Patching/FixtureManifest.swift` | public initializers and a `digest(of:)` helper so fixtures can be generated |
| `Makefile` | `ReleaseFixtureTests` joins the slow tier and `test-fixtures` |
| `fixtures/24A435/n104ap/` | new; 18 manifests, 198 records |

`liter8 inspect` cannot write to a binary:

```text
liter8 inspect <binary> segments
liter8 inspect <binary> strings <text>
liter8 inspect <binary> <xrefs|func|calls> <offset>
liter8 inspect <binary> dis <offset> [words]
liter8 inspect <binary> pattern <word[/mask]> ...
liter8 inspect <binary> pattern-at <offset> <word[/mask]> ...
```

## Device-validation result

The reviewed workflow gate is complete. The physical n104ap run verified:

1. CFW construction and guarded post-patch records for all six restore artifacts.
2. Erase restore with a managed TSS proxy and captured restore-bound APTicket.
3. SSHRD construction, boot, bootstrap installation and rootfs provisioning.
4. Setup.app, userland crash fixes, ScreenTime overrides, launchd injection, service cache, Dropbear, Sileo and per-boot tools through the on-device check.
5. Normal boot and repeat normal boot, followed by a successful `finalize --check`.

The first normal boot exposed one RC-specific wallpaper failure. `pfwatch` started before its old `~/Library/SpringBoard` log directory existed, and `pfruntimeprobe` derived its dyld slide from a beta-4 PosterFoundation address. The durable fix uses early-boot-safe log and lock paths and decodes the live ARM64 `ADRP`/`LDR` pairs to locate the adjacent dispatch-once and object slots. It fails closed until the globals initialize. A forced PosterBoard restart proved that the watcher detects the new PID, waits for initialization, repairs the dictionary and passes readback; the following normal boot retained the wallpaper.

### Exact-build inputs retained by the reviewed profile

| Item | Value |
| --- | --- |
| stock RC `/sbin/launchd` SHA-256 | `c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b` |
| stock RC `/sbin/launchd` Mach-O UUID | `CA54230D-4005-3131-8DC3-CCB7E7EF18E6` |
| stock RC `/sbin/launchd` size | 639376 |
| decrypted root filesystem SHA-256 | `df3be3fc3e3135adf88bcd539f32b1ce35c9e1fa44acd671289d68c3074bbf28` |
| decrypted root filesystem size | 9082765312 |
| restore ramdisk payload SHA-256 | `8773fe2450d8ef69f2ed9255c94f722f0c01ef4373befef173e0495647ba5637` |
| APFS volume label | `Rave24A435.N104OS` |

These values remain guards, not substitute offsets. Component offsets continue to come from the semantic resolvers and are checked against the RC fixtures.

## Open questions

1. **Is BTI enforced?** Not answerable from the kernelcache; `SCTLR_EL1` is programmed by SPTM, which is a separate binary. Pads are preserved everywhere regardless, which costs nothing.
2. **`setPowerStateGated` confidence.** It matched 19/32 words and was placed by neighbour-bounded scoring rather than a unique exact match. It is the least certain of the 26 ACM methods.
3. **AKS selector-7 ABI.** The RC `externalMethod` dispatch and its calling convention have not been re-checked against the transplanted payload; the support plan asks for that explicitly.

---

## Pre-boot work: Setup.app, launchd, service cache, APTicket

These inputs now have exact-build guards and local dry-run verification. The remaining evidence must come from the physical-device workflow.

### Setup.app: class ownership recovers the beta-4 set

The broad `__objc_methlist` scan produced 81 beta-4 and 82 RC candidates. Even a structurally correct global method-list walk still produced 79 beta-4 candidates. Those counts are not the patch rule because the section contains valid method lists that are not installed as base methods of a class in this image.

`device/patch_setup.py` now begins at `__objc_classlist` and follows the runtime ownership chain:

- each classlist pointer and `class_ro_t` must resolve through chained fixups;
- `baseMethods` must reference a valid relative `method_list_t` with `entsize == 12` and bounds wholly inside `__objc_methlist`;
- The `name` field of a relative entry is a delta to a **selector-reference slot**, not to the string. The binary uses chained fixups, so that slot is decoded before resolving into `__TEXT,__objc_methname`;
- the type must be `B16@0:8`, and the IMP must land inside `__TEXT,__text`.

Every classlist entry resolves on both binaries: 449 of 449 on beta 4 and 452 of 452 on RC.

| selection rule                         | beta 4 |     RC |
| -------------------------------------- | -----: | -----: |
| broad method-list candidates           |     81 |     82 |
| **class-owned `controllerNeedsToRun`** | **65** | **66** |

The class-owned beta-4 result exactly reproduces the 65 methods already proven on the device, without consulting offsets. RC preserves those 65 owning classes and adds one: `BuddyServicesTermsFlow`. The workflow therefore patches 66 on RC and refuses to write if the selected profile's expected count differs.

The patcher can also emit a JSON record containing each class, IMP, file offset, original bytes and replacement. This leaves a reviewable pre-image trail for a behavioural patch that must never silently broaden.

### launchd: `/usr/lib/lhook.dylib` is the only option that fits

|  | value |
| --- | --- |
| RC `/sbin/launchd` | 639376 bytes |
| SHA-256 | `c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b` |
| Mach-O UUID | `CA54230D-4005-3131-8DC3-CCB7E7EF18E6` |
| load commands | 27, `sizeofcmds` 4408 |
| header + commands end | `0x1158` |
| first section file offset | `0x1188` |
| **free header slack** | **48 bytes** |
| `LC_RPATH` | **absent** |

A `LC_LOAD_WEAK_DYLIB` is 24 bytes fixed plus path and NUL, padded to 8, so the path budget is 24 bytes — 23 characters.

| path | size | verdict |
| --- | --: | --- |
| `/usr/lib/systemhook.dylib` | 56 | too long |
| `@loader_path/lhook.dylib` | 56 | too long |
| `@rpath/lhook.dylib` | 48 | **ruled out: no `LC_RPATH` in this binary** |
| **`/usr/lib/lhook.dylib`** | **48** | **fits exactly** |

Both paths the support plan names are too long. `@rpath` was checked and rejected rather than assumed: `otool -l` reports no `LC_RPATH` load command, so an `@rpath` install name would not resolve. `/usr/lib/lhook.dylib` consumes the slack exactly, leaving none.

The same patch/re-sign/byte-diff verifier was run against pristine beta-4 and RC launchd binaries. Both produced valid code slots and only the intended header, load-command and CodeDirectory changes. RC consumes all 48 bytes of header slack, so the install name must remain `/usr/lib/lhook.dylib`.

### Service cache

`/System/Library/xpc/launchd.plist`, binary plist, 2474924 bytes, SHA-256 `752739f8224b016b5cee1b37a985995ffcfc1d6f12569fd2191ba5b4a9119c6a`.

| key                      |                       entries |
| ------------------------ | ----------------------------: |
| `SystemLibraryTreeState` |                          3478 |
| `AppExtensions`          |                           782 |
| `LaunchDaemons`          | **729** (724 distinct labels) |
| `AppRemovalServices`     |                            16 |
| `Symlinks`               |                             1 |
| `VersionNumber`          |                             7 |

Jobs are keyed by source plist path; each value carries `Label`, `Program`, `MachServices` and friends. `com.dropbear` and `com.jbboot` are absent, as expected — they are what the rebuild inserts.

There is a **signature sidecar**, `launchd.plist.sig`, 19661 bytes. Provisioning requires it to be present and deliberately leaves it untouched, matching the beta-4 path under `launchd_unsecure_cache=1`.

**Finding on the ScreenTime overrides.** Four of the five labels the support plan lists are present as LaunchDaemons:

| label | source |
| --- | --- |
| `com.apple.ScreenTimeAgent` | `/System/Library/LaunchDaemons/com.apple.ScreenTimeAgent.plist` |
| `com.apple.ScreenTimeSettingsAgent` | `/System/Library/LaunchDaemons/com.apple.ScreenTimeSettingsAgent.plist` |
| `com.apple.FamilyControlsAgent` | `/System/Library/LaunchDaemons/com.apple.FamilyControlsAgent.plist` |
| `com.apple.familycircled` | `/System/Library/LaunchDaemons/com.apple.familycircled.plist` |
| `com.apple.familynotificationd` | **not in this cache** |

This cache holds no `LaunchAgents` key, so `com.apple.familynotificationd` is either a per-user agent cached elsewhere or absent from RC entirely. The plan's acceptance check asks that all five labels be exactly `true` in `/private/var/db/com.apple.xpc.launchd/disabled.plist`; writing an override for a label that does not exist is harmless, but the check as written cannot be satisfied from this cache alone and should be re-read against the Data volume.

### APTicket: captured and verified during device restore

A ticket is issued by Apple's TSS during a restore and is bound to this device's ECID and the build's nonce. There is nothing to resolve, extract or verify from the IPSW.

The handling code is build-agnostic: `scripts/apticket.py` performs DER/IM4M validation and atomic publication, while `scripts/capture_ticket.py` recovers the ticket from a completed restore log. Neither required an RC-specific implementation.

The physical-device RC restore captured and verified the restore-bound ticket before SSHRD and normal-boot artifacts were built.

---

## Appendix: resolver evidence per record

Every record here is one from the per-patch tables, with the evidence its resolver emitted for choosing that site. Evidence is what makes a record auditable: it names the semantic identity that was matched, not the address the match happened to land on. A record whose evidence no longer holds on a future build should fail loudly rather than drift to a neighbouring function.

Records are grouped where they share an evidence set, which is the normal case for a paired result/return stub or a multi-word generated payload. The 198 records reduce to 56 distinct evidence sets.

Produced by `liter8 resolve <component> <plan> <binary> --json` against the same RC payloads the fixtures pin. Every offset and byte pair was checked to match `fixtures/24A435/n104ap/` exactly, so this appendix describes the same 198 records and not a re-run that drifted.

### iBSS / iBEC

#### `ibss-validate-asn1` — 2 records, 1 evidence set

**2 records**, `0x236e8`–`0x236ec`

- `ibss.validate-asn1.branch` @ `0x236e8` — Bypass the ASN.1 validation failure branch
- `ibss.validate-asn1.result` @ `0x236ec` — Return success after bypassing validation

Evidence:

- unique string anchor at 0x1392ea
- ADRP+ADD xref at 0x237d0
- conditional branch target contains anchor xref at target+8
- preceding BL and following mov x0,x20 / ldp x29,x30,[sp,#0xd0]

#### `ibss-restore` — 5 records, 2 evidence sets

**2 records**, `0x236e8`–`0x236ec`

- `ibss.validate-asn1.branch` @ `0x236e8` — Bypass the ASN.1 validation failure branch
- `ibss.validate-asn1.result` @ `0x236ec` — Return success after bypassing validation

Evidence:

- unique string anchor at 0x1392ea
- ADRP+ADD xref at 0x237d0
- conditional branch target contains anchor xref at target+8
- preceding BL and following mov x0,x20 / ldp x29,x30,[sp,#0xd0]

**3 records**, `0x2aa0c`–`0x26cfc0`

- `ibss.boot-args.adrp` @ `0x2aa0c` — Redirect the boot-args format pointer to the selected page
- `ibss.boot-args.add` @ `0x2aa10` — Redirect the boot-args format pointer within the selected page
- `ibss.boot-args.string` @ `0x26cfc0` — Install the literal boot argument string

Evidence:

- unique ADRP X2 / ADD X2 / ADD X0,SP / MOV W1,#0x400 / BL call shape
- original pointer resolves to isolated %s string at 0x139c0f
- unique zero run ending at page boundary 0x26d000
- aligned string slot 0x26cfc0 has 64 bytes available

#### `ibss-ramdisk` — 5 records, 2 evidence sets

**2 records**, `0x236e8`–`0x236ec`

- `ibss.validate-asn1.branch` @ `0x236e8` — Bypass the ASN.1 validation failure branch
- `ibss.validate-asn1.result` @ `0x236ec` — Return success after bypassing validation

Evidence:

- unique string anchor at 0x1392ea
- ADRP+ADD xref at 0x237d0
- conditional branch target contains anchor xref at target+8
- preceding BL and following mov x0,x20 / ldp x29,x30,[sp,#0xd0]

**3 records**, `0x2aa0c`–`0x26cfc0`

- `ibss.boot-args.adrp` @ `0x2aa0c` — Redirect the boot-args format pointer to the selected page
- `ibss.boot-args.add` @ `0x2aa10` — Redirect the boot-args format pointer within the selected page
- `ibss.boot-args.string` @ `0x26cfc0` — Install the literal boot argument string

Evidence:

- unique ADRP X2 / ADD X2 / ADD X0,SP / MOV W1,#0x400 / BL call shape
- original pointer resolves to isolated %s string at 0x139c0f
- unique zero run ending at page boundary 0x26d000
- aligned string slot 0x26cfc0 has 64 bytes available

#### `ibss-normal` — 5 records, 2 evidence sets

**2 records**, `0x236e8`–`0x236ec`

- `ibss.validate-asn1.branch` @ `0x236e8` — Bypass the ASN.1 validation failure branch
- `ibss.validate-asn1.result` @ `0x236ec` — Return success after bypassing validation

Evidence:

- unique string anchor at 0x1392ea
- ADRP+ADD xref at 0x237d0
- conditional branch target contains anchor xref at target+8
- preceding BL and following mov x0,x20 / ldp x29,x30,[sp,#0xd0]

**3 records**, `0x2aa0c`–`0x26cfba`

- `ibss.boot-args.adrp` @ `0x2aa0c` — Redirect the boot-args format pointer to the selected page
- `ibss.boot-args.add` @ `0x2aa10` — Redirect the boot-args format pointer within the selected page
- `ibss.boot-args.string` @ `0x26cfba` — Install the literal boot argument string

Evidence:

- unique ADRP X2 / ADD X2 / ADD X0,SP / MOV W1,#0x400 / BL call shape
- original pointer resolves to isolated %s string at 0x139c0f
- unique zero run ending at page boundary 0x26d000
- aligned string slot 0x26cfba has 70 bytes available

#### `ibss-skip-display-init` — 1 records, 1 evidence set

**`ibss.display.skip-initialization`** @ `0x35230` — Skip iBSS display initialization and take its handled-failure path

Evidence:

- BL power / BL display / CBZ result sequence
- failure path writes one to an X20 state byte then returns zero
- explicit iBSS-only operation because iBSS and iBEC payloads are identical

#### `ibec-diag-ignore-pinot-id-failure` — 1 records, 1 evidence set

**`ibec.pinot.zero-panel-id.return-success`** @ `0x9e6d4` — Redirect zero panel-ID failure to Pinot's existing success return

Evidence:

- LDR W8,[X25,#panel_id] / CBZ W8 failure
- failure target calls teardown then returns -1
- replacement target sets W0 to zero and enters the shared epilogue

### TXM

#### `txm-restore` — 6 records, 3 evidence sets

**3 records**, `0x3df48`–`0x3e244`

- `txm.query-module.0` @ `0x3df48` — Make queryModule CDHash comparison 0 report equality
- `txm.query-module.1` @ `0x3e0b0` — Make queryModule CDHash comparison 1 report equality
- `txm.query-module.2` @ `0x3e244` — Make queryModule CDHash comparison 2 report equality

Evidence:

- MOV X0,Xn / MOV X1,Xn / MOV W2,#0x14 / BL / CBZ W0
- all three selected calls target one memcmp implementation
- fourth 20-byte comparison rejected because it uses CMP after BL

**`txm.constraints.restricted-entitlements`** @ `0x43744` — Do not reject the six restricted task-port entitlements

Evidence:

- unique six-entry loop with TST W0,#0xff00
- loop advances table pointer by 8 until 0x30 bytes
- selected B.EQ returns the per-entry 0x00NN30A2 error

**2 records**, `0x437b0`–`0x437b8`

- `txm.constraints.signature-type-range` @ `0x437b0` — Keep validateConstraintsSignatureType on its benign path
- `txm.constraints.signature-type-null` @ `0x437b8` — Do not skip to the 0x000130A1 error construction

Evidence:

- unique MOV/MOVK construction of error 0x000130A1 at 0x437dc
- B.LO and CBZ X9 skip the benign MOV W0,#0xA1 path
- fall-through branches directly to the epilogue before error construction

#### `txm-boot` — 9 records, 5 evidence sets

**3 records**, `0x3df48`–`0x3e244`

- `txm.query-module.0` @ `0x3df48` — Make queryModule CDHash comparison 0 report equality
- `txm.query-module.1` @ `0x3e0b0` — Make queryModule CDHash comparison 1 report equality
- `txm.query-module.2` @ `0x3e244` — Make queryModule CDHash comparison 2 report equality

Evidence:

- MOV X0,Xn / MOV X1,Xn / MOV W2,#0x14 / BL / CBZ W0
- all three selected calls target one memcmp implementation
- fourth 20-byte comparison rejected because it uses CMP after BL

**`txm.constraints.restricted-entitlements`** @ `0x43744` — Do not reject the six restricted task-port entitlements

Evidence:

- unique six-entry loop with TST W0,#0xff00
- loop advances table pointer by 8 until 0x30 bytes
- selected B.EQ returns the per-entry 0x00NN30A2 error

**2 records**, `0x437b0`–`0x437b8`

- `txm.constraints.signature-type-range` @ `0x437b0` — Keep validateConstraintsSignatureType on its benign path
- `txm.constraints.signature-type-null` @ `0x437b8` — Do not skip to the 0x000130A1 error construction

Evidence:

- unique MOV/MOVK construction of error 0x000130A1 at 0x437dc
- B.LO and CBZ X9 skip the benign MOV W0,#0xA1 path
- fall-through branches directly to the epilogue before error construction

**2 records**, `0x2fd04`–`0x2fd08`

- `txm.secure-channel.return-one` @ `0x2fd04` — Make allowedBeforeSecureChannelOperational return true
- `txm.secure-channel.return` @ `0x2fd08` — Return immediately after setting the secure-channel result

Evidence:

- unique secure-channel accessor body begins at 0x2fd00
- accessor and developer-mode routine reference state at 0x84db0
- BTI landing pad is preserved; replacement begins after it

**`txm.developer-mode.publish`** @ `0x2fa88` — Take the existing path that publishes developer mode as true

Evidence:

- unique secure-channel accessor body begins at 0x2fd00
- accessor and developer-mode routine reference state at 0x84db0
- BTI landing pad is preserved; replacement begins after it
- TBZ W9,#0 otherwise skips MOV W20,#1
- NOP preserves TXM's existing propagation and final store

### Kernel

#### `kernel-restore` — 20 records, 14 evidence sets

**2 records**, `0x3f2be`–`0x3f324`

- `kernel.identity.0` @ `0x3f2be` — Mark kernel version string 0 as patched
- `kernel.identity.1` @ `0x3f324` — Mark kernel version string 1 as patched

Evidence:

- exact same-length RELEASE_ARM64_T8030 string
- exactly two occurrences in the pristine kernelcache
- replacement does not move data or alter container layout

**`kernel.panic.root-snapshot`** @ `0x2fec20c` — Do not enter the root-snapshot panic block

Evidence:

- unique diagnostic phrase: Failed to find the root snapshot
- unique ADRP+ADD reference to its containing C string
- conditional target is uniquely closest to that xref within the 0x40-byte panic-block window

**`kernel.panic.seal-broken`** @ `0x2f58ed4` — Do not enter the seal-broken panic block

Evidence:

- unique diagnostic phrase: root volume seal is broken
- unique ADRP+ADD reference to its containing C string
- conditional target is uniquely closest to that xref within the 0x40-byte panic-block window

**`kernel.panic.rootvp-authentication`** @ `0x366924c` — Do not enter the rootvp-authentication panic block

Evidence:

- unique diagnostic phrase: rootvp not authenticated after mounting
- unique ADRP+ADD reference to its containing C string
- conditional target is uniquely closest to that xref within the 0x40-byte panic-block window

**`kernel.panic.unencrypted-data-volume`** @ `0x2fed640` — Do not enter the unencrypted-data-volume panic block

Evidence:

- unique diagnostic phrase: unencrypted data volume is not allowed
- unique ADRP+ADD reference to its containing C string
- conditional target is uniquely closest to that xref within the 0x40-byte panic-block window

**5 records**, `0x1efbe84`–`0x1efbe94`

- `kernel.amfi.trust-cache.0` @ `0x1efbe84` — Make AMFI trust-cache lookup succeed (word 1/5)
- `kernel.amfi.trust-cache.1` @ `0x1efbe88` — Make AMFI trust-cache lookup succeed (word 2/5)
- `kernel.amfi.trust-cache.2` @ `0x1efbe8c` — Make AMFI trust-cache lookup succeed (word 3/5)
- … 2 further records in this group

Evidence:

- unique PACIBSP function with saved x3 out-parameter
- stack result is passed to a lookup call and followed by result/out-parameter guards

**`kernel.amfi.launch-constraints.result`** @ `0x1f00bb8` — Return success from AMFI launch-constraint validation

Evidence:

- function uniquely owns the Validation Category diagnostic

**`kernel.amfi.launch-constraints.return`** @ `0x1f00bbc` — Return immediately after the launch-constraint result

Evidence:

- paired entry-point stub

**`kernel.debugger.result`** @ `0x39abbfc` — Report that the platform permits a debugger

Evidence:

- unique highest-call-count ADRP x8 leaf with optional x0 output-pointer data flow

**`kernel.debugger.return`** @ `0x39abc00` — Return the forced debugger result

Evidence:

- paired leaf-function stub

**`kernel.amfi.developer-mode.result`** @ `0x36f4cd8` — Report developer mode enabled

Evidence:

- unique shared-pointer byte accessor masked to bit zero

**`kernel.amfi.developer-mode.return`** @ `0x36f4cdc` — Return the forced developer-mode result

Evidence:

- paired accessor stub

**`kernel.amfi.post-validation.compare`** @ `0x1f08978` — Force the post-validation comparison unequal so the accept branch is taken

Evidence:

- callee of the function owning the code-signature validation diagnostic
- CMP W0,#imm follows a BL and is immediately consumed by B.NE
- fallthrough formats a diagnostic and branches to the shared reject tail

**2 records**, `0x1f08ee4`–`0x1f08ef0`

- `kernel.amfi.dyld-policy.0` @ `0x1f08ee4` — Make dyld policy helper 1 succeed
- `kernel.amfi.dyld-policy.1` @ `0x1f08ef0` — Make dyld policy helper 2 succeed

Evidence:

- within 80 bytes of the Swift Playgrounds development entitlement xref
- BL is immediately followed by a conditional test of w0 and the two helpers differ

#### `kernel-boot-policy` — 4 records, 4 evidence sets

**`kernel.persona.uid-zero`** @ `0x36a21a4` — Allow the persona UID override to be zero

Evidence:

- LDR Wn,[persona,#8] followed by CBZ Wn
- UID and GID branches share the same result-one deny block

**`kernel.persona.gid-zero`** @ `0x36a21ac` — Allow the persona GID override to be zero

Evidence:

- LDR Wn,[persona,#0xc] followed by CBZ Wn
- fallthrough writes result zero while the shared target writes result one

**`kernel.usb.restore-mode-result`** @ `0x28053d0` — Report restore mode to the USB Restricted Mode policy

Evidence:

- unique rd/rootdev/-restore boot-argument string cluster
- function owns sibling rd and rootdev parser calls to the same helper
- arm64e entry follows RETAB

**`kernel.usb.restore-mode-return`** @ `0x28053d4` — Return the forced restore-mode result

Evidence:

- paired entry-point stub

#### `kernel-sep` — 32 records, 6 evidence sets

**`kernel.aks.start.sep-call`** @ `0x20e629c` — Skip the SEP-dependent call in AKSUserClient::start

Evidence:

- unique relocation-masked AKS start-call body

**20 records**, `0x20f13a4`–`0x20f13f0`

- `kernel.aks.external-method.selector7.0` @ `0x20f13a4` — Selector-7 shim: CMP W1,#7 - recognize selector 7
- `kernel.aks.external-method.selector7.1` @ `0x20f13a8` — Selector-7 shim: B.NE success - other selectors keep the existing success path
- `kernel.aks.external-method.selector7.2` @ `0x20f13ac` — Selector-7 shim: CBZ X2,badArgument - reject a null arguments pointer
- … 17 further records in this group

Evidence:

- unique relocation-masked AKSUserClient::externalMethod prologue
- IOExternalMethodArguments LP64 offsets validated by the native selector-7 path
- entry PACIBSP is deliberately preserved

**`kernel.aks.external-method.log-call`** @ `0x20f15d8` — Silence the now-unreachable externalMethod IOLog call

Evidence:

- unique relocation-masked IOLog call sequence in the AKS external method

**3 records**, `0x213d340`–`0x213a43c`

- `kernel.sep.panic-check.result` @ `0x213d340` — Return success from sepPanicCheck
- `kernel.sep.did-timeout.result` @ `0x2139aa4` — Report that the SEP command did not time out
- `kernel.sep.power-notification.result` @ `0x213a43c` — Return success from the paging-off notification handler

Evidence:

- semantic SEP function entry resolved without a target offset

**3 records**, `0x213d344`–`0x213a440`

- `kernel.sep.panic-check.return` @ `0x213d344` — Return the forced SEP result
- `kernel.sep.did-timeout.return` @ `0x2139aa8` — Return the forced SEP result
- `kernel.sep.power-notification.return` @ `0x213a440` — Return the forced SEP result

Evidence:

- paired entry-point stub

**4 records**, `0x213e1fc`–`0x213e7c4`

- `kernel.sep.set-power-a` @ `0x213e1fc` — Do not enter the first setPowerState SEP failure path
- `kernel.sep.notify-active` @ `0x213d194` — Do not enter the notifyOSActiveGated SEP failure path
- `kernel.sep.set-power-b` @ `0x213e22c` — Do not enter the second setPowerState SEP failure path
- … 1 further records in this group

Evidence:

- unique relocation-masked local failure-path sequence

#### `kernel-sandbox` — 46 records, 6 evidence sets

**`kernel.sandbox.vnode-check-open.target`** @ `0x10cf898` — Retarget vnode_check_open to the scoped process-name shim

Evidence:

- mac_policy_conf -> mpc_ops[267]
- low chained-pointer target only

**`kernel.sandbox.vnode-check-open.metadata`** @ `0x10cf89c` — Assert and preserve vnode_check_open PAC metadata

Evidence:

- high chained-pointer word from mpc_ops[267]

**33 records**, `0x39fd480`–`0x39fd500`

- `kernel.sandbox.vnode-check-open.shim.0` @ `0x39fd480` — Scoped vnode_check_open shim: PACIBSP - sign LR with the B key and SP
- `kernel.sandbox.vnode-check-open.shim.1` @ `0x39fd484` — Scoped vnode_check_open shim: STP FP,LR,[SP,#-0x30]! - save frame and signed LR
- `kernel.sandbox.vnode-check-open.shim.2` @ `0x39fd488` — Scoped vnode_check_open shim: MOV FP,SP - establish the frame pointer
- … 30 further records in this group

Evidence:

- unique executable cave after reviewed function tail

**`kernel.sandbox.vnode-check-exec.target`** @ `0x10cf850` — Retarget vnode_check_exec to the existing allow stub

Evidence:

- mac_policy_conf -> mpc_ops[258]
- mpc_ops[36] target

**5 records**, `0x2f219fc`–`0x2f1a480`

- `kernel.sandbox.file-check-mmap.result` @ `0x2f219fc` — Return success from file_check_mmap
- `kernel.sandbox.mount-check-mount.result` @ `0x2f1f998` — Return success from mount_check_mount
- `kernel.sandbox.mount-check-remount.result` @ `0x2f1f7c8` — Return success from mount_check_remount
- … 2 further records in this group

Evidence:

- native target read from its mpc_ops slot

**5 records**, `0x2f21a00`–`0x2f1a484`

- `kernel.sandbox.file-check-mmap.return` @ `0x2f21a00` — Return the forced Seatbelt result
- `kernel.sandbox.mount-check-mount.return` @ `0x2f1f99c` — Return the forced Seatbelt result
- `kernel.sandbox.mount-check-remount.return` @ `0x2f1f7cc` — Return the forced Seatbelt result
- … 2 further records in this group

Evidence:

- paired entry-point stub

#### `kernel-credential-manager` — 52 records, 3 evidence sets

**22 records**, `0x20bfd50`–`0x20c5688`

- `kernel.credential-manager.sepmanagermatchedthreadcallhandler.result` @ `0x20bfd50` — Return success from sepManagerMatchedThreadCallHandler
- `kernel.credential-manager.callplatformfunction.result` @ `0x20c0434` — Return success from callPlatformFunction
- `kernel.credential-manager.cmdcontextv2.result` @ `0x20c04bc` — Return success from cmdContextV2
- … 19 further records in this group

Evidence:

- unique relocation-masked function body
- genuine PACIBSP or BTI C function entry

**26 records**, `0x20bfd54`–`0x20d1b30`

- `kernel.credential-manager.sepmanagermatchedthreadcallhandler.return` @ `0x20bfd54` — Return the forced AppleCredentialManager result
- `kernel.credential-manager.callplatformfunction.return` @ `0x20c0438` — Return the forced AppleCredentialManager result
- `kernel.credential-manager.cmdcontextv2.return` @ `0x20c04c0` — Return the forced AppleCredentialManager result
- … 23 further records in this group

Evidence:

- paired entry-point stub

**4 records**, `0x20c1c54`–`0x20d1b2c`

- `kernel.credential-manager.updateanalytics.result` @ `0x20c1c54` — Return success from updateAnalytics
- `kernel.credential-manager.sendsepcommand.result` @ `0x20c2084` — Return success from sendSEPCommand
- `kernel.credential-manager.unlockitem.result` @ `0x20c36e8` — Return success from unlockItem
- … 1 further records in this group

Evidence:

- neighbor-bounded 32-word similarity
- genuine PACIBSP or BTI C function entry

### Userland

#### `restored-external-fdr` — 1 records, 1 evidence set

**`restored-external.fdr-result`** @ `0x7e848` — Return success from RestoredFDRRecover

Evidence:

- unique RestoredFDRRecover string at 0x204f28
- unique ADRP+ADD reference at 0x7e514
- MOV X0,status immediately precedes LDP X29,X30,[SP,#0x90]

#### `asr-signature` — 1 records, 1 evidence set

**`asr.signature-mismatch-branch`** @ `0x1f670` — Do not enter the image-signature failure block after memcmp

Evidence:

- unique signature-failure string at 0x3bb69
- reporter function begins at 0x35504
- reporter callers: 0x1fc98
- unique CBNZ W0 into caller block immediately follows a BL

#### `coreauthd` — 1 records, 1 evidence set

**`coreauthd.dto-ratchet.start-controller`** @ `0x95c0` — Skip the SEP-dependent DTO ratchet controller startup

Evidence:

- unique startController selector and Objective-C selector reference
- optimized objc_msgSend selector stub at 0x3da20
- unique BL caller followed by LDR X0,[SP,#8] at crash return address

#### `ctkd` — 2 records, 1 evidence set

**2 records**, `0x1b38`–`0x1b3c`

- `ctkd.sep-key-server.return-nil` @ `0x1b38` — Return nil from serverAttributesOfKey:error:
- `ctkd.sep-key-server.return` @ `0x1b3c` — Return before entering the SEP-backed method body

Evidence:

- unique Objective-C selector serverAttributesOfKey:error:
- relative method entry at 0x26710 resolves to 0x1b38
- RETAB / PACIBSP / SUB SP,SP entry boundary

#### `mobileactivationd` — 5 records, 2 evidence sets

**`mobileactivationd.should-hactivate`** @ `0x2ec368` — Make DeviceType report that hactivation is enabled

Evidence:

- unique Objective-C selector should_hactivate
- relative method entry resolves to 0x2ec368
- two-instruction LDRB W0,[X0,#ivar] / RET getter

**4 records**, `0x329be8`–`0x329c50`

- `mobileactivationd.activation-state.migration-gate` @ `0x329be8` — Do not skip activation-state reporting before migration completes
- `mobileactivationd.activation-state.adrp` @ `0x329c48` — Load the page containing the Activated CFString
- `mobileactivationd.activation-state.add` @ `0x329c4c` — Materialize the Activated CFString address in X0
- … 1 further records in this group

Evidence:

- unique getActivationStateWithCompletionBlock: implementation at 0x329b88
- TBZ W22,#0 data-migration gate followed 0x60 bytes later by ADRP/ADD/LDR fallback load
- unique 32-byte CFString object for Activated at 0x3ef6f8

---

56 evidence groups across 198 records.
