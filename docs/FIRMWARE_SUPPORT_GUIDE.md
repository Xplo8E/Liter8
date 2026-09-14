# Firmware and device support in Liter8

This guide explains what Liter8 means by “supported” and how to add a firmware build or device without turning offsets into runtime configuration. It uses the iPhone 11 (`n104ap`) ports for iOS 27 beta 4 (`24A5390f`) and iOS 27 `24A435` as the worked example.

## The support model

Liter8 keeps four kinds of data separate:

| Layer | Question it answers | Stored in |
| --- | --- | --- |
| Resolver | Where is this operation in the current binary? | `Sources/Liter8Core/Resolvers/` |
| Resolver profile | Which signature or replacement family applies to this kernel? | `Sources/Liter8Core/Profiles/` |
| Workflow profile | May this exact IPSW and device run the full workflow? | `DeviceWorkflowRegistry` |
| Fixture | Did the resolver reproduce the reviewed result for one exact binary? | `fixtures/<build>/<board>/` |

The runtime path is:

```text
BuildManifest.plist
        |
        v
DeviceWorkflowProfile
  exact build and hardware gate
  pre-boot guards
  board boot policy
        |
        v
Swift semantic resolver
  inspect the supplied binary
  derive PatchRecord values
        |
        v
guarded patch application
  verify original bytes
  write replacements
        |
        v
Python workflow
  extract, sign, copy and send artifacts
```

Python receives component paths and reviewed boot policy from Swift. It does not contain firmware offsets, signature tables, or `device_class` branches.

> [!IMPORTANT]
> A fixture is an oracle, not a lookup table. Runtime resolution must succeed without reading the fixture offset.

## What “supported” means

Support has four stages:

1. **Resolver verified:** every required resolver finds one defensible result in clean binaries from the new build.
2. **Artifact verified:** fixtures bind those results to input hashes, original bytes, replacement bytes and patched-output hashes.
3. **Workflow experimental:** the exact IPSW has a workflow profile, but restore or boot evidence is incomplete. The CLI requires `--experimental`.
4. **Device reviewed:** restore, SSHRD, provisioning, normal boot, finalization and repeat health checks passed on the target device.

Only stage 4 belongs in the default firmware workflow.

## Working method

Keep discovery, implementation, fixtures and device validation as separate phases. Each phase consumes recorded evidence from the previous one and has its own stopping condition. This makes the work reviewable whether it is performed manually or with a coding tool.

### Record the target

Create a research note with these fields before editing code:

| Field                 | Example                                  |
| --------------------- | ---------------------------------------- |
| Repository            | `/path/to/liter8`                        |
| Reference             | `24A5390f`, `iPhone12,1`, `n104ap`       |
| Target                | `24A435`, `iPhone12,1`, `n104ap`         |
| Clean target binaries | `/path/to/private/24A435/`               |
| Reference fixtures    | `fixtures/24A5390f/n104ap/`              |
| Research note         | `docs/plans/IOS_27_24A435_RC_PATCHES.md` |
| Current phase         | Resolver discovery                       |

Apply these rules throughout the port:

- Resolve from the target binary. Do not read a fixture offset as an input.
- Treat reference offsets as post-resolution checks only.
- Do not weaken uniqueness or masks merely to make the target pass.
- Comment every raw instruction sequence with its decoded purpose.
- Preserve beta-4 output exactly unless evidence requires a shared correction.
- Keep the new workflow profile experimental until device validation completes.
- Stop on ambiguous candidates instead of choosing the nearest offset.

Define which local files may be modified. Clean binaries and mounted filesystems should remain read-only inputs.

### Phase A: inventory and baseline

Inspect the target binaries without editing resolver code. Run every existing resolver against the clean target inputs and compare the required plan set with the reference build. Record plan, patch ID, result count, target offset, original bytes and one classification: unchanged rule, signature drift, payload drift, ambiguous, or missing.

The output should include:

- hashes and sizes for every clean input;
- the exact command used for each resolver;
- unresolved and ambiguous patch IDs;
- evidence for each proposed semantic match;
- a list of required userland images that have not been mounted or decrypted.

Do not create fixtures or change the workflow registry during this phase. Save the table under `docs/plans/` so work can resume without repeating discovery.

### Phase B: resolver implementation

Implement only the failures recorded in Phase A. Prefer shared semantic rules when control flow proves them. Add a profile signature or payload variant when the difference is build-family data. Add focused negative tests for missing and duplicate candidates. Do not generate or edit fixtures during implementation. Run the smallest relevant release-mode test after each kernel resolver change.

Require an evidence record for each non-trivial correction:

| Field | What to record |
| --- | --- |
| Patch ID | Stable Liter8 operation name |
| Anchor | String, xref, call target, metadata or instruction relation used |
| Containing function | Symbol or recovered purpose |
| Selection rule | Why exactly one candidate survives |
| Original bytes | Bytes read from the clean target |
| Replacement | Instruction or data behavior, explained in plain text |
| Reference comparison | Same operation in beta 4, after target resolution |
| Failure test | Mutation or synthetic case that must be rejected |

For a raw sequence such as `d503237f d10103ff`, the nearby comment should say which instructions they encode and why those words identify the function. A comment such as “RC signature” does not explain the evidence.

### Phase C: independent review

Review the clean binaries and code diff from a fresh context. Derive each match before reading the proposed offset. Check that the resolver reaches the claimed function, branch polarity and calling convention support the replacement, and BTI/PAC landing pads remain valid. Look for broadened masks, first-match selection, fixture-derived offsets and build checks inside semantic resolvers.

Agreement on an offset is weak evidence when both passes started from the same expected-offset table. Independent review follows binary evidence first, then compares results.

### Phase D: fixture generation

After semantic review passes, generate fixtures for every required target plan from the reviewed clean binaries. Reload and verify every manifest. Compare its patch-ID set with the reference build and explain each difference. Do not modify resolver code during fixture generation or add a workflow profile yet.

If fixture generation exposes a resolver problem, return to Phase B. Do not edit the JSON until it agrees with the code.

### Phase E: workflow profile

Add an experimental `DeviceWorkflowProfile` using the BuildManifest identity, measured launchd, service-cache and Setup guards, and reviewed hardware boot policy. Add profile and context tests. Keep `validationState` set to `.experimental`.

The device operator controls DFU transitions, destructive restore, sudo authorization and recovery. Record the exact command and output for each step.

### Phase F: device evidence

Compare every device command result with the acceptance conditions before running the next stage. Record passed and failed checks. After restore, SSHRD, provisioning, normal boot, finalization and repeat checks pass, update the run note, promote the profile to reviewed, add the regression test and run all test tiers. Keep remaining risks separate from completed evidence.

### Evidence required for support claims

Reject any support claim that lacks the named evidence:

| Claim | Required evidence |
| --- | --- |
| “Resolver works” | Unique target result plus semantic analysis and guarded pre-image |
| “Same patch” | Same operation and replacement behavior, not a nearby offset |
| “Fixture passes” | Manifest reload, record comparison and output hash verification |
| “Firmware supported” | Exact IPSW profile plus complete required artifact coverage |
| “Device supported” | Restore, boot, provisioning, finalization and repeat-run logs |
| “Safe to generalize” | At least two binary shapes and negative ambiguity tests |

Require the command output, binary relation, test name, fixture path or device log behind each conclusion.

### State for a long-running port

Maintain a short state block in the research note:

```markdown
## Current state

- Target: iPhone12,1 / n104ap / 24A435
- Clean inputs: <path>, hashes recorded
- Resolvers: 198/198 records resolved
- Fixtures: 18/18 verified
- Workflow profile: experimental
- Device validation: restore passed; normal boot pending
- Open risk: performLoggingLevelQueryGated replaces a PAC-less BTI leaf entry
- Next action: build SSHRD from the captured APTicket
```

This state describes completed evidence and the next action. It should not become a diary of every attempted command.

## Case 1: another build for a supported device

This was the `24A5390f` to `24A435` port. The product and board stayed the same:

| Field        | Beta 4       | `24A435`     |
| ------------ | ------------ | ------------ |
| Product type | `iPhone12,1` | `iPhone12,1` |
| Device class | `n104ap`     | `n104ap`     |
| Chip ID      | `0x8030`     | `0x8030`     |
| Board ID     | `0x04`       | `0x04`       |
| Build        | `24A5390f`   | `24A435`     |

The existing device policy could be reused, but every binary result still had to be recovered from the new build.

### 1. Stage clean inputs

Read `BuildManifest.plist` and record:

- product version and build;
- product type, device class, chip ID and board ID;
- the selected non-research erase identity;
- every component path used by CFW, SSHRD and normal boot.

Keep decompressed or mounted binaries outside the public repository. Do not rename them to resemble the old build.

### 2. Run the existing resolvers

For each required plan, run `liter8 resolve` against the clean new binary. A successful result must have:

- one candidate for every required patch ID;
- original bytes that match the supplied binary;
- replacement bytes with the same intended behavior as the reviewed build;
- no overlapping writes unless the resolver explicitly composes them.

Classify each failure before editing code:

| Result | Action |
| --- | --- |
| Same semantic rule still works | Reuse the resolver unchanged |
| Compiler changed the recognizable shape | Add or generalize a signature variant |
| ABI or intended replacement changed | Add a payload variant |
| Old rule now finds several candidates | Strengthen semantic evidence |
| Required operation changed | Add a separate resolver or plan |

Do not weaken a uniqueness check until a binary passes. Use xrefs, function boundaries, branch targets and result consumption to distinguish candidates.

### 3. Separate shared rules from build-specific data

The `24A435` port produced several useful examples.

#### A compiler change that belongs in shared analysis

`24A435` enabled BTI throughout the kernelcache. Function entries gained `BTI C` landing pads before many prologues. ARM64 boundary helpers were taught to distinguish a landing pad from the body that a replacement stub may own. That rule remains useful for any binary with the same control-flow shape.

#### A semantic change that the resolver can derive

The AMFI post-validation check changed branch polarity. Beta 4 compared against SHA-256; `24A435` compared against SHA-1 with a different accept/reject branch. The resolver now derives the replacement from the observed branch sense. No build ID is needed for that decision.

#### A signature family that belongs in a resolver profile

AppleSEPCredentialManager still needed the same 26 methods replaced with the same success stub. Their compiled shapes changed enough to require separate signature families:

```swift
// beta 4
signature: "ios27-early-beta-acm-v1"
payload: "acm-return-success-v1"

// 24A435
signature: "ios27-24A435-acm-v1"
payload: "acm-return-success-v1"
```

The signature changed. The patch behavior did not. Copying the replacement bytes into a new build-specific resolver would duplicate the wrong layer.

#### A data-location rule that needed stronger evidence

The iBSS boot-argument slot moved from `0xd0e30` to the `0x26cfc0` area. Liter8 does not store either offset. It selects the unique largest zero run ending on a page boundary, keeps the guard gap, then places the requested string inside that run. The beta-4 and `24A435` fixtures verify the derived locations.

### 4. Add the kernel resolver profile

`KernelResolverProfileRegistry` identifies a kernel using its embedded XNU fingerprint. The profile records metadata and only the variants that differ:

```swift
KernelResolverProfile(
    id: "ios27-24A435-n104ap",
    productVersion: "27.0 RC/release",
    build: "24A435",
    boards: ["n104ap"],
    component: "kernelcache.release.iphone12b",
    embeddedFingerprint: "xnu-13432.2.10~2/RELEASE_ARM64_T8030",
    resolverVariants: [
        "kernel-credential-manager": ResolverVariantProfile(
            signature: "ios27-24A435-acm-v1",
            payload: "acm-return-success-v1"
        ),
    ]
)
```

An unknown fingerprint must return no profile. Similar filenames, offsets, or version strings are not acceptable fallbacks.

### 5. Create exact-build fixtures

`24A435` has 18 manifests under `fixtures/24A435/n104ap/`, covering 198 patch records. Generate each manifest from the clean binary and the production resolver:

```bash
.build/release/liter8 fixture kernel restore <kernelcache> \
  fixtures/24A435/n104ap/kernel-restore-n104-24A435.json \
  --device "iPhone 11" \
  --board n104ap \
  --build 24A435 \
  --component-name kernelcache.release.iphone12b
```

Review the generated records. Fixture generation proves that serialization and guarded application agree; it does not prove that the selected function is the right function. Static analysis supplies that evidence.

Each fixture must contain:

- clean input size and SHA-256;
- patch ID and resolved file offset;
- original and replacement bytes;
- complete patched-output SHA-256.

Compare the new and previous fixture patch-ID sets. Offset equality is neither required nor expected.

### 6. Add an experimental workflow profile

`DeviceWorkflowProfile` is the full-workflow gate. Add it only after the IPSW identity and pre-boot inputs have been measured:

```swift
DeviceWorkflowProfile(
    id: "iphone12,1-n104ap-24A435",
    productVersion: "27.0",
    build: "24A435",
    productType: "iPhone12,1",
    deviceClass: "n104ap",
    chipID: 0x8030,
    boardID: 0x04,
    extractedDirectoryName: "iPhone12,1_27.0_24A435_Restore",
    validationState: .experimental,
    launchdSHA256: "<measured stock hash>",
    launchdCacheSHA256: "<measured stock hash>",
    launchdCacheDaemonCount: 729,
    setupControllerMethodCount: 66,
    bootPlan: DeviceBootPlan(
        normalIBSSAdditionalPlans: [.skipDisplayInitialization],
        restoreIBSSAdditionalPlans: [.skipDisplayInitialization]
    )
)
```

The launchd, service-cache and Setup values guard destructive pre-boot writes. They are exact-build inputs, so they belong here. They are not resolver offsets.

Both n104 builds select `skipDisplayInitialization`. Swift writes that choice to context schema 2, and Python applies it only to iBSS. iBEC retains display initialization for the LCD handoff.

### 7. Run tests in tiers

```bash
# Fast resolver, parser and workflow tests.
make test

# Real beta-4 and 24A435 binaries, compiled with optimization.
make test-fixtures

# All optimized tests except the deliberately uncached production composition.
make test-full

# Production composite resolver without the fixture cache.
make test-e2e

# Swift-to-Python context, ZIP safety and workflow handoff.
make integration
```

A passing fixture suite proves exact output parity for the staged binaries. It does not prove restore or boot behavior.

### 8. Validate on the device

Keep the workflow profile experimental during this sequence:

1. Prepare the IPSW and build the CFW.
2. Verify all CFW artifact records.
3. Restore and capture the device-bound APTicket.
4. Build and boot SSHRD.
5. Install the bootstrap.
6. Prepare the root filesystem and provision System, Data and Preboot.
7. Run the provision check and unmount the host rootfs.
8. Build and send normal-boot artifacts.
9. Complete Setup and run post-boot finalization.
10. Repeat the health check and at least one normal boot.

Record the command, build, device, observed result and any recovery action in a run note under `docs/runs/`. Promote `validationState` to `.reviewed` only after the complete sequence passes.

`24A435` reached reviewed status after erase restore, APTicket capture, SSHRD provisioning, normal boot, Procursus finalization, Dropbear verification, persona 99 and icon-token checks, PosterBoard recovery and a repeated healthy boot.

## Case 2: a new device for an existing build

A new device requires more than another `productType` in the existing profile. Start with a separate experimental `DeviceWorkflowProfile`, even when the iOS build matches an existing entry.

### Check every component choice

The new BuildManifest identity may select different files for:

- iBSS and iBEC;
- DeviceTree;
- restore and normal kernelcache;
- restore and normal TXM;
- SEP, SPTM and firmware payloads;
- restore ramdisk and root filesystem.

Run every resolver against the files selected for that board. Shared code can be reused only when the semantic evidence and replacement behavior still hold.

### Describe hardware boot policy explicitly

Set both `DeviceBootPlan` arrays after checking the device:

```swift
// A board reviewed without the n104 display handoff workaround.
bootPlan: DeviceBootPlan(
    normalIBSSAdditionalPlans: [],
    restoreIBSSAdditionalPlans: []
)
```

An empty list is an explicit reviewed choice. A missing boot plan is rejected before patching.

The current schema selects additional iBSS operations only. If the new device needs different iBEC, DeviceTree, TXM or kernel plan composition, extend the typed Swift workflow model first and export that choice through the context. Do not add the device with a Python conditional as a temporary shortcut.

### Collect device-specific guards

Measure the new board's stock launchd hash, service-cache hash and daemon count, Setup method count, component paths and any hardware-specific pre-boot input. Do not reuse values merely because the iOS build is the same.

Then follow the fixture, test and exact-device sequence from Case 1.

## Failure conditions

Stop the port and keep it experimental when any of these remains true:

- a resolver returns zero or several candidates;
- the candidate is supported only by nearby strings or an old offset;
- original bytes do not match the clean input;
- a replacement crosses a function or landing-pad boundary without proof;
- fixture patch IDs differ without an explained operation change;
- a required userland binary has not been extracted and checked;
- workflow guards were copied from another build or board;
- Setup, launchd injection, service-cache handling or APTicket capture is untested;
- the device booted once but repeat boot or finalization is unhealthy.

## Files changed by a normal port

| Purpose | Expected location |
| --- | --- |
| Kernel fingerprint and variant selection | `Sources/Liter8Core/Profiles/FirmwareProfile.swift` |
| New signature family | `Sources/Liter8Core/Profiles/` |
| New replacement family | `Sources/Liter8Core/Profiles/Payloads/` |
| Semantic resolver correction | `Sources/Liter8Core/Resolvers/` |
| Exact IPSW and device gate | `Sources/Liter8Core/Firmware/IPSWManifest.swift` |
| Exact-build oracles | `fixtures/<build>/<board>/` |
| Focused tests | `Tests/Liter8CoreTests/` |
| Device evidence | `docs/runs/` |

Python should change only when the generic workflow itself changes. A new firmware offset, signature family, board name or component filename is not a reason to edit Python.
