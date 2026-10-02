# Liter8 codebase guide

For someone about to change the code. [README.md](README.md) covers using it.

Swift decides, Python plumbs. Swift picks the firmware profile, parses the binary formats, works out where each patch goes, checks the bytes before writing, and signs the artifacts. Python mounts images, moves files, calls the external tools and walks the device through each stage. No offsets in the Python, no `device_class` branches either.

## What's where

| Path | What it holds |
| --- | --- |
| `Sources/Liter8CLI` | argument parsing, workflow dispatch |
| `Sources/Liter8Core/Binary` | ARM64, Mach-O, ObjC, byte primitives, read-only inspection |
| `Sources/Liter8Core/Firmware` | IPSW, profile context, IMG4/IM4P, resources, venv |
| `Sources/Liter8Core/Patching` | patch records, manifests, guarded writes |
| `Sources/Liter8Core/Profiles` | signature and payload variants |
| `Sources/Liter8Core/Resolvers` | per-component patch discovery |
| `Tests/Liter8CoreTests` | same split as Sources |
| `fixtures/<build>/<board>` | exact-build oracles |
| `scripts` | the Python: mounting, staging, signing, tool calls, device sequencing |
| `device` | what gets installed on the phone from SSHRD, and the scripts that do it |
| `payloads` | `ssh.tar.gz` and the sftp entitlements, both hash-pinned |
| `tools` | `usbliter8ctl`, plus `ldid`/`gtar`/`sshpass` fallbacks for hosts without them, plus the `idevicerestore` `make setup` builds |
| `docs` | porting procedure, design notes, device evidence |

## Where a command goes

`Sources/Liter8CLI/main.swift` reads the first argument and branches. `resolve`, `apply`, `verify`, `survey` and `inspect` load a `BinaryImage` and go straight into `Liter8Core`. Anything under `fw` goes through `FirmwareWorkflowRunner`, which writes a semantic context file and then hands off to the matching Python helper.

`survey --guards` is the one exception: it runs the sweep in Swift, then calls `scripts/measure_guards.py` to read the pre-boot guards off the root filesystem, because the decrypt and mount already live in `rootfs.py`.

`fw prepare` is the exception. It never touches Python.

## The pieces worth knowing

`BinaryImage` does bounded reads, pattern searches and holds the patch input.

`ARM64` decodes instructions and answers boundary questions. On a BTI build that matters more than it sounds: `functionEntry` and `functionStart` give you what a `BL` targets, `stubStart` gives you where a replacement stub can safely be written. They are the same address on a build without landing pads, which is why beta 4 never exercised the difference.

`BinaryInspector` is read-only. Segments, strings, xrefs, functions, calls, disassembly, ObjC methods, masked patterns. It exists for the hour you spend working out why a signature stopped matching.

`MachOLayout` and `ObjCMetadata` handle userland structure.

`IPSWManifest` holds firmware identity and `DeviceWorkflowRegistry`. `IPSWUnzip` does archive preflight, extraction and verification. `FirmwareArtifact` and `IMG4Signing` handle the containers natively.

`KernelResolverProfileRegistry` maps an embedded XNU fingerprint to signature and payload variants. It stores no resolved offsets, and an unknown fingerprint returns nothing rather than a near miss.

`GuardedPatchApplier` preflights the whole plan before it writes a byte, which is where the pre-image guards are enforced.

## What a firmware run does

1. Read the IPSW manifest, select exactly one workflow profile.
2. Extract to staging, verify the inventory.
3. Map semantic component names onto the manifest's paths.
4. Resolve and guard every site. `apply --records-out` emits records from that same pass rather than resolving twice.
5. Patch and sign into a staging set.
6. Verify the output hashes, publish the set atomically.
7. Send the restore, SSHRD or normal-boot sequence.

## Supported builds

Five `DeviceWorkflowProfile` entries, all `.reviewed`, all iPhone 11 `n104ap`:

| Build | Version |
| --- | --- |
| `24A5390f` | 27.0 beta 4 |
| `24A435` | 27.0 |
| `24A446` | 27.0.1 |
| `24B5084k` | 27.2 beta 1 |
| `24B5089g` | 27.2 beta 2 |

`supports()` requires an exact build match, so anything else fails at `fw prepare`.

Resolver profiles are a separate list and do not line up one to one. `ios27-24A435-n104ap` covers `24A435`, `24A437` and `24A446` because the kernels share an XNU fingerprint. `ios27-beta2-24A5370h-d421ap` exists only as a credential-manager signature reference for `d421ap`/`d431ap`, with no workflow behind it. A resolver profile existing says nothing about whether the device workflow is supported.

Nothing is currently marked `.experimental`. The flag and the gate are wired up and waiting for the next port.

## Flags and environment

- `--file`, then `IPSW_FILE`: the input IPSW.
- `--work-dir`, then `WORK_DIR`, then cwd: where mutable state lands.
- `--experimental`: opt into a profile that has not finished device validation.
- `--serial`: add `serial=3` to the artifact being built, moving the kernel console to UART. Per artifact, because the literal is baked in at build time.
- `--ticket`: supply an IM4M instead of using the captured one.
- `--irecovery`: the project's custom build, required for every boot command.
- `--idevicerestore`: override the pinned binary. Development only.
- `--rootfs`: a root filesystem you mounted yourself.
- `--records-out`: write the records from this same guarded apply.
- `--resource-dir`, `--check`: resource override, and inspect a phase without changing it.
- `LITER8_SELF`: the CLI path, exported to the Python helpers.

## Build and test

```sh
make setup
make
.build/debug/liter8 profiles
.build/debug/liter8 fw actions
```

`make test` is the edit loop. `make test-fixtures` runs the optimized exact-build verification. `make test-full` is everything optimized except the deliberately uncached production composition, which is what `make test-e2e` runs on its own. `make integration` covers the Swift-to-Python handoff. `make check` runs the lot.

Fixture-backed tests need real Apple binaries, which are not in this repo. Point `LITER8_FIXTURE_ROOT` at a private tree and they wake up; leave it unset and they skip.

Use the release build for repeated full-image scans. Debug kernelcache work is slow enough to notice.

```sh
make release
.build/release/liter8 resolve kernel restore /path/to/kernelcache.raw
```

External pieces: Capstone for ARM64 decoding, the vendored `libimg4-spm` for containers, a pinned `idevicerestore` built by `make setup`, macOS `hdiutil` and `aea` for disk images and encrypted firmware, 7-Zip for ZIP64 extraction, and Python 3 in a venv Liter8 manages itself.

## Words used here

- **Profile** is overloaded, so read which one. A *resolver profile* maps a kernel fingerprint to signature and payload variants. A *workflow profile* says this exact IPSW and board may run the full device workflow.
- **Signature variant**: masked instructions that locate a target.
- **Payload variant**: the bytes written once it is located.
- **Fixture manifest**: an exact-build oracle holding input and output hashes plus the expected records. It is checked against, never read from.
- **Plan**: a named group of related resolvers.
- **SSHRD**: the SSH-capable restore ramdisk.

## Known gaps

`fw get-boot` and `fw get-rd` rebuild far more than they need to.

Normal Apple pairing is still not lined up with the Wi-Fi and Dropbear SSH path.

Redistribution terms for the third-party binaries under `tools/` have not been audited.

## Reading order

1. `README.md`
2. `Sources/Liter8CLI/main.swift`
3. `Sources/Liter8CLI/FirmwareWorkflowRunner.swift`
4. `Sources/Liter8Core/Firmware/IPSWManifest.swift`
5. `docs/FIRMWARE_SUPPORT_GUIDE.md`
6. one folder under `Sources/Liter8Core/Resolvers`
7. `Sources/Liter8Core/Patching/GuardedPatchApplier.swift`
8. `docs/ADDING_FIRMWARE_SUPPORT.md`
9. `docs/plans/IOS_27_24A435_RC_PATCHES.md`
