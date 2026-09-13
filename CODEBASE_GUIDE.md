# TL;DR

Liter8 is a Swift 6 CLI with a small Python orchestration layer. Swift selects
firmware profiles, parses binary formats, resolves patch locations, validates
pre-images, and produces signed artifacts. Python coordinates macOS filesystem
operations and device-facing tools.

Analyzed commit: `f25e7df` plus the current public-repository restructuring

Branch: `master`

Generated at: 2026-09-13

Confidence: High. Entry points, resolver composition, firmware workflow, tests,
and the completed iPhone 11 beta-4 run were inspected directly.

# What This Project Does

- Identifies an IPSW using `BuildManifest.plist`.
- Resolves patches from semantic binary evidence, not runtime offset tables.
- Applies patches only after checking every expected original byte.
- Builds CFW, SSHRD, and normal-boot artifacts.
- Manages restore ticket capture, device provisioning, and finalization.

# Who Uses It / Why It Exists

Liter8 is for firmware researchers extending a reviewed device workflow across
iOS builds. It replaces fixed-offset scripts with reusable resolvers while
retaining exact-build manifests as independent verification oracles.

# Tech Stack & Runtime

- Swift 6 and Swift Package Manager.
- Capstone for ARM64 decoding.
- Vendored `libimg4-spm` for IM4P and IMG4 containers.
- Python 3 in a Liter8-managed venv for host orchestration.
- macOS `hdiutil` and `aea` for disk images and encrypted firmware.
- 7-Zip for safe ZIP64 IPSW extraction.
- Pinned `idevicerestore` plus reviewed device utilities.

# Repo Layout (Human-Friendly)

| Path | Responsibility |
| --- | --- |
| `Sources/Liter8CLI` | Argument parsing and workflow dispatch |
| `Sources/Liter8Core/Binary` | ARM64, Mach-O, Objective-C, and byte primitives |
| `Sources/Liter8Core/Firmware` | IPSW, profile context, IMG4/IM4P, resources, venv |
| `Sources/Liter8Core/Patching` | Patch records, manifests, errors, guarded writes |
| `Sources/Liter8Core/Profiles` | Firmware signature and payload variants |
| `Sources/Liter8Core/Resolvers` | Component-specific patch discovery |
| `Tests/Liter8CoreTests` | Tests grouped by the same domains |
| `fixtures/<build>/<board>` | Exact-build resolver and output oracles |
| `scripts` | Generic macOS and device workflow orchestration |
| `device` | Reviewed provisioning resources |
| `payloads` | Pinned SSHRD inputs |
| `tools` | Reviewed or setup-built host tools |
| `docs` | Design notes, extension rules, and device evidence |

# Startup & Execution Flow

`Sources/Liter8CLI/main.swift` parses a top-level command. Resolver commands
load a `BinaryImage` and dispatch directly into `Liter8Core`. Firmware commands
use `FirmwareWorkflowRunner`, which writes a semantic context and then invokes
the appropriate generic workflow helper.

`fw prepare` is fully Swift-owned and does not invoke Python.

# Core Modules and Responsibilities

- `BinaryImage`: bounded reads, pattern searches, and patch input storage.
- `ARM64`: instruction decoding and control-flow helpers.
- `MachOLayout` / `ObjCMetadata`: structural userland resolution.
- `IPSWManifest`: firmware identity and reviewed workflow selection.
- `IPSWUnzip`: archive preflight, extraction, verification, and publication.
- `FirmwareArtifact` / `IMG4Signing`: native container handling.
- `FirmwareProfileRegistry`: build fingerprints and resolver variants.
- Component resolvers: produce guarded `PatchRecord` values.
- `GuardedPatchApplier`: preflights the complete plan before writing output.

# End-to-End Data / Request Flow

For a firmware build:

1. Inspect the IPSW manifest and select one exact workflow profile.
2. Extract into staging and verify the resulting inventory.
3. Map semantic component names to manifest-selected paths.
4. Resolve and guard every patch site.
5. Patch and sign artifacts into a staging set.
6. Verify complete output hashes and atomically publish the set.
7. Send the verified restore, SSHRD, or normal-boot sequence.

# Key Configs, Flags, and Environments

- `--file`, then `IPSW_FILE`: IPSW input.
- `--work-dir`, then `WORK_DIR`, then cwd: mutable state root.
- `--ticket`: explicit IM4M override.
- `--irecovery`: reviewed custom recovery transport.
- `--idevicerestore`: development-only executable override.
- `--resource-dir`: source/install resource override.
- `--check`: inspect a provisioning or finalization phase without modifying it.
- `LITER8_SELF`: exact CLI path exported to Python helpers.

# External Dependencies & Integrations

- `vendor/libimg4-spm`: pinned source dependency.
- `vendor/idevicerestore`: pinned source built by `make setup`.
- Homebrew utilities: 7-Zip, `ipsw`, GNU tar/coreutils, zstd, and
  libimobiledevice tooling.
- Apple firmware and local raw fixtures are external inputs and are not stored
  in the repository.

# How To Run, Debug, and Test

```sh
make setup
make
.build/debug/liter8 profiles
.build/debug/liter8 fw actions

make test
make integration
make test-full
```

Use the release executable for repeated full-image scans:

```sh
make release
.build/release/liter8 resolve kernel restore /path/to/kernelcache.raw
```

# ASCII Diagrams

```text
[liter8 CLI]
      |
      +-> [Binary + resolver + guarded patching]
      |
      +-> [Firmware profile + artifact handling]
                         |
                         +-> [generic Python orchestration]
                                      |
                                      +-> [macOS tools / device]
```

```text
fw prepare
  -> inspect BuildManifest
  -> select exact profile
  -> preflight archive
  -> extract to staging
  -> verify inventory and identity
  -> publish extracted tree

fw get-boot / get-rd
  -> resolve components
  -> patch guarded copies
  -> create ticket-bearing IMG4 files
  -> hash and publish one mode-bound boot set
```

# Glossary (Important Files & Symbols)

- **Profile**: reviewed firmware identity and resolver-variant selection.
- **Signature variant**: masked instructions used to locate semantic targets.
- **Payload variant**: bytes written after a site is resolved.
- **Fixture manifest**: exact-build oracle containing input/output hashes and
  expected patch records.
- **Plan**: a named composition of related resolvers.
- **SSHRD**: the SSH-capable restore ramdisk environment.

# Unknowns / Open Questions

- The new SSHRD display/backlight handoff has focused test coverage but still
  needs an exact-device visual confirmation.
- `fw get-boot` and `fw get-rd` need incremental caching.
- Normal Apple pairing is not part of the verified Wi-Fi/Dropbear SSH path.
- Firmware beyond the complete beta-4 n104 workflow remains partial research.
- Third-party binary and payload redistribution terms still need auditing.

# Suggested Next Reading Path

1. `README.md`
2. `Sources/Liter8CLI/main.swift`
3. `Sources/Liter8CLI/FirmwareWorkflowRunner.swift`
4. `Sources/Liter8Core/Firmware/IPSWManifest.swift`
5. One folder under `Sources/Liter8Core/Resolvers`
6. `Sources/Liter8Core/Patching/GuardedPatchApplier.swift`
7. `docs/ADDING_FIRMWARE_SUPPORT.md`
8. `docs/runs/IOS_27_BETA4_IPHONE11.md`
