# TL;DR

Liter8 is a Swift 6 CLI with a small Python orchestration layer. Swift selects firmware profiles, parses binary formats, resolves patch locations, validates pre-images, and produces signed artifacts. Python coordinates macOS filesystem operations and device-facing tools.

Analyzed state: current public working tree, including the iOS 27 `24A435` port

Branch: `main`

Generated at: 2026-09-14

Confidence: High. Entry points, resolver composition, firmware workflows, fixtures, tests, and physical-device results for iPhone 11 on iOS 27 beta 4 and `24A435` were inspected directly.

# What This Project Does

- Identifies an IPSW using `BuildManifest.plist`.
- Resolves patches from semantic binary evidence, not runtime offset tables.
- Applies patches only after checking every expected original byte.
- Builds CFW, SSHRD, and normal-boot artifacts.
- Manages restore ticket capture, device provisioning, and finalization.

# Who Uses It / Why It Exists

Liter8 is for firmware researchers extending a reviewed device workflow across iOS builds. It replaces fixed-offset scripts with reusable resolvers while retaining exact-build manifests as independent verification oracles.

# Reviewed Workflows

| Firmware | Product / board | Evidence |
| --- | --- | --- |
| iOS 27 beta 4, `24A5390f` | `iPhone12,1` / `n104ap` | CFW restore, APTicket capture, SSHRD, provisioning, normal boot, finalization, and repeat boot |
| iOS 27 RC/release, `24A435` | `iPhone12,1` / `n104ap` | CFW restore, APTicket capture, SSHRD, provisioning, normal boot, Procursus finalization, Dropbear, persona/icon services, wallpaper repair, and repeat boot |

Both entries are `.reviewed` in `DeviceWorkflowRegistry` and run without `--experimental`. Resolver profiles for other artifacts do not imply that their complete device workflows are supported.

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
| `Sources/Liter8Core/Binary` | ARM64, Mach-O, Objective-C, byte primitives, and read-only inspection |
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
| `docs` | Contributor guidance, firmware-port procedure, retained research, and device evidence |

# Startup & Execution Flow

`Sources/Liter8CLI/main.swift` parses a top-level command. Resolver and inspection commands load a `BinaryImage` and dispatch directly into `Liter8Core`. Firmware commands use `FirmwareWorkflowRunner`, which writes a semantic context and then invokes the appropriate generic workflow helper.

`fw prepare` is fully Swift-owned and does not invoke Python.

# Core Modules and Responsibilities

- `BinaryImage`: bounded reads, pattern searches, and patch input storage.
- `ARM64`: instruction decoding and control-flow helpers.
- `BinaryInspector`: read-only segments, strings, xrefs, functions, calls, disassembly, Objective-C methods, and masked-pattern diagnostics used while developing resolvers.
- `MachOLayout` / `ObjCMetadata`: structural userland resolution.
- `IPSWManifest`: firmware identity and reviewed workflow selection.
- `IPSWUnzip`: archive preflight, extraction, verification, and publication.
- `FirmwareArtifact` / `IMG4Signing`: native container handling.
- `KernelResolverProfileRegistry`: embedded kernel fingerprints and build-specific signature or payload variants. It never stores resolved offsets.
- `DeviceWorkflowRegistry`: exact IPSW identity, component mapping guards, boot-plan additions, and reviewed versus experimental workflow status.
- Component resolvers: produce guarded `PatchRecord` values.
- `GuardedPatchApplier`: preflights the complete plan before writing output.

# End-to-End Data / Request Flow

For a firmware build:

1. Inspect the IPSW manifest and select one exact workflow profile.
2. Extract into staging and verify the resulting inventory.
3. Map semantic component names to manifest-selected paths.
4. Resolve and guard every patch site. When evidence is requested, `apply --records-out` emits records from this same operation instead of running the resolver a second time.
5. Patch and sign artifacts into a staging set.
6. Verify complete output hashes and atomically publish the set.
7. Send the verified restore, SSHRD, or normal-boot sequence.

# Key Configs, Flags, and Environments

- `--file`, then `IPSW_FILE`: IPSW input.
- `--work-dir`, then `WORK_DIR`, then cwd: mutable state root.
- `--experimental`: explicitly opt into a workflow profile that has not completed device validation.
- `--ticket`: explicit IM4M override.
- `--irecovery`: reviewed custom recovery transport.
- `--idevicerestore`: development-only executable override.
- `--rootfs`: explicit mounted root filesystem for provisioning.
- `--records-out`: write patch records produced by the same guarded `apply` operation.
- `--resource-dir`: source/install resource override.
- `--check`: inspect a provisioning or finalization phase without modifying it.
- `LITER8_SELF`: exact CLI path exported to Python helpers.

# External Dependencies & Integrations

- `vendor/libimg4-spm`: pinned source dependency.
- `vendor/idevicerestore`: pinned source built by `make setup`.
- Homebrew utilities: 7-Zip, `ipsw`, GNU tar/coreutils, zstd, and libimobiledevice tooling.
- Apple firmware and local raw fixtures are external inputs and are not stored in the repository.

# How To Run, Debug, and Test

```sh
make setup
make
.build/debug/liter8 profiles
.build/debug/liter8 fw actions

make test
make test-fixtures
make integration
make test-full
make test-e2e
make check
```

`make test` is the fast edit loop. `make test-fixtures` runs optimized exact-build fixture verification and the one-pass apply checks. `make test-full` runs the optimized suite except the deliberately uncached production composition. `make test-e2e` runs that composition, and `make check` combines the full resolver, E2E, and integration tiers. Set `LITER8_FIXTURE_ROOT` to the private research tree containing extracted Apple binaries when running fixture-backed tests.

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
  -> select the exact firmware and device boot plan
  -> resolve and patch guarded copies in one pass
  -> retain patch records from that same apply operation
  -> create ticket-bearing IMG4 files
  -> hash and publish one mode-bound boot set
```

# Glossary (Important Files & Symbols)

- **Profile**: reviewed firmware identity and resolver-variant selection.
- **Signature variant**: masked instructions used to locate semantic targets.
- **Payload variant**: bytes written after a site is resolved.
- **Fixture manifest**: exact-build oracle containing input/output hashes and expected patch records.
- **Reviewed workflow profile**: exact IPSW/device mapping that completed restore, SSHRD, provisioning, normal boot, finalization, and repeat-boot validation.
- **Experimental workflow profile**: mapped firmware that remains gated behind `--experimental` until the same device evidence exists.
- **Plan**: a named composition of related resolvers.
- **SSHRD**: the SSH-capable restore ramdisk environment.

# Unknowns / Open Questions

- `fw get-boot` and `fw get-rd` need incremental caching.
- Normal Apple pairing is not part of the verified Wi-Fi/Dropbear SSH path.
- Third-party binary and payload redistribution terms still need auditing.

# Suggested Next Reading Path

1. `README.md`
2. `Sources/Liter8CLI/main.swift`
3. `Sources/Liter8CLI/FirmwareWorkflowRunner.swift`
4. `Sources/Liter8Core/Firmware/IPSWManifest.swift`
5. `docs/FIRMWARE_SUPPORT_GUIDE.md`
6. One folder under `Sources/Liter8Core/Resolvers`
7. `Sources/Liter8Core/Patching/GuardedPatchApplier.swift`
8. `docs/ADDING_FIRMWARE_SUPPORT.md`
9. `docs/plans/IOS_27_24A435_RC_PATCHES.md`
10. `docs/runs/IOS_27_BETA4_IPHONE11.md`
