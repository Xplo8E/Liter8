# Liter8

Liter8 is a macOS firmware research CLI for resolving, verifying, applying, and
booting reviewed iOS patch sets. It identifies firmware from
`BuildManifest.plist`, discovers patch sites from binary structure and semantic
anchors, verifies every original byte, and refuses unknown or ambiguous input.

The first end-to-end supported target is iPhone 11 (`iPhone12,1`, `n104ap`) on
iOS 27.0 beta 4 (`24A5390f`). That workflow has been exercised on a physical
device through IPSW preparation, CFW restore, SSH restore ramdisk, device
provisioning, normal boot, and post-boot finalization.

Liter8 is profile-driven. Supporting a new build means adding reviewed
signatures, payload variants, manifests, and exact-device evidence. It does not
mean copying a build-specific workflow or falling back to known offsets.

## Current support

| Firmware | Device | Status |
| --- | --- | --- |
| iOS 27 beta 4, `24A5390f` | iPhone 11, `n104ap` | End-to-end verified |
| iOS 27 beta 2, `24A5370h` | `d421ap` / `d431ap` | Credential-manager resolver reference only |
| iOS 27, `24A435` | iPhone 11, `n104ap` | Registered as pending research |

An unsupported IPSW fails before extraction. A recognized firmware profile
never supplies patch offsets; offsets remain outputs of the resolvers.

## What Liter8 owns

- IPSW identity checks and safe ZIP64 extraction.
- Semantic component selection from `BuildManifest.plist`.
- ARM64, Mach-O, Objective-C, iBoot, kernel, TXM, and userland resolution.
- Guarded patch application with complete pre-image verification.
- Native Swift IM4P, IMG4, APTicket, and DeviceTree handling.
- CFW, normal-boot, and SSHRD artifact construction.
- Managed TSS proxy lifecycle during restore.
- Reviewed bootstrap, provisioning, and first-boot finalization.

Swift owns firmware parsing and patch decisions. Generic Python scripts remain
only for host orchestration such as disk-image mounting, file staging, tool
execution, and device workflow sequencing. They contain no build-specific
offset tables.

```text
IPSW
  -> Swift manifest/profile selection
  -> Swift extraction and component mapping
  -> Swift semantic resolvers
  -> guarded patch application
  -> IMG4/IM4P signing and verification
  -> Python host/device orchestration
  -> CFW, SSHRD, or normal-boot artifacts
```

## Requirements

- macOS 14 or newer.
- Xcode Command Line Tools with Swift 6.
- Homebrew `7zz`, `ipsw`, GNU tar, GNU coreutils, `zstd`, and
  `libimobiledevice` tools.
- Autoconf, Automake, Libtool, `pkg-config`, and the libraries required to build
  the pinned `idevicerestore` submodule.
- A reviewed project-specific `irecovery` binary for device boot commands.
- A supported IPSW supplied locally. Apple firmware files are not stored here.

`make setup` initializes submodules, builds the pinned `idevicerestore`, and
creates Liter8's isolated Python environment. It does not install dependencies
globally.

## Build

Clone recursively, then prepare the tools and build Liter8:

```sh
git clone --recurse-submodules https://github.com/Xplo8E/liter8.git
cd liter8

make setup
make release
```

For development, `make` builds the debug binary. Invoke the built executable
directly so repeated commands do not pay SwiftPM startup costs:

```sh
.build/debug/liter8
.build/release/liter8
```

Useful build targets:

```sh
make              # Debug build
make release      # Optimized build
make test         # Responsive suite; skips full kernel scans
make test-full    # Optimized full resolver suite
make integration  # Host workflow integration tests
make check        # Full tests and integrations
make clean        # Remove SwiftPM build products
```

Tests that require locally extracted Apple binaries skip when those files are
absent. Set `LITER8_FIXTURE_ROOT` to a private fixture tree containing paths
such as `offsets/kc/kc_b4_n104.raw`; the binaries are never copied into Liter8.

## Firmware workflow

Use one work directory for all mutable state. `--work-dir` wins over
`WORK_DIR`; otherwise Liter8 uses the current directory.

```sh
export WORK_DIR="$PWD/.liter8"

.build/release/liter8 fw prepare --file /path/to/firmware.ipsw
.build/release/liter8 fw make-cfw
```

`fw prepare` identifies the firmware from its plist metadata. The IPSW filename
is not trusted. `IPSW_FILE` may be used instead of `--file`.

The restore command performs an erase restore. It verifies the CFW, starts a
loopback TSS proxy, captures the restore-bound APTicket, invokes the pinned
`idevicerestore`, and always stops the proxy afterward:

```sh
.build/release/liter8 fw restore-cfw
```

After placing the device back in pwn DFU, build and boot the SSH restore
environment:

```sh
.build/release/liter8 fw get-rd
.build/release/liter8 fw boot-rd --irecovery /path/to/custom/irecovery
```

While the phone is in SSHRD:

```sh
.build/release/liter8 fw bootstrap --check
.build/release/liter8 fw bootstrap

.build/release/liter8 fw prepare-rootfs
.build/release/liter8 fw provision --check
.build/release/liter8 fw provision
.build/release/liter8 fw unmount-rootfs
```

Return the phone to pwn DFU, then build and send the normal boot chain:

```sh
.build/release/liter8 fw get-boot
.build/release/liter8 fw boot --irecovery /path/to/custom/irecovery
```

Once normal-boot SSH is available, finish the bootstrap and verify the result:

```sh
.build/release/liter8 fw finalize --check
.build/release/liter8 fw finalize
.build/release/liter8 fw finalize --check
```

Every generated boot set is mode-bound and hash-verified. `fw boot` rejects
SSHRD output, and `fw boot-rd` rejects normal-boot output.

## Resolver commands

Inspect available components and plans:

```sh
.build/release/liter8
.build/release/liter8 profiles
.build/release/liter8 fw actions
```

Resolve without modifying the input:

```sh
.build/release/liter8 resolve kernel restore /path/to/kernelcache.raw
.build/release/liter8 resolve iboot ibss-normal /path/to/iBSS.raw --json
```

Write a separately patched output:

```sh
.build/release/liter8 apply \
  kernel restore \
  /path/to/kernelcache.raw \
  /path/to/kernelcache.patched
```

Verify an exact-build oracle:

```sh
.build/release/liter8 verify \
  fixtures/24A5390f/n104ap/kernel-restore-n104-24A5390f.json \
  /path/to/kernelcache.raw
```

Known offsets in fixture manifests are verification oracles only. Resolution
fails if semantic evidence is missing, duplicated, or inconsistent.

## Repository layout

```text
Sources/
  Liter8CLI/                 CLI parsing and workflow dispatch
  Liter8Core/
    Binary/                  ARM64, Mach-O and Objective-C analysis
    Firmware/                IPSW, IMG4/IM4P and runtime resources
    Patching/                patch records, manifests and guarded writes
    Profiles/                build-to-signature and payload selection
    Resolvers/
      iBoot/                 iBSS, iBEC, boot arguments and display
      Kernel/                AMFI, AKS, SEP, sandbox and boot policy
      TXM/                   TXM restore and normal-boot policy
      Userland/              restore and post-boot binaries
      DeviceTree/            structural DeviceTree plans
Tests/Liter8CoreTests/       tests grouped by the same domains
fixtures/<build>/<board>/    exact-build verification manifests
scripts/                     generic host workflow orchestration
device/                      reviewed device provisioning resources
payloads/                    pinned SSHRD payload inputs
tools/                       reviewed or setup-built host tools
vendor/                      pinned source dependencies
docs/                        design notes and exact-device run evidence
```

This remains one `Liter8Core` Swift target. The folders express ownership
without adding artificial target boundaries or widening internal APIs.

## Adding firmware support

Read [docs/ADDING_FIRMWARE_SUPPORT.md](docs/ADDING_FIRMWARE_SUPPORT.md). The
short version is:

1. Record an immutable build and board identity.
2. Add or reuse reviewed signature and payload variants.
3. Resolve sites semantically; never add an offset fallback.
4. Add manifests under `fixtures/<build>/<board>/`.
5. Prove wrong-input and ambiguity failures.
6. Compare complete patched-image hashes against an independent implementation.
7. Record exact-device behavior before calling the workflow supported.

## Documentation

- [Architecture and onboarding](CODEBASE_GUIDE.md)
- [Adding firmware support](docs/ADDING_FIRMWARE_SUPPORT.md)
- [iPhone 11 beta-4 device run](docs/runs/IOS_27_BETA4_IPHONE11.md)
- [Bootstrap and provisioning status](docs/design/BOOTSTRAP_JB_STATUS.md)
- [Normal boot handoff](docs/design/NORMAL_BOOT_HANDOFF.md)
- [Performance backlog](docs/BACKLOG.md)

## Project status

The beta-4 iPhone 11 path works end to end. The next engineering priority is
incremental caching for `fw get-rd` and `fw get-boot`; both currently rebuild
more artifacts than necessary. Normal Apple pairing also remains separate from
the verified Wi-Fi and Dropbear SSH path.

Binary firmware fixtures and generated work directories are intentionally not
committed.

## Acknowledgements

Liter8 builds on research and tooling published by the following projects and
contributors:

- [usbliter8-fun](https://github.com/wh1te4ever/usbliter8-fun) by
  [wh1te4ever](https://github.com/wh1te4ever), whose iOS 27 beta 2 and beta 3
  CFW and ramdisk work formed the base of the iPhone 11 beta-4 port.
- [34306](https://github.com/34306/usbliter8-fun) (Huy Nguyen) for the fork, tutorial, and
  original `patches/` scripts used by the public workflow.
- [Procursus](https://github.com/ProcursusTeam) for the rootless bootstrap.
- [khanhduytran0](https://github.com/khanhduytran0) for the DeviceTree and
  kernel USB-restriction ideas.
- [tihmstar](https://github.com/tihmstar) for `img4` and `img4tool` and their
  APTicket-based IMG4 signing work.
- [m1stadev](https://github.com/m1stadev) and
  [doronz88](https://github.com/doronz88) for `pyimg4` and
  `pymobiledevice3`, used by the earlier kernelcache and USB forwarding flows.
- [Lakr233](https://github.com/Lakr233) for
  [vphone-cli](https://github.com/Lakr233/vphone-cli), whose Swift CLI,
  firmware workflow structure, and vendored IMG4 integration informed Liter8,
  and for `trollvnc` and USB device-control work.

## License

Liter8's original source is available under the [MIT License](LICENSE). Third-party submodules, tools, and
payloads remain subject to their respective licenses and distribution terms.
