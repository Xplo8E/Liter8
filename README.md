<h1 align="center">Liter8</h1>

<p align="center">
A macOS CLI for the usbliter8 firmware patching and boot workflow.
</p>

> [!WARNING]
> Liter8 is under active development. Support is exact-build and exact-device scoped; an unlisted IPSW or board is not implicitly compatible.

Liter8 provides a unified CLI for preparing IPSWs, resolving and applying firmware patches, building custom firmware, restoring devices, booting SSH restore ramdisks, provisioning the filesystem, and generating patched normal-boot artifacts.

The project replaces build-specific patch scripts and hardcoded offsets with profile-driven firmware support and semantic patch resolution. Firmware-specific differences are isolated through reviewed resolver and payload variants, while exact-build fixtures are used to verify patch output.

## Tested on

| Firmware                    | Device              | Status              |
| --------------------------- | ------------------- | ------------------- |
| iOS 27 beta 4, `24A5390f`   | iPhone 11, `n104ap` | End-to-end verified |
| iOS 27 RC/release, `24A435` | iPhone 11, `n104ap` | End-to-end verified |

An unsupported IPSW fails before extraction. A recognized firmware profile never supplies patch offsets; offsets remain outputs of the resolvers.

The temporary SSHRD workflow was additionally verified against an untouched stock installation: the device booted the ramdisk, served SSH with no volume mounted, and returned to the original iOS after a reboot. No restore was performed.

> [!NOTE]
> IPSWs, extracted Apple binaries, tickets, and generated work directories are not included in this repository.

## Install and build

Liter8 requires macOS 14 or newer, Xcode Command Line Tools with Swift 6, and Homebrew. Install the host dependencies:

```sh
brew install \
  sevenzip blacktop/tap/ipsw gnu-tar coreutils zstd autoconf automake libtool pkg-config \
  libimobiledevice libimobiledevice-glue libirecovery libusbmuxd libplist libtatsu libzip curl
```

Clone, prepare the pinned tools, and build the release executable:

```sh
git clone --recurse-submodules https://github.com/Xplo8E/liter8.git
cd liter8
make setup
make release
```

The executable is `.build/release/liter8`. Device boot also requires the reviewed project-specific `irecovery`; pass its path with `--irecovery`.

## Usage

Keep every generated file under one work directory. `--work-dir` overrides `WORK_DIR`; without either, Liter8 uses the current directory.

Every workflow starts by preparing the IPSW:

```sh
export WORK_DIR="$PWD/.liter8"

.build/release/liter8 fw prepare --file /path/to/firmware.ipsw
```

`fw prepare` identifies the build from `BuildManifest.plist`; the IPSW filename is ignored. Set `IPSW_FILE` if you do not want to pass `--file`.

### Two workflows

Everything after `fw prepare` belongs to one of two workflows. They share the prepared IPSW and nothing else. Choose deliberately.

|                      | [Temporary SSHRD](#temporary-sshrd-non-destructive) | [Custom firmware](#custom-firmware-destructive) |
| -------------------- | --------------------------------------------------- | ----------------------------------------------- |
| What it does         | Boots an SSH ramdisk in RAM over the installed OS    | Erases the device and installs a patched OS     |
| Data on the device   | Untouched                                            | Destroyed                                       |
| After a reboot       | The original OS boots as before                      | The custom firmware boots                       |
| Commands             | `fw get-rd`, `fw boot-rd`                            | `fw make-cfw`, `fw restore-cfw`, then provisioning |
| Needs Apple's TSS    | No                                                   | Yes                                             |


## Temporary SSHRD (non-destructive)

Boots Apple's restore ramdisk with an SSH server injected into it, over whatever is already installed. The ramdisk runs entirely in RAM, no volume is mounted, and the installed OS boots normally afterwards.

This needs an APTicket. `fw get-rd` reads `$WORK_DIR/apticket.im4m` by default, or takes an explicit path.

```sh
# device in pwn DFU
.build/release/liter8 fw get-rd --ticket /path/to/apticket.im4m
.build/release/liter8 fw boot-rd --irecovery /path/to/custom/irecovery
```

Once the chain has booted, forward the SSH port and connect:

```sh
iproxy 2222 22 &
ssh -p 2222 root@localhost
```

Reboot the device to return to the installed OS.

> [!NOTE]
> This chain boots through a patched iBSS and iBEC whose Image4 validation is deliberately bypassed, so `fw get-rd` accepts any APTicket that parses as an IM4M. Ticket freshness is not required for this path. Liter8 has no command yet for obtaining a first APTicket for a device you hold none for.

## Custom firmware (destructive)

> [!WARNING]
> Step 2 erases the device. Check the selected IPSW, device, build, board, and work directory before running it.

> [!CAUTION]
> `fw restore-cfw` performs an erase restore and destroys everything on the target device. If you only want a shell on the OS that is already installed, do not run it. Use the temporary SSHRD workflow.

### 1. Build the CFW

```sh
.build/release/liter8 fw make-cfw
```

### 2. Restore the CFW

Put the device in pwn DFU, then run:

```sh
.build/release/liter8 fw restore-cfw
```

Liter8 verifies the CFW, manages the local TSS proxy, captures the restore-bound APTicket, and stops the proxy when `idevicerestore` exits.

### 3. Boot the SSH restore ramdisk

Return the device to pwn DFU:

```sh
.build/release/liter8 fw get-rd
.build/release/liter8 fw boot-rd --irecovery /path/to/custom/irecovery
```

The ticket captured by step 2 is now at `$WORK_DIR/apticket.im4m`, so `--ticket` is not needed here.

### 4. Provision the restored system

Run these while the device is in SSHRD:

```sh
.build/release/liter8 fw bootstrap --check
.build/release/liter8 fw bootstrap
.build/release/liter8 fw prepare-rootfs
.build/release/liter8 fw provision --check
.build/release/liter8 fw provision
.build/release/liter8 fw unmount-rootfs
```

### 5. Boot iOS

Return the device to pwn DFU:

```sh
.build/release/liter8 fw get-boot
.build/release/liter8 fw boot --irecovery /path/to/custom/irecovery
```

### 6. Finalize the bootstrap

After normal-boot SSH becomes available:

```sh
.build/release/liter8 fw finalize --check
.build/release/liter8 fw finalize
.build/release/liter8 fw finalize --check
```

## Resolver-only commands

These belong to neither workflow and never touch a device.

List available profiles and plans:

```sh
.build/release/liter8 profiles
.build/release/liter8 fw actions
```

Resolve a patch plan without changing the input:

```sh
.build/release/liter8 resolve kernel restore /path/to/kernelcache.raw
.build/release/liter8 resolve iboot ibss-normal /path/to/iBSS.raw --json
```

Apply a plan to a separate output:

```sh
.build/release/liter8 apply \
  kernel restore \
  /path/to/kernelcache.raw \
  /path/to/kernelcache.patched
```

Verify against an exact-build fixture:

```sh
.build/release/liter8 verify \
  fixtures/24A5390f/n104ap/kernel-restore-n104-24A5390f.json \
  /path/to/kernelcache.raw
```

> [!IMPORTANT]
> Fixture offsets verify resolver output. Runtime resolution never uses them as fallbacks.

## How Liter8 works

- Swift identifies firmware, parses binaries, resolves patch locations, validates pre-images, and handles IMG4, IM4P, APTickets, and DeviceTrees.
- Python coordinates macOS disk images, file staging, external tools, and device workflow steps. It contains no build-specific offset tables.
- Every patch plan resolves and validates completely before Liter8 writes an output.

```text
IPSW
  -> manifest and profile selection
  -> component extraction
  -> semantic resolution
  -> guarded patching
  -> IMG4/IM4P signing and verification
  -> CFW, SSHRD, or normal-boot artifacts
```

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

This remains one `Liter8Core` Swift target. The folders express ownership without adding artificial target boundaries or widening internal APIs.

## Contributing

Read [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) before changing resolvers or workflows. Firmware ports also use the checklist in [docs/ADDING_FIRMWARE_SUPPORT.md](docs/ADDING_FIRMWARE_SUPPORT.md).

- Keep patch discovery and patch bytes in Swift.
- Keep build-specific differences in profiles, signatures, and payloads.
- Explain every opcode and raw byte sequence in a nearby comment.
- Use fixture offsets only as verification oracles.
- Include wrong-input and ambiguity tests.
- Record a physical-device run before claiming end-to-end support.

## Running tests

```sh
make test           # Fast suite; skips real-kernel fixture scans
make test-fixtures  # Optimized exact-build fixture and one-pass apply checks
make integration    # Host workflow integration tests
make test-full      # Optimized suite except the uncached production composition
make test-e2e       # Uncached production-composition resolver test
make check          # Full resolver, E2E, and integration tiers
```

Tests that need extracted Apple binaries skip when those files are absent. Use `LITER8_FIXTURE_ROOT` to point at a private fixture tree:

```sh
LITER8_FIXTURE_ROOT=/path/to/private/research make test-full
```

## Documentation

- [Architecture and onboarding](CODEBASE_GUIDE.md)
- [Contributor guide](docs/CONTRIBUTING.md)
- [Firmware and device support guide](docs/FIRMWARE_SUPPORT_GUIDE.md)
- [Adding firmware support](docs/ADDING_FIRMWARE_SUPPORT.md)
- [iOS 27 `24A435` resolver and device evidence](docs/plans/IOS_27_24A435_RC_PATCHES.md)
- [iPhone 11 beta-4 device run](docs/runs/IOS_27_BETA4_IPHONE11.md)
- [Bootstrap and provisioning status](docs/design/BOOTSTRAP_JB_STATUS.md)
- [Normal boot handoff](docs/design/NORMAL_BOOT_HANDOFF.md)
- [Performance backlog](docs/BACKLOG.md)

> [!NOTE]
> `fw get-rd` and `fw get-boot` currently rebuild more artifacts than needed. Normal Apple pairing also remains separate from the verified Wi-Fi and Dropbear SSH path. Both items are tracked in the project documentation.

## Acknowledgements

Liter8 builds on research and tooling published by the following projects and contributors:

- [usbliter8-fun](https://github.com/wh1te4ever/usbliter8-fun) by [wh1te4ever](https://github.com/wh1te4ever), whose iOS 27 beta 2 and beta 3 CFW and ramdisk work formed the base of the iPhone 11 beta-4 port.
- [34306](https://github.com/34306/usbliter8-fun) (Huy Nguyen) for the fork, tutorial, and original `patches/` scripts used by the public workflow.
- [Procursus](https://github.com/ProcursusTeam) for the rootless bootstrap.
- [khanhduytran0](https://github.com/khanhduytran0) for the DeviceTree and kernel USB-restriction ideas.
- [tihmstar](https://github.com/tihmstar) for `img4` and `img4tool` and their APTicket-based IMG4 signing work.
- [m1stadev](https://github.com/m1stadev) and [doronz88](https://github.com/doronz88) for `pyimg4` and `pymobiledevice3`, used by the earlier kernelcache and USB forwarding flows.
- [Lakr233](https://github.com/Lakr233) for [vphone-cli](https://github.com/Lakr233/vphone-cli), whose Swift CLI, firmware workflow structure, and vendored IMG4 integration informed Liter8, and for `trollvnc` and USB device-control work.

## License

Liter8's original source is available under the [MIT License](LICENSE). Third-party submodules, tools, and payloads remain subject to their respective licenses and distribution terms.
