# Liter8

Patch and boot custom iOS 27 on an iPhone 11, from a Mac. Built on the usbliter8 exploit.

![iOS](https://img.shields.io/badge/iOS-27.0%20to%2027.2%20beta%202-2ea043?style=flat-square)

<img src="./docs/iphone11-sileo.jpg" alt="iPhone 11 running patched iOS 27 with Sileo" width="760">

Two things before you go any further.

It's tethered. The phone only boots from pwn DFU with `fw boot`, so the Mac has to be there every single time. No Mac, no boot.

And it's iPhone 11 only, `n104ap`. I don't own another A13 device so that's all i'm willing to claim.

## What works

Normal boot to the home screen, root SSH, apt and Sileo, TrollStore, apps launch.

## What doesn't

- SEP
- passcode
- cellular
- Apple services
- xTweak injection. It injects, but it's nowhere near as solid as vphone
- 11 Pro and Pro Max. profiles exist but no device to test on

PRs welcome on any of these, especially SEP. The Pro and Pro Max are open too, if you own one and want to take the port on, i'll help where i can. Or if you'd rather help on the hardware side, there's a [coffee link](https://buymeacoffee.com/xplo8e) and that's what it'd go towards. Either route is fine, and so is neither.

## Builds and devices

| Firmware        | Build      | iPhone 11 | 11 Pro       | 11 Pro Max   |
| --------------- | ---------- | --------- | ------------ | ------------ |
| iOS 27.0 beta 4 | `24A5390f` | run       | -            | -            |
| iOS 27.0 RC     | `24A435`   | run       | -            | -            |
| iOS 27.0        | `24A437`   | run       | experimental | experimental |
| iOS 27.0.1      | `24A446`   | run       | experimental | experimental |
| iOS 27.2 beta 1 | `24B5084k` | run       | -            | -            |
| iOS 27.2 beta 2 | `24B5089g` | run       | -            | -            |

"Run" means i did an erase restore, booted it normally, then rebooted and it came back up. "Experimental" means unverified. It resolves and you can use it with `--experimental`, but nobody has confirmed it on that phone. If you own one and are willing to try, share what happens and i'll change the tag.

There's a catch with that table though. `fw restore-cfw` pulls a fresh APTicket from Apple while the restore is happening, so once Apple drops signing for a build you can't install it anymore. The row stays in the table because i did test it, but that doesn't mean you can still use it today. Check signing first.

Anything not in the table fails before it even gets extracted. The profiles don't carry offsets either, so adding a build isn't a matter of pasting numbers in. The resolvers work them out at runtime.

## Building it

You need macOS 14 or newer, Xcode command line tools with Swift 6, and Homebrew.

```sh
brew install \
  sevenzip blacktop/tap/ipsw gnu-tar coreutils zstd autoconf automake libtool pkg-config \
  libimobiledevice libimobiledevice-glue libirecovery libusbmuxd libplist libtatsu libzip curl
```

```sh
git clone --recurse-submodules https://github.com/Xplo8E/liter8.git
cd liter8
make setup
make release
```

Binary ends up at `.build/release/liter8`.

One thing that will catch you out: booting needs this project's `irecovery`, not whatever brew gave you. You pass it with `--irecovery` on every boot command. Yes, every one.

## Using it

Everything lands in one work directory. Set `WORK_DIR`, or pass `--work-dir`, or don't and it'll dump into whatever directory you're standing in.

Run the steps in order, every time. Each one eats the output of the one before it. Coming back to a phone days later, restart from `fw make-cfw` rather than guessing where you left off.

> [!CAUTION]
> Step 3 wipes the phone. Erase restore, everything gone, no undo. Read the IPSW path, the device, the build, the board and the work dir twice before you hit enter.

### 1. Prepare the IPSW

```sh
export WORK_DIR="$PWD/.liter8"

.build/release/liter8 fw prepare --file /path/to/firmware.ipsw
```

It gets the build out of `BuildManifest.plist` and ignores what you named the file. `IPSW_FILE` does the same job as `--file` if you'd rather set it once.

### 2. Build the CFW

```sh
.build/release/liter8 fw make-cfw
```

There's a `--serial` flag here, and on `fw get-rd` and `fw get-boot`. It writes `serial=3` into the boot args, which moves the kernel console onto the UART. Useful when you're debugging a boot that dies early. The downside is the phone screen goes quiet, no boot log on the device anymore. It's off by default, and because the literal gets baked in at build time you have to pass it separately for each artifact you build.

### 3. Restore it

Phone in pwn DFU, then:

```sh
.build/release/liter8 fw restore-cfw
```

This checks the CFW over, starts a local TSS proxy, catches the restore ticket on its way through, and shuts the proxy down once `idevicerestore` exits.

### 4. Boot the SSH ramdisk

Back to pwn DFU.

```sh
.build/release/liter8 fw get-rd
.build/release/liter8 fw boot-rd --irecovery /path/to/irecovery
```

Step 3 already dropped the ticket at `$WORK_DIR/apticket.im4m`, so skip `--ticket` here.

### 5. Provision

Phone is in SSHRD now. Run these:

```sh
.build/release/liter8 fw bootstrap --check
.build/release/liter8 fw bootstrap
.build/release/liter8 fw prepare-rootfs
.build/release/liter8 fw provision --check
.build/release/liter8 fw provision
.build/release/liter8 fw unmount-rootfs
```

### 6. Boot iOS

pwn DFU again.

```sh
.build/release/liter8 fw get-boot
.build/release/liter8 fw boot --irecovery /path/to/irecovery
```

### 7. Finish the bootstrap

Wait until you can SSH into the booted OS, then:

```sh
.build/release/liter8 fw finalize --check
.build/release/liter8 fw finalize
.build/release/liter8 fw finalize --check
```

The second `--check` is just so you can see it went through.

## How it's put together

Swift does the thinking. Works out which firmware you handed it, parses the binaries, finds the patch sites, checks the bytes are what it expected before writing over them, and deals with IMG4, IM4P, APTickets and DeviceTrees.

Python does the plumbing. Disk images, moving files into place, calling the external tools, walking the device through each stage. There are no offsets anywhere in the Python and i'd like to keep it that way.

Nothing gets written to disk until the whole patch plan has resolved and every pre-image has checked out. Half-applied patches are how you brick things.

```text
Sources/
  Liter8CLI/        arg parsing, dispatch
  Liter8Core/
    Binary/         ARM64, Mach-O, ObjC
    Firmware/       IPSW, IMG4/IM4P
    Patching/       patch records and guarded writes
    Profiles/       build to signature mapping
      Payloads/     the bytes each plan writes
    Resolvers/
      iBoot/        iBSS, iBEC, boot args, display
      Kernel/       AMFI, AKS, SEP, sandbox, boot policy
      TXM/          restore and normal boot policy
      Userland/     restore and post-boot binaries
      DeviceTree/
Tests/              same split as above
fixtures/<build>/<board>/
scripts/            host side orchestration
device/             provisioning resources
payloads/           SSHRD payload inputs
tools/              host tools, some built by setup
vendor/             pinned deps
docs/
```

It's all one Swift target. The folders are there so i can find things, nothing more.

## Rough edges

`fw get-rd` and `fw get-boot` rebuild far more than they need to. It's slow and i know it, it's on the list.

Normal Apple pairing still isn't lined up with the Wi-Fi and Dropbear SSH path that actually works. Written up in the docs.

## Docs

- [Architecture and onboarding](CODEBASE_GUIDE.md)
- [Firmware and device support guide](docs/FIRMWARE_SUPPORT_GUIDE.md)
- [iOS 27 `24A435` resolver and device evidence](docs/plans/IOS_27_24A435_RC_PATCHES.md)
- [iPhone 11 beta 4 device run](docs/runs/IOS_27_BETA4_IPHONE11.md)
- [Bootstrap and provisioning status](docs/design/BOOTSTRAP_JB_STATUS.md)
- [Normal boot handoff](docs/design/NORMAL_BOOT_HANDOFF.md)
- [Performance backlog](docs/BACKLOG.md)

## Contributing

[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). If you're porting a firmware, [docs/ADDING_FIRMWARE_SUPPORT.md](docs/ADDING_FIRMWARE_SUPPORT.md) too.

## Thanks

None of this starts without these people.

[wh1te4ever](https://github.com/wh1te4ever) and [usbliter8-fun](https://github.com/wh1te4ever/usbliter8-fun). The beta 2 and beta 3 CFW and ramdisk work is what the beta 4 port was built on top of.

[34306](https://github.com/34306/usbliter8-fun), Huy Nguyen, for the fork, the tutorial, and the original `patches/` scripts everyone was using.

[Procursus](https://github.com/ProcursusTeam) for the rootless bootstrap.

[khanhduytran0](https://github.com/khanhduytran0) for the DeviceTree and kernel USB restriction ideas.

[tihmstar](https://github.com/tihmstar) for `img4`, `img4tool`, and the APTicket based IMG4 signing work.

[m1stadev](https://github.com/m1stadev) and [doronz88](https://github.com/doronz88) for `pyimg4` and `pymobiledevice3`, which the older kernelcache and USB forwarding flows ran on.

[Lakr233](https://github.com/Lakr233) for [vphone-cli](https://github.com/Lakr233/vphone-cli). The Swift CLI shape, the firmware workflow, and the vendored IMG4 integration all came from reading that. Also `trollvnc` and the USB device control work.

## License

MIT, see [LICENSE](LICENSE). Submodules, tools and payloads keep their own licenses.