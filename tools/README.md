# Liter8 host tools

What is left here after the unused imports were removed. The bundled `ldid` is
arm64 and the bundled `gtar` and `sshpass` are x86_64, so one of the two Mac
architectures always needs Rosetta or a native replacement. See
https://github.com/Xplo8E/Liter8/issues/2.

`usbliter8ctl` is the one tool with no substitute. `sshdev` is a convenience
script for reading device logs by hand, not part of any workflow. `sshpass` is
no longer called at all: `device/askpass-sshpass` replaced it, and every call
site names that shim by path.

`logdev` streams the device's unified log through `sshdev`. A normally booted
device has no `/usr/bin/log`, so the reader it runs is installed on the device
as `/var/root/oslog` by `liter8 fw provision`; the binary it runs is the
`payloads/oslog` resource, documented there. `LITER8_DEVICE_OSLOG` overrides
the remote path.

`make setup` generates an ignored `idevicerestore` here from the pinned
`vendor/idevicerestore` submodule. The project-specific `irecovery` remains
unmanaged until its source and build are selected.

## How callers resolve these

**This directory comes first on `PATH`, not last.**
`Sources/Liter8CLI/FirmwareScriptRunner.swift` prepends it for every Python
helper and `scripts/device_provision.py` prepends a symlink copy of it for
every `device/` shell script. That is load-bearing for `idevicerestore`: the
pinned build here has to beat an unrelated `/usr/local/bin/idevicerestore`
during an erase restore. It is the opposite of what `gtar` and `sshpass` want,
and no single ordering satisfies both.

So **ordering is not the guard, runnability is.** A tool resolved by name has
to be executed before it is trusted: the executable bit is set on a
wrong-architecture binary and on one whose dynamic libraries have moved, and
both fail far later with nothing but "Bad CPU type in executable". Three
implementations of that check exist, one per language:

| Layer | Resolver |
| --- | --- |
| Swift | `HostTool.locate(_:requiringRunnable:)`, used by `Preflight` |
| Python | `liter8_workflow.runnable_tool` |
| Shell | the `GTAR` and `LDID` probes at the top of `device/sshrd_provision.sh` |

All three search `PATH` and then `/opt/homebrew/bin` and `/usr/local/bin`,
because Homebrew sits at a different prefix on Apple Silicon and Intel and the
inherited `PATH` carries neither when Liter8 is launched outside a login
shell. Those two prefixes have to stay in step across the three: a tool
`Preflight` reports as runnable that a helper cannot find is the same late
failure the runnability check exists to prevent.

A new caller that resolves a tool by name uses its layer's resolver. A plain
`shutil.which`, `command -v` or `-x` test will pick the x86_64 `gtar` here
ahead of a working Homebrew one.

## Removed

`bspatch`, `img4`, `img4tool`, `kerneldiff`, `optool` and
`trustcache_macos_arm64` came over with the original `usbliter8-fun/tools`
import and nothing ever called them. `img4tool` was the last to go: it
extracted the APTicket until `liter8 img4 extract-manifest` replaced it. Git
history has them if one is ever needed again.

## Distribution status

Liter8's MIT license does not relicense these third-party files. The hashes
below identify the exact imported bytes, but hashes are not evidence of a
redistribution grant. Before the standalone repository is made public, record
an upstream source, version or commit, and license for each retained binary;
remove any file whose redistribution terms cannot be established.

Three binaries remain to account for, down from nine, and all three are
replaceable with a Homebrew package rather than relicensed.

## Provenance

| File | Architecture/type | SHA-256 |
| --- | --- | --- |
| `gtar` | x86_64 Mach-O | `185f794bce58dc25161ac445f10b46716e02e9fdec284a2373660e47aa931066` |
| `ldid_macosx_arm64` | arm64 Mach-O | `ba1a681cb4ccd9ae68894b9f54b515a36e2763909546d0265686f3e0215b8f82` |
| `logdev` | Python | `e7bf8896329194f5f3d1fa6282d9c9f2549b5b6944b640412d41873501844cb0` |
| `sshdev` | POSIX shell | `83ab0d0d678399d5d2cb89739c74ca840000fd0380077a0950431ad4ea0e943e` |
| `sshpass` | x86_64 Mach-O | `b1b7d11fac3c2f63ec72a021014234d3d0d1ec15433d26bd674c7c3a3fbdb310` |
| `usbliter8ctl` | Python/PyUSB | `5d93b4de1bbfb48db9135e35d2e94572c3db367c0d8d336140ad50d020daa275` |

`usbliter8ctl` requires PyUSB, which Liter8 installs at its pinned version in
the managed venv.
