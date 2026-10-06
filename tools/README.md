# Liter8 host tools

What is left here after the unused imports were removed. `gtar`, `ldid` and
`sshpass` are fallbacks only: every caller resolves the tool from `PATH` first,
so install them with Homebrew and these copies go unused. They exist because
the bundled `ldid` is arm64 and the bundled `gtar` and `sshpass` are x86_64,
which means one of the two Mac architectures always needs Rosetta or a native
replacement. See https://github.com/Xplo8E/Liter8/issues/2.

`usbliter8ctl` is the one tool with no substitute. `sshdev` is a convenience
script for reading device logs by hand, not part of any workflow.

`make setup` generates an ignored `idevicerestore` here from the pinned
`vendor/idevicerestore` submodule. The project-specific `irecovery` remains
unmanaged until its source and build are selected.

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
| `sshdev` | POSIX shell | `83ab0d0d678399d5d2cb89739c74ca840000fd0380077a0950431ad4ea0e943e` |
| `sshpass` | x86_64 Mach-O | `b1b7d11fac3c2f63ec72a021014234d3d0d1ec15433d26bd674c7c3a3fbdb310` |
| `usbliter8ctl` | Python/PyUSB | `5d93b4de1bbfb48db9135e35d2e94572c3db367c0d8d336140ad50d020daa275` |

`usbliter8ctl` requires PyUSB, which Liter8 installs at its pinned version in
the managed venv.
