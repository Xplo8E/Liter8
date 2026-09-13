# Liter8 host tools

These files were imported byte-for-byte from the public `usbliter8-fun/tools`
directory. Their original names and executable modes are preserved. Liter8
puts this directory before the host `PATH` for workflow helpers.

`make setup` generates an ignored `idevicerestore` here from the pinned
`vendor/idevicerestore` submodule. The project-specific `irecovery` remains
unmanaged until its source and build are selected.

Swift now owns IMG4/IM4P operations, so `img4` and `img4tool` are retained only
for parity with the public tool bundle. New code should not depend on them.

## Distribution status

Liter8's MIT license does not relicense these third-party files. The hashes
below identify the exact imported bytes, but hashes are not evidence of a
redistribution grant. Before the standalone repository is made public, record
an upstream source, version or commit, and license for each retained binary;
remove any file whose redistribution terms cannot be established.

## Provenance

| File | Architecture/type | SHA-256 |
| --- | --- | --- |
| `bspatch` | arm64 Mach-O | `cd94ac4f9b10b4855d4afdf38dff6bf19ef80ccb4e0486598964207e07e073b9` |
| `gtar` | x86_64 Mach-O | `185f794bce58dc25161ac445f10b46716e02e9fdec284a2373660e47aa931066` |
| `img4` | arm64 Mach-O | `58d19d8065d199f1a135eca807da77114f2a756a8a17d3447cb46fb15db56ecd` |
| `img4tool` | arm64 Mach-O | `8d3e9015cb6658fc91c24d76ff591bd1665b57af9944412b92db27f01fb5650f` |
| `kerneldiff` | x86_64 Mach-O | `a6d8d4560f4abd0708b6918656b7c7ff622cb6c2f6480433408facdf275bd9bd` |
| `ldid_macosx_arm64` | arm64 Mach-O | `ba1a681cb4ccd9ae68894b9f54b515a36e2763909546d0265686f3e0215b8f82` |
| `optool` | arm64 Mach-O | `a4f7ba296b3d6d1fc405ca2419a2d9164868e1121bfa16d8ba2b035211ad50c4` |
| `sshdev` | POSIX shell | `83ab0d0d678399d5d2cb89739c74ca840000fd0380077a0950431ad4ea0e943e` |
| `sshpass` | x86_64 Mach-O | `b1b7d11fac3c2f63ec72a021014234d3d0d1ec15433d26bd674c7c3a3fbdb310` |
| `trustcache_macos_arm64` | arm64 Mach-O | `1e3a1272b08eb86cd5e7354fb63091ba5bce8baa4fdab09b31e4330dc3531e45` |
| `usbliter8ctl` | Python/PyUSB | `5d93b4de1bbfb48db9135e35d2e94572c3db367c0d8d336140ad50d020daa275` |

The x86_64-only tools require Rosetta on Apple Silicon. `usbliter8ctl` requires
PyUSB, which Liter8 installs at its pinned version in the managed venv.
