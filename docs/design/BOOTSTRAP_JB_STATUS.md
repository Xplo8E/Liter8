# Bootstrap and jailbreak migration status

This audit compares Liter8 with the public iPhone 11 iOS 27 beta 4 workflow in
`usbliter8-fun/work-27.0b4-n104`. It separates firmware construction from the
steps that mutate or configure a restored device.

## Already owned by Liter8

- IPSW identification and extraction.
- CFW, normal-boot and SSHRD artifact construction.
- Swift patch resolution, guarded application, IM4P and IMG4 packaging.
- The reviewed `ssh.tar.gz` restore payload. Liter8 verifies SHA-256
  `ddfa230acd2789c7e61ddb0d2ec3df9a6c741f2ddcab58fc1a826d278be1d74d`
  before mounting the ramdisk.
- `sftp_server_ents.plist`, used when re-signing the SSHRD sftp server.

## Core device phases now exposed by Liter8

These are required for feature parity, not optional research utilities:

1. `bootstrap`: verify and transfer `bootstrap_1900.tar.zst`, preserve
   symlinks, ownership and setuid modes, and install it as `/var/jb` from
   SSHRD.
2. `provision`: mount System, Data and Preboot from SSHRD; recover the
   restore-bound APTicket; patch Setup; deploy dropbear, the launchd service
   cache, injection payloads, boot helpers, Sileo and DNS state; then verify
   read-back hashes.
3. `setup-shell`: install the normal-boot shell profile and verify it on the
   device. This stays separate because it must run during a normal boot.

Liter8 materializes the reviewed inputs in a writable, resumable runtime under
the selected work directory. Relative tool paths resolve inside that runtime,
and the beta-4 launchd hash is supplied by the exact firmware profile instead
of being hidden inside a generic script.

## Bootstrap and JB assets

| Public asset | Classification | Migration decision |
| --- | --- | --- |
| `ssh.tar.gz` | Core SSHRD input | Imported and hash-locked. |
| `bootstrap_1900.tar.zst` | Core rootless bootstrap | Imported and SHA-256 locked for `fw bootstrap`. |
| `install_bootstrap.sh` | Core device installer | Owned by the `fw bootstrap` phase. |
| `install_dropbear.sh` | Core normal-boot SSH installer | Owned by `fw provision`; shared archive keys are not installed. |
| `sshrd_provision.sh` | Core post-restore workflow | Owned by a resumable `fw provision` runtime. |
| `patch_setup.py` | Core first-run bypass | Retain its ObjC-metadata resolver, but move firmware support into reviewed profile data and tests. |
| `patch_launchd_cache.py`, `add_jbboot.py` | Core launchd cache edits | Consolidate into one generic cache editor with structural guards. |
| `boot/jbboot.sh` | Core per-boot state setup | Imported with its native helper sources. |
| `launchdhook/*` | Core injection sources and verifiers | Source and build recipes imported; generated products remain runtime state. |
| `fetch_payloads.sh` | Reproducibility entry point | Imported with complete upstream hashes and a profile-provided launchd hash. |
| `setup_shell.sh`, `shell/*` | Optional operator quality-of-life | Owned by `fw setup-shell`. |
| `Sileo.app`, `launchd.hooked`, `lhook.dylib`, `uicache` | Generated payloads | Do not commit the old build output; reproduce from pinned inputs and source. |
| `photoforce/pfwatch`, `spawnprobe/personaalloc` | Core per-boot helpers | Import their source and build recipes with `jbboot.sh`; both are invoked by that script. |
| Remaining `photodiag`, `photoforce`, `spawnprobe` files | Research/probe utilities | Keep outside the core firmware workflow. |
| `aptproxy.py`, `tss_proxy_server.py` | Host services | TSS service is required for restore; APT proxy is an optional debugging aid. Both still need an explicit lifecycle owner. |

The reviewed SSH archive also contains reusable private host keys. They remain
part of the existing SSHRD byte image, but `fw provision` installs only the
Dropbear binaries. Its launchd job uses `dropbear -R`, so missing normal-boot
host keys are generated on that phone.

## Host tools still needed

The public tool bundle is imported under `tools/`, including `usbliter8ctl`,
`sshpass`, `ldid_macosx_arm64` and GNU tar. The device phases additionally
require the project's custom `irecovery`, `idevicerestore`, `iproxy`, GNU
`timeout`, `zstd` and PyUSB. Liter8 should resolve installed resources first
and PATH tools second, print a complete preflight report, and never download
or install them implicitly. The custom `irecovery` is still missing; the
official libirecovery 1.3.1 currently on this host is not an accepted fallback.

## Completion boundary

Firmware artifact generation, restore/boot transport, bootstrap, provisioning,
reproducible JB payload construction and normal-boot shell setup are now wired
into the CLI. Exact-device restore, boot and read-back validation remain the
completion boundary; these commands have not been run against the phone yet.
