# Liter8 workflow scripts

This directory contains the generic Python orchestration used by `liter8 fw`.
Scripts here may copy, mount, sign, or package firmware files. They must not
contain build-specific offset tables or duplicate a workflow for each iOS
build. Swift selects firmware profiles and resolves every binary patch.

At runtime Liter8 finds this directory relative to its own executable. The
current working directory and `--work-dir` are reserved for mutable firmware
inputs and outputs, never executable code.

`liter8_workflow.py` owns the shared BuildManifest context and subprocess
guards. `make_cfw.py`, `get_boot.py`, and `verify_cfw.py` are thin action entry
points. `rootfs.py` selects the manifest's `OS` component, resolves its AEA
key, keeps a decrypted cache in the work directory, and validates the mounted
System image against the selected build and reviewed launchd hash.
Host-specific ramdisk mounting is isolated in `ramdisk_patch.py`. SSHRD image
construction is isolated in `sshrd.py`, including its terminal-visible
privilege boundary.
`device_boot.py` owns the ordered normal/SSHRD upload sequence. It requires an
explicit custom `irecovery` path and verifies every generated artifact before
touching the device. `restore_cfw.py` verifies the CFW and then performs the
RP2350 iBSS handoff followed by `idevicerestore`. It starts the bundled,
loopback-only `tss_proxy.py` for exactly the lifetime of that restore. Restore
stages remain visible in the terminal, while full debug logs are retained in
the selected work directory's `logs/` directory.
`apticket.py` owns DER/IM4M validation and atomic publication;
`capture_ticket.py` recovers the ticket from an already completed restore log.
