# Device provisioning resources

This directory contains the reviewed bootstrap, jailbreak provisioning and
shell-setup inputs migrated from the public iPhone 11 beta-4 work directory.
They are installed as immutable Liter8 resources. The CLI copies them into
`<work-dir>/device-runtime/workflow` before running them, because the
payload builders need a persistent writable `payload/` and build directory.

The checked-in archives are pinned by complete SHA-256 values in
`scripts/device_provision.py`. The launchd input is also pinned to the firmware
profile selected from `BuildManifest.plist`; provisioning refuses an unknown
profile instead of applying a boot-critical patch by pattern alone.

Commands have deliberately narrow device states:

- `liter8 fw bootstrap` runs from the Mac while the phone is in SSHRD and
  installs the Procursus tree on the Data volume.
- `liter8 fw provision --rootfs <mounted-rootfs>` builds the reviewed payloads,
  installs Dropbear and performs the System/Data/Preboot provisioning pass. It
  also patches and entitlement-preserving re-signs `coreauthd`,
  `mobileactivationd`, `ctkd` and Setup, then installs the five fail-fast
  ScreenTime overrides recorded by the beta-4 device research. The Dropbear
  payload also supplies the minimal System `/bin/sh`, `ls` and `cat`; the shell
  is required by both root logins and the `com.jbboot` launchd-cache job. It
  requires `fw bootstrap` to have created `/var/jb` first.
- `liter8 fw setup-shell` runs only after a normal boot and installs the root
  shell profiles on the writable Data volume.
- `liter8 fw finalize` runs once after the first normal boot. It explicitly
  invokes the bootstrap through `/var/jb/bin/sh`, configures passwd databases
  and shells, installs the root profile, performs the guarded one-time System
  application registration, restarts SpringBoard and verifies `com.jbboot`.
  It refuses registration when container applications already exist.

Add `--check` to inspect the corresponding state without installing files.
Device scripts retain `.orig` or `.prev` copies when replacing boot-critical
content. They still require operator-controlled device state and are never run
as part of build or test targets.
