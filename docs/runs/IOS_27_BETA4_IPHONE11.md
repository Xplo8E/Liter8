Create the isolated Liter8 work directory used by every firmware phase.

```bash
mkdir -p .liter8
```

Delete previous Swift build products and compile a fresh debug CLI.

```bash
make clean && make build
```

Identify, validate, and extract the iPhone 11 iOS 27 beta 4 IPSW into the work directory.

```bash
time .build/debug/liter8 fw prepare \
  --file /Volumes/vinay-ssd/ipsw-files/iPhone12,1_27.0_24A5390f_Restore.ipsw \
  --work-dir "$PWD/.liter8"
```

Clone the extracted IPSW into `CFW`, patch every restore component, and verify the generated artifacts.

```bash
time .build/debug/liter8 fw make-cfw \
  --work-dir "$PWD/.liter8"
```

Erase-restore the patched CFW through the RP2350 iBSS handoff and Liter8's managed TSS proxy.

```bash
time .build/debug/liter8 fw restore-cfw \
  --work-dir "$PWD/.liter8"
```

Recover this successful restore's device-bound APTicket from its retained debug log.

```bash
.build/debug/liter8 fw capture-ticket --work-dir "$PWD/.liter8"
```

Build the patched and ticket-signed SSH restore ramdisk boot set. Liter8 requests
administrator authentication when it must preserve root ownership inside the image.

```bash
.build/debug/liter8 fw get-rd \
  --work-dir "$PWD/.liter8"
```

Boot the verified SSH restore ramdisk set on the pwn-DFU device. The raw iBSS
uses the RP2350 transport; the remaining signed images use the selected
project-compatible `irecovery`.

```bash
.build/debug/liter8 fw boot-rd \
  --work-dir "$PWD/.liter8" \
  --irecovery /usr/local/bin/irecovery
```

Observed display behavior: the SSHRD boot chain completed and the device was
reachable, but the iPhone 11 panel remained black. Liter8 did send the
sky-blue `bgcolor` command and `setpicture 0x1`, so this is an unresolved
restore-ramdisk display/backlight handoff issue rather than evidence that SSHRD
failed to boot.

Confirm that SSHRD is running, mount the Data volume, and report bootstrap state
without installing or changing anything on the device.

```bash
.build/debug/liter8 fw bootstrap \
  --work-dir "$PWD/.liter8" \
  --check
```

Install the Procursus bootstrap into the device Data volume, preserve its root
ownership and setuid files, apply the Sileo apt policy, and verify the complete
installation. The same command safely resumes incomplete post-install steps.

```bash
.build/debug/liter8 fw bootstrap \
  --work-dir "$PWD/.liter8"
```

Decrypt the BuildManifest `OS` component, mount it read-only at the location
selected by macOS, and verify its build identity and reviewed `launchd` hash.

```bash
.build/debug/liter8 fw prepare-rootfs \
  --work-dir "$PWD/.liter8"
```

Build the reviewed jailbreak payloads and provision the mounted System and Data
volumes while the device is running SSHRD. The command verifies every deployed
boot-critical artifact before declaring the device safe to reboot.

```bash
.build/debug/liter8 fw provision \
  --work-dir "$PWD/.liter8"
```

Observed on the beta-4 iPhone 11: the command preserved pristine `.orig`
copies, deployed and read back all three signed daemon fixes, installed the
five ScreenTime overrides, and reported `OK` for every new and existing
provisioning check.

Detach the verified host rootfs after provisioning while retaining the
decrypted image cache for future retries.

```bash
.build/debug/liter8 fw unmount-rootfs \
  --work-dir "$PWD/.liter8"
```

Build and verify the ticket-signed normal-boot set, including the n104 display
handoff, normal DeviceTree, TXM and public kernel patch plans.

```bash
.build/debug/liter8 fw get-boot \
  --work-dir "$PWD/.liter8"
```

From pwn DFU, send the verified normal boot chain. The RP2350 transports raw
iBSS; the selected project-compatible `irecovery` sends the remaining images.

```bash
.build/debug/liter8 fw boot \
  --work-dir "$PWD/.liter8" \
  --irecovery /usr/local/bin/irecovery
```

Observed early display behavior: normal boot showed the expected sky-blue
background and Apple logo, followed by verbose output. The panel later went
black and the device temporarily disappeared from USB. This proves the n104
iBEC display handoff worked, but it is not proof that userspace finished
booting. The original beta-4 workflow records the same black/USB-absent window;
wait about five minutes and test normal-boot SSH before declaring failure.

After repairing Setup.app's invalid CodeDirectory and restoring the missing
System `/bin/sh`, the same `get-boot` and `boot` commands completed a confirmed
normal boot to the iOS Setup screen. This is the first end-to-end successful
normal boot recorded for the Liter8 rewrite on `iPhone12,1` build `24A5390f`.

After completing the iOS Setup flow, inspect and then perform the guarded
one-time Procursus, shell and System-application finalization:

```bash
.build/debug/liter8 fw finalize \
  --work-dir "$PWD/.liter8" \
  --check

.build/debug/liter8 fw finalize \
  --work-dir "$PWD/.liter8"
```
