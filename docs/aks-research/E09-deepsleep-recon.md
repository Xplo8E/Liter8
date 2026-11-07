# E09 — Deep-Sleep Blocked: Display LPM Firmware Path (SEP-less)

Date: 2026-11-07. Branch: research/e07-passcode-gate (analysis session; no device changes).
Related: issue #16 on GitHub (delayed black-screen freeze, d421ap — SEP-update timer, separate failure).
Evidence tags: [V] measured/decoded, [I] inference, [R] runtime-pending.

## Symptom

The device does not reach deep sleep on the SEP-less Liter8 boot (Vinay: "deep sleep
issues"). Expected related effects: battery drain, warm device, load average with no
matching userspace CPU (the profile notes previously recorded load 129-295 at boot
settling to 15-43 with every process at 0.0% CPU — an unexplained observation that fits
a deep-sleep-blocked platform).

## Serial-log evidence [V] (Serialis session 2026-11-06_12-31-29, capture.raw)

Three repeating signatures, all in the display power pipeline:

```
AppleOLYHAL::deviceCheckLPEM: IOPMUBootLPMFWOK property not found     (repeated)
amfm: deepSleepLocked: port is not marked on                          (repeated)
AppleBluetoothModule::deepSleepVote: vote is already deasserted       (noise)
[IOSA][Boot] [MSR0] SleepState transition from SleepRequested to Awake
```

SleepState bouncing SleepRequested → Awake during boot = the system requests sleep and
bounces — consistent with a blocked quiesce, not a clean entry.

## The mechanism [V + I]

1. On stock iOS, iBoot validates the display's Low-Power Mode firmware (the MCU-side
   firmware that draws the clock/charging UI while the SoC sleeps — tap-to-wake, AOD
   path) and injects the device-tree property `IOPMUBootLPMFWOK` = "LPM firmware OK"
   when validation passes.
2. Our tethered boot never sets it: the property is absent from both the stock and
   patched device-tree binaries on the host side (byte-count = 0 for
   IOPMUBootLPMFWOK/LPMFW/LPEM in devicetree.n104ap.stock.bin — it is an iBoot-injected
   dynamic property, not a static DT entry), and AppleOLYHAL reports "property not
   found" repeatedly on device.
3. AppleOLYHAL (OLED display HAL) gates the display's low-power path on that property.
   Without it → `AppleAMFM deepSleepLocked: port is not marked on` — a display-pipe
   port is never marked powered, so deep sleep stays LOCKED platform-wide.
4. Net effect: the SoC never reaches deep sleep; the platform sits in a shallow power
   state.

## Separation from issue #16 [V]

Issue #16's delayed black-screen freeze is the SEP-update check
(`com.apple.SepUpdateTimer` → seputil → SEP mailbox conversation) — a different
subsystem. Both are "boot-chain can't verify coprocessor/firmware state" failures, but:

- Deep-sleep block: display LPM firmware path — present on our n104ap boots (verified
  in serial + DT), chronic, no crash.
- SEP-update freeze: fires hourly when the SepUpdateTimer job loads (community d421ap
  devices; bootout → 10h+ stable). Our boots do NOT register the job (launchctl print
  system/com.apple.SepUpdateTimer → "Could not find service", verified 2026-11-07)
  despite the cache referencing it — the job plist carries
  `_LimitLoadToDeviceTree: "hilo"`, a device-tree condition our boot evidently fails
  (exact match semantics undecoded). A d421/n104 board difference is possible but the
  job loading is the necessary condition.

## Fix direction (NOT implemented — one decode needed first)

The naive fix is injecting `IOPMUBootLPMFWOK` into the device tree at boot-artifact
build time (the same DT-flag mechanism as ephemeral-storage etc.). That is only honest
if the LPM firmware is actually functional on the patched chain — otherwise the display
could black out during sleep instead. The gate decode:

1. What iBoot's LPM-validation path checks before setting the property (patched iBoot
   vs stock: does the validation run and fail, or is it skipped?).
2. What the display does in LPM when the property is present but the firmware is
   broken (black screen during sleep risk).

Intermediate alternative: check whether the LPM firmware itself loads and runs (the
serial log's IOSA/MSR0 lines suggest the coprocessor is alive), and whether OLYHAL's
LPEM check has a non-fatal path.

## Context carried into the next session

- The main direct-push precedent is established (fdc6111, post-merge review fix).
- PR #35 is rebased onto main, retargeted, source-only, still draft.
- tools/poolwalk.py + the isa-decode (low 40 bits = class, slide 0x8694000) remain the
  live-debug toolkit.
- Serial capture available: Serialis session 2026-11-06_12-31-29 (the boot analyzed
  here). A fresh capture during a sleep attempt would catch the exact failing
  transition.
