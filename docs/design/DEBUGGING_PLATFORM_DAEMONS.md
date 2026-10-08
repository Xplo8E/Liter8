# Debugging platform daemons on an SPTM device

Why `breakpoint set -H` is mandatory on this platform, why `debugserver` has to be
re-signed, and which approaches were tried and abandoned. Worked out on iPhone 11
(`n104ap`), iOS 27.2 `24B5099f`.

Install the debugger with `liter8 fw setup-debugger`. This document is the reasoning
behind what that stage does.

## What works and what does not

| capability | state |
| --- | --- |
| attach to a platform daemon, symbolicated `bt`, registers, `memory read`, `image lookup` | works |
| hardware breakpoints, `breakpoint set -H` | works |
| log-level tracing, `oslog --debug -p <daemon>` | works |
| software breakpoints, plain `breakpoint set` | silently never fire |
| inline hooks, Substrate-style `MSHookFunction` | fault with SIGBUS |

Nothing in the firmware patch set is required for any of the working rows. The device
runs the stock Liter8 boot plans.

## The code signing monitor is TXM, not XNU

On this device:

```text
kern.sptm.boot_timestamps.txm_bootstrap   nonzero
kern.sptm.boot_timestamps.txm_complete    nonzero
kern.sptm.boot_timestamps.sk_bootstrap    0        (no Secure Kernel)
kern.exclaves_status                      255      (no Exclaves)
security.codesigning.monitor              2        (monitor = TXM)
```

So code signing decisions are made by TXM in its own SPTM domain, and XNU defers to it:
`vm.cs_defer_to_csm` climbs continuously. Any attempt to relax code signing on the XNU
side alone therefore changes nothing, which is exactly what happened (see "Dead ends").

## TXM logs its own refusals

This is the useful part for anyone investigating further: TXM's error line reaches the
kernel log, so the gate that refuses you is directly observable rather than guessed.
Capture with `oslog --debug` while triggering the failure and grep for `TXM [`:

```text
inline hook of a function in its own process  ->  TXM [Error]: selector: 42 | 37
lldb software breakpoint in a platform daemon ->  TXM [Error]: selector: 42 | 29
```

Selector 42 is the debug-mapping call. The two codes are two different gates.

**Error 37** is an entitlement check on the caller. TXM queries
`com.apple.private.cs.debugger`, and the diagnostic string is
`disallowed non-debugger initiated debug mapping`. A re-signed `debugserver` carries that
entitlement and so passes; an ordinary binary hooking itself does not.

**Error 29** is a per-address-space flag. TXM sets it only when the target holds
`get-task-allow`, or holds `research.com.apple.license-to-operate` with developer mode,
or when a policy byte is set. A normal platform daemon satisfies none of those.

Related strings in the TXM binary name the rest of the decision set:
`disallowed writable debug mapping due to address space`, `… due to developer mode`,
`disallowed executable debug mapping`.

## Why software breakpoints cannot work, regardless of entitlements

Even with both gates passing, the write never lands. Demonstrated in a single lldb
session against one process, which is what rules out a broken write path:

```text
shared-cache text 0x25428cccc
  memory read   -> 0x928005d0 0xd4001001 0xd65f03c0
  memory write  0xd503201f            (no error reported)
  memory read   -> 0x928005d0 0xd4001001 0xd65f03c0    UNCHANGED

stack 0x16c01af90
  memory read   -> 0x0000000000000000
  memory write  0xdeadbeefcafe0001
  memory read   -> 0xdeadbeefcafe0001                  LANDED
```

Writes to shared-cache **code** pages are silently discarded. No error, no refusal from
TXM or XNU. That is why lldb's own internal breakpoints report
`error sending the breakpoint request: 9` (it verifies and finds memory unchanged) while
an explicitly set one appears to succeed and then never fires.

Making such a page privately writable requires retyping the frame and repointing the PTE,
which only SPTM can do. That boundary was not crossed and is well below anything Liter8
currently patches.

## Hardware breakpoints sidestep all of it

ARM64 debug registers need no memory write, so none of the above applies. What they do
need is `com.apple.private.thread-set-state` on `debugserver`, to program them.

The stock Procursus `debugserver-16` attaches to a platform daemon perfectly well but
**cannot** set a hardware breakpoint: lldb reports the breakpoint as set and it then never
fires. Confirmed by an A/B on one boot against one target, stock versus re-signed. This is
the reason `fw setup-debugger` re-signs the binary rather than just installing the package.

The three entitlements it adds:

| entitlement | why |
| --- | --- |
| `com.apple.private.set-exception-port` | iOS 27 guards `task_set_exception_ports(mach_task_self())`. Without it debugserver is SIGKILLed with `EXC_GUARD` / `GUARD_TYPE_MACH_PORT` before it binds its socket. |
| `com.apple.private.thread-set-state` | programs the ARM64 debug registers, so hardware breakpoints fire |
| `com.apple.private.cs.debugger` | satisfies TXM's gate 1 entitlement check |

Only `set-exception-port` has been individually proven necessary, with a minimal repro that
dies without it and survives with it. The other two were added together, and the stock
binary lacking all three cannot set hardware breakpoints.

## Symbols are not optional

Attaching to a daemon without a DeviceSupport tree for the exact build does not merely run
slowly, it never returns. A packet trace of one attempt showed **23,929** memory reads of
512 bytes each, dragging shared-cache symbol tables over the ssh link one round trip at a
time.

Building the tree turns that into a roughly 30 second attach with full symbolication:

```sh
ipsw extract --dyld --dyld-arch arm64e -o out iPhone12,1_27.2_<BUILD>_Restore.ipsw
ipsw dyld split --cache --build <BUILD> --version 27.2 -x /Applications/Xcode.app \
    out/<BUILD>__iPhone12,1/dyld_shared_cache_arm64e

cd ~/Library/Developer/Xcode/iOS\ DeviceSupport
mkdir -p "iPhone12,1 27.2 (<BUILD>)"
mv "27.2 (<BUILD>) arm64e" "iPhone12,1 27.2 (<BUILD>)/arm64e"
cp "iPhone12,1 27.2 (<OTHER-BUILD>)/arm64e/.finalized" "iPhone12,1 27.2 (<BUILD>)/arm64e/"
```

`ipsw dyld split -c` writes `27.2 (<BUILD>) arm64e`, which is **not** the layout lldb
scans, hence the move. Verify with `lldb -b -o "platform select remote-ios"`: the build
must appear as `SDK Roots [0]`.

This is still manual; `fw setup-debugger` warns about it but does not build it, because it
is host-side and needs the IPSW.

## Dead ends, none of which are in the tree

Recorded so nobody repeats them.

**Patching XNU's `vm_fault_enter_prepare` cs_bypass gate.** The gate is real and was
recovered semantically (`tbz Wflags,#3` on a flag loaded from `[Xinfo,#0x28]`, exactly one
candidate kernel-wide, cross-validated on two kernels). NOPing it produced **no measurable
change in any configuration**, alone or combined with the TXM patches below. XNU defers to
CSM, so its own validation is not the authority.

**Setting TXM's debug-mapping policy byte statically.** The byte is read in exactly the two
places that refuse, and has no direct store anywhere in the binary, which looked like a
safe static patch. It is not: both gates still fired on device. The signed image provably
carried the change and TXM is uploaded and hash-verified at boot, so the value is zero at
runtime regardless. Absence of a direct store does not imply a value survives boot.

**Forcing both TXM gates with two branch patches.** This one does something real: the kill
changes from `CODESIGNING / Invalid Page` SIGKILL to an ordinary SIGBUS, and a daemon
survives a software-breakpoint attempt instead of dying. But the write is still discarded,
so the breakpoint still never fires. Not needed for hardware breakpoints, which work on a
completely stock system.

## Methodology warnings

Two false results cost real time here.

**An idle daemon is indistinguishable from a broken breakpoint.** A hardware breakpoint on
a cold path in a freshly respawned daemon never fires, which looks exactly like failure.
Generate activity before concluding anything, and confirm on the device: `ps -o stat -p
<pid>` showing `T` means genuinely stopped at the breakpoint, `?X` means traced and still
running.

**A short log capture window will miss the TXM error.** A capture that straddles the
failure can still come back empty. Give it several seconds either side and sanity-check the
total line count before trusting a zero.

**Never pick a central daemon as a test target.** Holding something like `notifyd` stopped
stalls large parts of the OS. Use an analytics daemon, or a process you launched yourself.

## Session gotchas

1. **`detach` in lldb before stopping debugserver.** Killing debugserver takes the attached
   process down with it.
2. **Never probe the forwarded port with `nc`.** debugserver accepts exactly one client, so
   `nc` becomes it and debugserver exits.
3. **Expression evaluation needs a JIT** and generally fails here, so prefer literal
   addresses over `` `(void*)symbol` `` in `memory` commands.
4. **`apt` upgrades revert the re-signed binary.** `fw setup-debugger` runs `apt-mark hold`
   on the three packages for this reason; `--check` detects drift by hash.
