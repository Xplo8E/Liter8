# launchctl compatible with iOS 26 and later

`launchctl`
SHA-256 `c46e143151f4d56fd9e3c088d74e231f4b6f4ff7477aad080359454821ec0125`,
116560 bytes, arm64, adhoc signed as `com.apple.xpc.launchctl`.

## Why the bootstrap copy cannot be used

The bootstrap ships Procursus `launchctl 1:1.1.1`, built 2024-06-10 against the
iOS 17.5 SDK. It imports `_launch_active_user_switch` from libSystem as a
**strong** reference, and Apple removed that routine in the iOS 26 line. dyld
binds every GOT entry before `main`, so the process aborts on load no matter
which subcommand was asked for:

    dyld[941]: Symbol not found: _launch_active_user_switch
      Referenced from: /private/var/jb/usr/bin/launchctl
      Expected in:     /usr/lib/libSystem.B.dylib
    Abort trap: 6

The upstream source guarded the *call* with `__builtin_available`, which is a
runtime check and does nothing to the link-time binding.

This is not specific to `24A435`. `nm -gU` on libxpc extracted from the
`24A5390f` shared cache shows `_launch_active_user_switch` absent there too,
while its siblings `_launch_active_user_login` and `_launch_active_user_logout`
are present, so the routine was split rather than deleted outright. The
iPhoneOS 26.5 SDK stub library does not declare it either.

## What this build changes

Source: the `ios27-weak-imports` branch of the launchctl fork at
`research/launchctl`, built with its `build-ios.sh`.

- `_launch_active_user_switch` is resolved with `dlsym(RTLD_DEFAULT, ...)` and
  no longer appears in the symbol table at all. No SDK stub library declares it,
  so a link-time reference cannot be weak either: ld rejects it outright.
  `launchctl userswitch` now reports ENOTSUP instead of aborting the process.
- `_xpc_user_sessions_enabled` and `_xpc_user_sessions_get_foreground_uid` are
  weak references behind one absence gate. Both still exist on `24A435`, which
  the device confirmed by taking the `user/foreground` redirect path, but a
  strong reference to either would reproduce the same class of failure the next
  time Apple drops one.

libSystem is not patched and no substitute symbol is defined.

## Known difference from the Procursus package

The bootstrap's `libiosexec1` ships no header or stub library, so the
`ie_posix_spawnp()` redirection is not applied here. That affects only
`launchctl examine` and `launchctl attach`, which spawn an external examiner
binary and lldb respectively; neither is present on the device.

Entitlements come from the fork's `launchctl.xml`. They are a subset of what
Procursus signs its copy with, which additionally carries a large
`com.apple.private.security.storage.*` and `com.apple.rootless.*` block. Every
subcommand exercised on `24A435` worked without it: `version`, `print`,
`print system`, `print-disabled`, `list`, `procinfo`, `managerpid`,
`manageruid`, `managername`, `error`, `userswitch`.

## Verified on device

iPhone 11 / n104ap on `24A435`, launchd healthy as PID 1:

    launchctl print system/com.apple.mobilegestalt.xpc

returns launchd state with rc 0. Not yet re-verified after a reboot.
