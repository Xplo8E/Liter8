# Tweak injection on Liter8

Liter8's PID 1 hook must remain small. It is weak-loaded into launchd as
`/usr/lib/lhook` because launchd strips ordinary `DYLD_*` injection.

The integrated router deliberately does **not** propagate lhook itself.

## Flow

```text
launchd
  |
  +-- xpcproxy
  |     DYLD_INSERT_LIBRARIES = ElleKit pspawn.dylib
  |       |
  |       +-- final app/daemon
  |             ElleKit adds libinjector/TweakLoader
  |             ElleKit adds the rootless sandbox extension
  |             libinjector evaluates tweak Filters
  |
  +-- direct launchd child (for example SpringBoard)
        DYLD_INSERT_LIBRARIES = TweakLoader.dylib
```

ElleKit's injector evaluates each tweak's standard filter keys, including
`Bundles`, `Executables`, `Classes` and `CoreFoundationVersion`.
The PID 1 router therefore does not need a per-tweak allowlist.

## Safety

Nothing is injected until:

```sh
touch /var/jb/.lhook_enabled
```

Optional routing diagnostics:

```sh
touch /var/jb/.lhook_debug
cat /var/jb/tmp/lhook.log
```

Disable immediately:

```sh
rm -f /var/jb/.lhook_enabled /var/jb/.lhook_debug
```

Critical trust/security/recovery processes are hard-denied in `lhook.c`.
Additional executable basenames can be denied in:

```text
/var/jb/etc/lhook.deny
```

## Required ElleKit files

For a rootless bootstrap:

```text
/var/jb/usr/lib/ellekit/pspawn.dylib
/var/jb/usr/lib/TweakLoader.dylib
```

The second path is normally a symlink to ElleKit's libinjector.

## Why the old propagation design was unstable

The earlier implementation appended lhook and TweakLoader to every child and
allowed those children to propagate the same environment again. That made
generic loader code appear in many unrelated system processes and made a boot
failure much more likely.

The current implementation uses lhook only as the PID 1 routing edge and hands
xpcproxy over to ElleKit's own pspawn implementation.
