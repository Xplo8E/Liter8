#!/usr/bin/env python3
"""Add a dropbear job to launchd's signed service cache.

    ./patch_launchd_cache.py <launchd.plist>              dry run, reports only
    ./patch_launchd_cache.py <launchd.plist> --apply      add the job (keeps a .bak)
    ./patch_launchd_cache.py <launchd.plist> --remove     take it back out

Why this works at all, and why it did not before:

launchd takes its whole service list from /System/Library/xpc/launchd.plist, loaded by
/usr/libexec/launchd_cache_loader, and never scans /System/Library/LaunchDaemons. Editing
the cache normally fails because the loader verifies a detached signature it cannot be made
to accept without Apple's key.

The loader has a second path, selected by a boot argument. Our earlier note claimed that
argument did not exist on iOS 27; that was wrong, because we grepped /sbin/launchd instead
of the loader. The two arguments live in different binaries:

    /sbin/launchd                      launchd_no_cache=
    /usr/libexec/launchd_cache_loader  launchd_unsecure_cache=

With launchd_unsecure_cache=1 in boot-args, the loader's own log on 24A5390f shows:

    Using default cache paths
    Code: /System/Library/xpc/launchd.plist Sig: /System/Library/xpc/launchd.plist.sig
    Using unsecure cache: /System/Library/xpc/launchd.plist        <- new
    Trying to send bytes to launchd: 2307 16384
    Sending validated cache to launchd
    Cache sent to launchd successfully

Compare the signed-path boot, where these two lines appear instead of the "unsecure" one:

    cdhash: {length = 20, bytes = 0xc00176d0...} is trusted
    Attached signature to file, checking ...

The signature check is skipped entirely, so a modified cache is accepted. That makes launchd
itself the process creator, which sidesteps the whole reason the osanalyticshelper wrapper
failed: it was inheriting that daemon's sandbox and getting EPERM from both posix_spawn and
execv.

Cache layout, from reading the real file (2464857 bytes, binary plist, VersionNumber 7):

    AppExtensions           dict, 777
    LaunchDaemons           dict, 731     keyed by PLIST PATH, value = the job dictionary
    AppRemovalServices      dict, 16
    SystemLibraryTreeState  dict, 3474    frameworks and their XPC bundles, no LaunchDaemons
    Symlinks                dict, 1
    VersionNumber           int

Only LaunchDaemons needs touching. SystemLibraryTreeState contains zero keys mentioning
LaunchDaemons, so it is not an index of jobs and is left alone.

The job dictionary is modelled on com.apple.logd, the closest real analogue (long-running,
root, RunAtLoad + KeepAlive). Notes on the choices:

  -F            dropbear must NOT fork into the background. launchd needs the process it
                spawned to be the one that stays alive, otherwise KeepAlive respawns it
                forever while the real daemon runs detached.
  -r paths      read the unique host keys that install_dropbear.sh generated
                on Data while running in SSHRD. The default /etc/dropbear path
                is on the sealed, read-only System volume during normal boot.
                We intentionally do not use -R: this old Dropbear only creates
                keys at its default paths, not at arbitrary explicit -r paths.
  -E            log to stderr, which StandardErrorPath then captures.
  no UserName   563 of 731 daemons set one; omitting it leaves the job as root, which
                dropbear needs to bind port 22 and authenticate root.
  no LimitLoadToSessionType   711 of 731 omit it.
"""

import argparse
import plistlib
import shutil
import sys
from pathlib import Path

CACHE_KEY = "/System/Library/LaunchDaemons/com.dropbear.plist"
LABEL = "com.dropbear"

DROPBEAR_JOB = {
    "Label": LABEL,
    "ProgramArguments": [
        "/usr/local/bin/dropbear",
        "-F",          # foreground; launchd owns the lifecycle
        "-r", "/private/var/dropbear/dropbear_rsa_host_key",
        "-r", "/private/var/dropbear/dropbear_ecdsa_host_key",
        "-r", "/private/var/dropbear/dropbear_dss_host_key",
        "-E",          # log to stderr -> StandardErrorPath
        "-p", "22",
    ],
    "RunAtLoad": True,
    "KeepAlive": True,
    "POSIXSpawnType": "Interactive",
    "EnablePressuredExit": False,
    "EnableTransactions": False,
    "ThrottleInterval": 5,
    "StandardOutPath": "/var/mobile/dropbear.log",
    "StandardErrorPath": "/var/mobile/dropbear.log",
}

def load(path):
    with open(path, "rb") as f:
        return plistlib.load(f)


def describe(d):
    ld = d.get("LaunchDaemons", {})
    present = CACHE_KEY in ld
    return ld, present


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cache", help="path to a copy of /System/Library/xpc/launchd.plist")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help="add the dropbear job")
    g.add_argument("--remove", action="store_true", help="remove it again")
    ap.add_argument(
        "--expected-pristine-daemons",
        type=int,
        help="exact profile-owned LaunchDaemons count before Liter8 adds jobs",
    )
    args = ap.parse_args()

    p = Path(args.cache)
    if not p.is_file():
        sys.exit(f"[!] not a file: {p}")

    size = p.stat().st_size
    d = load(p)
    ld, present = describe(d)

    print(f"[*] {p}")
    print(f"    size            {size}")
    print(f"    VersionNumber   {d.get('VersionNumber')}")
    print(f"    LaunchDaemons   {len(ld)}")
    print(f"    dropbear job    {'PRESENT' if present else 'absent'}")

    if args.expected_pristine_daemons is not None:
        expected_input = args.expected_pristine_daemons + (1 if present else 0)
        if len(ld) != expected_input:
            sys.exit(
                f"[!] cache has {len(ld)} daemons, expected {expected_input} for this profile"
            )

    if not (args.apply or args.remove):
        if present:
            print("\n    current job dictionary:")
            for k in sorted(ld[CACHE_KEY]):
                print(f"      {k:22s} {ld[CACHE_KEY][k]}")
        print("\n[dry-run] pass --apply or --remove to change anything.")
        return 0

    # Refuse to work on a cache that is not shaped the way we read it, rather than
    # silently producing something launchd will choke on at boot.
    for key in ("LaunchDaemons", "AppExtensions", "SystemLibraryTreeState", "VersionNumber"):
        if key not in d:
            sys.exit(f"[!] cache is missing top-level key {key!r}; refusing to edit")

    if args.remove:
        if not present:
            print("\n[=] not present, nothing to remove.")
            return 0
        del ld[CACHE_KEY]
        action = "removed"
    else:
        if present:
            print("\n[=] already present. Remove it first if you want to change the job.")
            return 0
        ld[CACHE_KEY] = DROPBEAR_JOB
        action = "added"
        print("\n    job to add:")
        for k in sorted(DROPBEAR_JOB):
            print(f"      {k:22s} {DROPBEAR_JOB[k]}")

    bak = p.with_suffix(p.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(p, bak)
        print(f"\n[*] backup -> {bak}")
    else:
        print(f"\n[*] backup already exists, keeping it: {bak}")

    with open(p, "wb") as f:
        plistlib.dump(d, f, fmt=plistlib.FMT_BINARY)

    # Re-read from disk. A cache that does not round-trip is a cache that will not boot.
    d2 = load(p)
    ld2, present2 = describe(d2)
    ok = (present2 if args.apply else not present2)
    expect = len(ld)

    print(f"\n[*] verify (re-read from disk)")
    print(f"    size            {p.stat().st_size}")
    print(f"    LaunchDaemons   {len(ld2)}   (expected {expect})")
    print(f"    dropbear job    {'PRESENT' if present2 else 'absent'}   -> {'OK' if ok else 'FAIL'}")

    if not ok or len(ld2) != expect:
        sys.exit("[!] round-trip failed; restore from the .bak")

    # Spot-check that an untouched neighbour survived the re-encode, since plistlib
    # rewrites the whole file rather than patching it in place.
    probe = "/System/Library/LaunchDaemons/com.apple.logd.plist"
    same = probe in ld2 and ld2[probe] == ld.get(probe, ld2.get(probe))
    print(f"    neighbour intact ({probe.split('/')[-1]}) -> {'OK' if same else 'FAIL'}")
    if not same:
        sys.exit("[!] an unrelated entry changed; restore from the .bak")

    print(f"\n[+] dropbear job {action}.")
    if args.apply:
        print("    Requires launchd_unsecure_cache=1 in boot-args, or the loader will take")
        print("    the signed path and reject this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
