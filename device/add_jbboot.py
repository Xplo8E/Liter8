#!/usr/bin/env python3
"""Add a com.jbboot job to the signed launchd service cache.

launchd on this build takes its entire service list from the signed cache at
/System/Library/xpc/launchd.plist and never scans /System/Library/LaunchDaemons.
The boot-arg launchd_unsecure_cache=1 (in /usr/libexec/launchd_cache_loader,
not in launchd) makes it accept a modified cache. That is how com.dropbear got
in.

This adds one more job whose only purpose is to run jbboot.sh at every boot,
so future per-boot setup needs no further changes to the signed cache.

ProgramArguments names the interpreter explicitly, because the kernel refuses
to exec shebang scripts here ("bad interpreter: Operation not permitted").

It must be the SYSTEM /bin/sh, not /var/jb/bin/sh. launchd cannot exec a
bootstrap binary at all; the first attempt used /var/jb/bin/sh (a symlink to
dash) and launchd rejected it outright:

    Service could not initialize: posix_spawn(/var/jb/bin/sh),
    error 0x1 - Operation not permitted
    xpcproxy exited due to exit(78)

Reading the script from /var/jb would probably be fine, since only execution of
bootstrap binaries is restricted. It is kept on the System volume next to
dropbear anyway, so the boot path has no dependency on /var/jb at all.

Kept separate from patch_launchd_cache.py rather than generalising it, because
that script is what currently gets us a shell and is not worth destabilising.

Usage:
    ./add_jbboot.py <launchd.plist>            # inspect only
    ./add_jbboot.py <launchd.plist> --apply
    ./add_jbboot.py <launchd.plist> --remove
"""

import argparse
import plistlib
import shutil
import sys
from pathlib import Path

CACHE_KEY = "/System/Library/LaunchDaemons/com.jbboot.plist"
LABEL = "com.jbboot"
SCRIPT = "/usr/local/bin/jbboot.sh"
SHELL = "/bin/sh"

JBBOOT_JOB = {
    "Label": LABEL,
    # interpreter first: the kernel will not exec a shebang script here
    "ProgramArguments": [SHELL, SCRIPT],
    "RunAtLoad": True,
    # one-shot: it sets up kernel state and exits. KeepAlive would respawn it
    # forever, which is wrong for a task that is meant to run once per boot.
    "KeepAlive": False,
    "POSIXSpawnType": "Interactive",
    "EnablePressuredExit": False,
    "EnableTransactions": False,
    "StandardOutPath": "/var/mobile/jbboot.log",
    "StandardErrorPath": "/var/mobile/jbboot.log",
}

PRISTINE_DAEMONS = 731          # untouched cache
WITH_DROPBEAR = 732             # after patch_launchd_cache.py


def load(path):
    with open(path, "rb") as f:
        return plistlib.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cache", help="path to launchd.plist (the service cache)")
    ap.add_argument("--apply", action="store_true", help="add the job")
    ap.add_argument("--remove", action="store_true", help="remove the job")
    args = ap.parse_args()

    path = Path(args.cache)
    if not path.is_file():
        sys.exit(f"[!] not found: {path}")

    data = load(path)
    ld = data.get("LaunchDaemons", {})
    n = len(ld)
    present = CACHE_KEY in ld

    print(f"[.] {path}")
    print(f"    size          {path.stat().st_size}")
    print(f"    LaunchDaemons {n}" + ("" if n in (PRISTINE_DAEMONS, WITH_DROPBEAR, WITH_DROPBEAR + 1)
                                      else f"   (expected {PRISTINE_DAEMONS}/{WITH_DROPBEAR})"))
    print(f"    com.dropbear  {'present' if '/System/Library/LaunchDaemons/com.dropbear.plist' in ld else 'ABSENT'}")
    print(f"    {LABEL}     {'present' if present else 'absent'}")

    if not (args.apply or args.remove):
        print("[.] inspect only; pass --apply or --remove")
        return

    if args.apply and present:
        sys.exit(f"[!] {LABEL} already present, refusing to double-add")
    if args.remove and not present:
        sys.exit(f"[!] {LABEL} not present, nothing to remove")

    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"[+] backup {backup}")

    if args.apply:
        ld[CACHE_KEY] = JBBOOT_JOB
        for k in sorted(JBBOOT_JOB):
            print(f"      {k:22s} {JBBOOT_JOB[k]}")
    else:
        del ld[CACHE_KEY]

    data["LaunchDaemons"] = ld
    with open(path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)

    after = load(path)
    got = len(after.get("LaunchDaemons", {}))
    want = n + (1 if args.apply else -1)
    if got != want:
        sys.exit(f"[!] verify FAILED: {got} daemons, expected {want}")
    if args.apply and CACHE_KEY not in after["LaunchDaemons"]:
        sys.exit("[!] verify FAILED: job missing after write")
    print(f"[+] wrote {path}, {n} -> {got} daemons")
    print("[+] the cache must be re-deployed to /System/Library/xpc/launchd.plist "
          "from SSHRD, and its detached .sig left in place")


if __name__ == "__main__":
    main()
