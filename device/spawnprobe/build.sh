#!/bin/sh
# Build the persona diagnostics. Signed with persona-mgmt and
# spawn-subsystem-root: both are safe ad-hoc (verified by bisection), while
# Sileo's full 34-entitlement set is NOT, AMFI SIGKILLs a binary claiming it.
set -e
cd "$(dirname "$0")"
# Prefer a native ldid. The bundled one is arm64 only, so it cannot run
# on an Intel Mac. See https://github.com/Xplo8E/Liter8/issues/2.
LDID=$(command -v ldid || echo ../../tools/ldid_macosx_arm64)
for src in spawnprobe.c personaprobe.c personaalloc.c; do
    [ -f "$src" ] || continue
    out="${src%.c}"
    xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -O2 -Wall "$src" -o "$out"
    "$LDID" -Icom.apple."$out" -Se_both.plist -Cadhoc "$out"
    codesign -d --entitlements :- "$out" 2>/dev/null | grep -q get-task-allow \
        && { echo "[!] $out carries get-task-allow, AMFI will kill it"; exit 1; }
    echo "[+] $out  $(wc -c < "$out" | tr -d ' ') bytes"
done
