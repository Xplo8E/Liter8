#!/bin/sh
# Build l8acmuc.dylib, the IOKit user-client interposer that serves the ACM
# credential store in software. Ad-hoc signed, no entitlements: it only
# interposes IOKit framework exports in its own process, like l8wifi's
# AppleKeyStore interpose. Marker-gated at runtime; marker off = pure forward.
set -e
cd "$(dirname "$0")"
LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)

# Host self-test first: the dispatch contract against fabricated client
# blobs. No IOKit calls happen on the host (the interposers stay dormant).
if command -v clang >/dev/null 2>&1 && [ "$(uname)" = Darwin ]; then
    xcrun clang -DLITER8_ACMUC_TEST -framework CoreFoundation -framework IOKit l8acmuc.m -o .l8acmuc-test
    ./.l8acmuc-test
    rm -f .l8acmuc-test
fi

SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

xcrun clang -isysroot "$SDK" -arch arm64 -arch arm64e \
    -miphoneos-version-min=15.0 -O2 -Wall -Wextra -dynamiclib \
    -Wl,-not_for_dyld_shared_cache -install_name /var/jb/usr/lib/TweakInject/l8acmuc.dylib \
    -framework CoreFoundation IOKit-client.tbd \
    l8acmuc.m -o l8acmuc.dylib

# No ObjC runtime, no Foundation: this loads into every TweakInject process
# including daemons that must never see ObjC classes appear early.
otool -L l8acmuc.dylib | grep -qE '/Foundation\.framework/' \
    && { echo "[!] l8acmuc links Foundation (keep it Foundation-free)" >&2; exit 1; }
otool -l l8acmuc.dylib | grep -q "__interpose" \
    || { echo "[!] no __DATA,__interpose section emitted" >&2; exit 1; }
"$LDID" -S -Icom.liter8.l8acmuc -Cadhoc l8acmuc.dylib
codesign -d --entitlements :- l8acmuc.dylib 2>/dev/null | grep -q get-task-allow \
    && { echo "[!] l8acmuc carries get-task-allow, AMFI will kill it"; exit 1; }
echo "[+] l8acmuc.dylib  $(wc -c < l8acmuc.dylib | tr -d ' ') bytes"
