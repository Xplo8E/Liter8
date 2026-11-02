#!/bin/sh
# Build the marker-gated AirPort credential shim for both device ABIs.
#
# The shim lives on the sealed System volume, not on Data. A restricted
# platform binary may only load a dylib from the sealed System volume: the
# same file at /var/jb/usr/lib is declined silently by dyld, with no AMFI or
# dyld message anywhere in the boot log. See the comment in
# device/userland_fixups.py.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -n ldid || true)

# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }
OUT="$BASE/l8wifi.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

for arch in arm64 arm64e; do
    xcrun clang -arch "$arch" -miphoneos-version-min=15.0 \
    -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra -Werror \
    -Wl,-not_for_dyld_shared_cache -install_name /usr/lib/l8wifi.dylib \
    -framework CoreFoundation -framework Security \
    -o "$BASE/l8wifi_$arch.dylib" \
    "$BASE/l8wifi.c"
done

lipo -create "$BASE/l8wifi_arm64.dylib" "$BASE/l8wifi_arm64e.dylib" -output "$OUT"
rm -f "$BASE/l8wifi_arm64.dylib" "$BASE/l8wifi_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"
echo "[+] $OUT (arm64 + arm64e, adhoc-signed)"
