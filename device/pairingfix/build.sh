#!/bin/sh
# Build the marker-gated lockdownd pairing-key fallback for both device ABIs.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/l8pair.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

for arch in arm64 arm64e; do
    xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra -Werror \
        -Wl,-not_for_dyld_shared_cache -install_name /usr/lib/l8pair.dylib \
        -framework CoreFoundation -framework Foundation -framework Security \
        -o "$BASE/l8pair_$arch.dylib" \
        "$BASE/l8pair.c" "$BASE/l8pair_auth.m"
done

lipo -create "$BASE/l8pair_arm64.dylib" "$BASE/l8pair_arm64e.dylib" -output "$OUT"
rm -f "$BASE/l8pair_arm64.dylib" "$BASE/l8pair_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
for arch in arm64 arm64e; do
    interpose_size=$(otool -arch "$arch" -l "$OUT" \
        | awk '/sectname __interpose/{found=1} found && /size/{print $2; exit}')
    [ "$interpose_size" = 0x0000000000000030 ] \
        || { echo "[!] l8pair $arch does not contain exactly three interposers" >&2; exit 1; }
done
otool -arch arm64 -L "$OUT" | grep -q '/System/Library/Frameworks/Security.framework/Security' \
    || { echo "[!] l8pair does not link Security.framework" >&2; exit 1; }
strings -a "$OUT" | grep -q '^com.apple.lockdown.pairingkeypair$' \
    || { echo "[!] pairing key label is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q 'LocationBasedTrustComputer' \
    || { echo "[!] Trust-computer policy guard is absent" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] l8pair unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, marker-gated pairing fallback)"
