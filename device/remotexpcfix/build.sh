#!/bin/sh
# Build the marker-gated remotepairingdeviced keybag and keychain repair.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/l8remotepairing.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

for arch in arm64 arm64e; do
    xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra -Werror \
        -Wl,-not_for_dyld_shared_cache \
        -Wl,-U,_MKBGetDeviceLockState \
        -Wl,-U,_MKBDeviceFormattedForContentProtection \
        -Wl,-U,_MKBDeviceUnlockedSinceBoot \
        -install_name /usr/lib/l8remotepairing.dylib \
        -framework CoreFoundation \
        -framework Security \
        -o "$BASE/l8remotepairing_$arch.dylib" \
        "$BASE/l8remotepairing.c"
done

lipo -create "$BASE/l8remotepairing_arm64.dylib" \
    "$BASE/l8remotepairing_arm64e.dylib" -output "$OUT"
rm -f "$BASE/l8remotepairing_arm64.dylib" \
    "$BASE/l8remotepairing_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
for arch in arm64 arm64e; do
    interpose_size=$(otool -arch "$arch" -l "$OUT" \
        | awk '/sectname __interpose/{found=1} found && /size/{print $2; exit}')
    [ "$interpose_size" = 0x0000000000000050 ] \
        || { echo "[!] $arch does not contain exactly five interposers" >&2; exit 1; }
done
nm -u "$OUT" | grep -q '_MKBGetDeviceLockState$' \
    || { echo "[!] MKBGetDeviceLockState import is absent" >&2; exit 1; }
for symbol in SecItemCopyMatching SecItemAdd SecItemUpdate SecItemDelete; do
    nm -u "$OUT" | grep -q "_$symbol$" \
        || { echo "[!] $symbol import is absent" >&2; exit 1; }
done
strings -a "$OUT" | grep -q '^remotepairingdeviced$' \
    || { echo "[!] process guard is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^/usr/lib/.liter8-remotepairing-fallback$' \
    || { echo "[!] marker guard is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^com.apple.RemotePairing$' \
    || { echo "[!] RemotePairing access-group guard is absent" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] l8remotepairing unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, marker-gated RemoteXPC keybag and keychain repair)"
