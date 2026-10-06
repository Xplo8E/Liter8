#!/bin/sh
# Build the coreauthd-only empty SEP ratchet-state guard for both device ABIs.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/l8coreauth.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

for arch in arm64 arm64e; do
    xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra -Werror \
        -fno-objc-arc -Wl,-not_for_dyld_shared_cache \
        -install_name /usr/lib/l8coreauth.dylib \
        -framework Foundation \
        -o "$BASE/l8coreauth_$arch.dylib" "$BASE/l8coreauth.m"
done

lipo -create "$BASE/l8coreauth_arm64.dylib" "$BASE/l8coreauth_arm64e.dylib" -output "$OUT"
rm -f "$BASE/l8coreauth_arm64.dylib" "$BASE/l8coreauth_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
otool -arch arm64 -L "$OUT" | grep -q '/System/Library/Frameworks/Foundation.framework/Foundation' \
    || { echo "[!] l8coreauth does not link Foundation.framework" >&2; exit 1; }
strings -a "$OUT" | grep -q '^ratchetStateFromState:$' \
    || { echo "[!] ratchet parser selector is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^coreauthd$' \
    || { echo "[!] coreauthd process guard is absent" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] l8coreauth unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, coreauthd-only ratchet-state guard)"
