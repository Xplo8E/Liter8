#!/bin/sh
# Build l8keychain.dylib, the securityd-only software class-key interposer,
# plus run its host self-test. Fat arm64+arm64e like every proven /usr/lib
# shim (l8wifi/l8pair/l8coreauth): the arm64e slice is what an arm64e
# process (securityd) picks, and a third-party arm64e slice at this install
# path is exactly the proven-working shape. Ad-hoc signed; no entitlements.
#
# The interposer imports aks_wrap_key/aks_unwrap_key from
# AppleKeyStore.framework normally, so there is no -Wl,-undefined,dynamic_lookup
# anywhere in this link: the fat build carrying that flag was the l8keychain
# v1 TweakInject crash storm (E04-securityd-classkey-provider.md).

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }
# Deterministic-build note: the hardware-validated binary (E04 full-pass
# matrix, byte-identical check against the deployed dylib) was produced with
# Xcode 27.0 (27A266a), iPhoneOS27.0 SDK. Same toolchain + source = same
# bytes; verify with the cksum recorded in the deployment log if it matters.
OUT="$BASE/l8keychain.dylib"

# Self-test on the host first: blob round-trip, gates, pass-through wiring.
( cd "$BASE" && ./build-host-test.sh )

for arch in arm64 arm64e; do
    xcrun clang -isysroot "$SDK" -arch "$arch" \
        -miphoneos-version-min=15.0 -O2 -Wall -Wextra -Werror \
        -dynamiclib -Wl,-not_for_dyld_shared_cache \
        -install_name /usr/lib/l8keychain.dylib \
        "$BASE/AppleKeyStore.tbd" \
        -o "$BASE/l8keychain_$arch.dylib" "$BASE/l8keychain.m"
done

lipo -create "$BASE/l8keychain_arm64.dylib" "$BASE/l8keychain_arm64e.dylib" \
    -output "$OUT"
rm -f "$BASE/l8keychain_arm64.dylib" "$BASE/l8keychain_arm64e.dylib"
"$LDID" -S -Icom.liter8.l8keychain -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*)  ;; *) echo "[!] missing arm64 slice"  >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
# The interpose section is the whole mechanism: two entries, wrap + unwrap,
# each entry a replacement/replacee pointer pair (0x20 bytes total).
n=$(otool -arch arm64 -l "$OUT" | grep -A3 'sectname __interpose' | awk '/size/{print $2}' | head -1)
[ "$n" = "0x0000000000000020" ] \
    || { echo "[!] interpose section is $n, expected 0x0000000000000020 (2 entries)" >&2; exit 1; }
otool -arch arm64 -L "$OUT" | grep -q '/System/Library/PrivateFrameworks/AppleKeyStore.framework/AppleKeyStore' \
    || { echo "[!] l8keychain does not link AppleKeyStore.framework" >&2; exit 1; }
# The tbd declares exactly two symbols; the link must import exactly those
# (each appears twice in the indirect-symbol table: import pointer + interpose
# entry, so the check counts unique names).
imports=$(otool -arch arm64 -Iv "$OUT" 2>/dev/null | grep '_aks_' | awk '{print $3}' | sort -u | wc -l | tr -d ' ')
[ "$imports" = "2" ] || { echo "[!] expected 2 unique aks_* imports, found $imports" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] l8keychain unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, securityd-only software class-key interposer)"
