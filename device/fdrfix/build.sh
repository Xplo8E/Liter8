#!/bin/sh
# Build the CommCenter-only FDR sik-verification bypass for both device ABIs,
# and l8radio, the airplane-mode toggle used to force a baseband reset while
# testing this path. Only l8fdr.dylib is deployed; l8radio is a hand tool that
# fetch_payloads.sh does not ship.
#
# The data-activation gate is NOT handled here. Patching the DataSettings
# vtable from inside CommCenter was tried and cannot work: vm_protect on those
# __DATA_CONST pages returns KERN_PROTECTION_FAILURE because max protection no
# longer carries write once dyld has applied fixups, and the device boots SPTM,
# so the process cannot grant itself write. That gate is a binary patch
# instead, resolved semantically by CommCenterDataActivationResolver.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/l8fdr.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

for arch in arm64 arm64e; do
    xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra -Werror \
        -Wl,-not_for_dyld_shared_cache -install_name /usr/lib/l8fdr.dylib \
        -framework CoreFoundation \
        -o "$BASE/l8fdr_$arch.dylib" "$BASE/l8fdr.c"
done

lipo -create "$BASE/l8fdr_arm64.dylib" "$BASE/l8fdr_arm64e.dylib" -output "$OUT"
rm -f "$BASE/l8fdr_arm64.dylib" "$BASE/l8fdr_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
for arch in arm64 arm64e; do
    # No interposing. The os_variant_is_recovery route was measured not to work
    # from a late-loaded dylib against a shared-cache-internal call, so an
    # __interpose section reappearing here means the dylib regressed to it.
    otool -arch "$arch" -l "$OUT" | grep -q 'sectname __interpose' \
        && { echo "[!] l8fdr $arch unexpectedly contains an interpose section" >&2; exit 1; }
done
# The whole mechanism is this one libFDR export. If it is not imported, the
# dylib loads, logs and changes nothing.
strings -a "$OUT" | grep -q '^AMFDRSealingMapRegisterCustomQueryProvider$' \
    || { echo "[!] the libFDR registration symbol is absent" >&2; exit 1; }
for key in CertificateSecurityMode EffectiveSecurityModeSEP EffectiveProductionStatusAp; do
    strings -a "$OUT" | grep -qx "$key" \
        || { echo "[!] demotion-state key $key is absent" >&2; exit 1; }
done
strings -a "$OUT" | grep -q '^CommCenter$' \
    || { echo "[!] the CommCenter process guard is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^/usr/lib/\.liter8-fdr-sik-bypass$' \
    || { echo "[!] the FDR marker gate is absent" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] l8fdr unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, CommCenter-only marker-gated FDR sik bypass)"

# l8radio. arm64e only: it runs on the device by hand, never in the arm64 slice
# of an injected payload. RadiosPreferences is private, so it is resolved at
# runtime and nothing here links it.
RADIO="$BASE/l8radio"
xcrun -sdk iphoneos clang -arch arm64e -miphoneos-version-min=15.0 \
    -isysroot "$SDK" -O2 -Wall -Wextra -Werror -fobjc-arc \
    -framework Foundation -o "$RADIO" "$BASE/l8radio.m"
"$LDID" -S "$RADIO"
strings -a "$RADIO" | grep -q '^RadiosPreferences$' \
    || { echo "[!] l8radio does not reference RadiosPreferences" >&2; exit 1; }
echo "[+] $RADIO (arm64e, airplane-mode toggle for forcing a baseband reset)"
