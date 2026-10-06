#!/bin/sh
set -eu

cd "$(dirname "$0")"

# The bundled ldid links only system libraries, so a Homebrew upgrade
# cannot break it, and its output is byte-identical. It is arm64 only,
# so fall back to PATH where it cannot run, such as an Intel Mac.
# See https://github.com/Xplo8E/Liter8/issues/2.
LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)

xcrun -sdk iphoneos clang \
    -arch arm64 -arch arm64e -miphoneos-version-min=26.0 -O2 -Wall \
    -framework Foundation pfruntimeprobe.m -o pfruntimeprobe
xcrun -sdk iphoneos clang \
    -arch arm64 -arch arm64e -miphoneos-version-min=26.0 -O2 -Wall \
    -framework Foundation pfwatch.m -o pfwatch

for binary in pfruntimeprobe pfwatch; do
    "$LDID" -Spfruntimeprobe.ent -Cadhoc "$binary"
    archs=$(lipo -archs "$binary")
    case " $archs " in *" arm64 "*) ;; *) echo "[!] $binary missing arm64" >&2; exit 1;; esac
    case " $archs " in *" arm64e "*) ;; *) echo "[!] $binary missing arm64e" >&2; exit 1;; esac
    codesign -v "$binary"
    echo "[+] $binary: $archs"
done
