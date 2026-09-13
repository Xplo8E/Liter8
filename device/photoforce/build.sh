#!/bin/sh
set -eu

cd "$(dirname "$0")"

LDID=../../tools/ldid_macosx_arm64

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
