#!/bin/sh
# Build the minimal universal hook that launchd weak-loads before main().

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$BASE/../../tools"
# The bundled ldid links only system libraries, so a Homebrew upgrade
# cannot break it, and its output is byte-identical. It is arm64 only,
# so fall back to PATH where it cannot run, such as an Intel Mac.
# See https://github.com/Xplo8E/Liter8/issues/2.
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/lhook.dylib"

# -x passes for an arm64 binary on an Intel Mac, so check that it runs and
# identifies itself. ldid -v exits non-zero even when it works.
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

# Name the slice. Without -arch, an Intel host matches neither arm64 nor
# arm64e, so otool prints both with a header each and the second header reads
# as a dependency. See https://github.com/Xplo8E/Liter8/issues/2.
verify_deps() {
    binary=$1
    label=$2
    expected=$3
    for slice in arm64 arm64e; do
        actual=$(otool -arch "$slice" -L "$binary" | awk 'NR > 1 {print $1}')
        [ "$actual" = "$expected" ] || {
            printf '[!] %s (%s) has unexpected dependencies:\n%s\n' \
                "$label" "$slice" "$actual" >&2
            exit 1
        }
    done
}

for arch in arm64 arm64e; do
    xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib -O2 -Wall -Wextra \
        -Wl,-not_for_dyld_shared_cache -install_name /usr/lib/lhook \
        -o "$BASE/lhook_$arch.dylib" "$BASE/lhook.c"
done

lipo -create "$BASE/lhook_arm64.dylib" "$BASE/lhook_arm64e.dylib" -output "$OUT"
rm -f "$BASE/lhook_arm64.dylib" "$BASE/lhook_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac

interpose=$(otool -l "$OUT" | grep -c __interpose || true)
[ "$interpose" -ge 1 ] || { echo "[!] hook has no __interpose section" >&2; exit 1; }
strings -a "$OUT" | grep -q '^/var/jb/usr/lib/TweakLoader.dylib$' \
    || { echo "[!] TweakLoader payload path missing" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] lhook unexpectedly carries entitlements" >&2; exit 1; }
verify_deps "$OUT" lhook "/usr/lib/lhook
/usr/lib/libSystem.B.dylib"

echo "[+] $OUT ($archs, $interpose interpose section)"

build_universal() {
    name=$1
    source=$2
    kind=$3
    for arch in arm64 arm64e; do
        extra=""
        [ "$kind" = dylib ] && extra="-dynamiclib -Wl,-not_for_dyld_shared_cache -install_name /usr/lib/systemhook.dylib"
        # extra is intentionally word-split: it is a fixed, source-controlled linker option set.
        # shellcheck disable=SC2086
        xcrun -sdk iphoneos clang -arch "$arch" -miphoneos-version-min=15.0 \
            -isysroot "$SDK" -O2 -Wall -Wextra $extra \
            -o "$BASE/${name}_$arch" "$BASE/$source"
    done
    lipo -create "$BASE/${name}_arm64" "$BASE/${name}_arm64e" -output "$BASE/$name"
    rm -f "$BASE/${name}_arm64" "$BASE/${name}_arm64e"
    "$LDID" -S -Cadhoc "$BASE/$name"
    archs=$(lipo -archs "$BASE/$name")
    case " $archs " in *" arm64 "*)  ;; *) echo "[!] $name lacks arm64" >&2; exit 1 ;; esac
    case " $archs " in *" arm64e "*) ;; *) echo "[!] $name lacks arm64e" >&2; exit 1 ;; esac
    [ -z "$("$LDID" -e "$BASE/$name")" ] \
        || { echo "[!] $name unexpectedly carries entitlements" >&2; exit 1; }
    echo "[+] $BASE/$name ($archs)"
}

build_universal systemhook.dylib systemhook_icon.c dylib
build_universal sbextissue sbextissue.c executable

verify_deps "$BASE/systemhook.dylib" systemhook "/usr/lib/systemhook.dylib
/usr/lib/libSystem.B.dylib"

verify_deps "$BASE/sbextissue" sbextissue "/usr/lib/libSystem.B.dylib"
