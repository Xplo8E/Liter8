#!/bin/sh
# Build l8localauth.dylib, the SEP-less passcode-confirmation translator, plus
# run its self-test. Ad-hoc signed; no get-task-allow (AMFI SIGKILLs an ad-hoc
# binary carrying it). No entitlement: it swizzles LAContext in its own process.
set -e
cd "$(dirname "$0")"
LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

# Self-test on the host first: translation logic plus the passcode-set gate
# (its LocalAuthenticationCore classes exist on macOS too) and the software
# ACM crypto core. The sandbox marker overrides let the unprivileged test run
# satisfy the root-owner gate check.
if command -v clang >/dev/null 2>&1 && [ "$(uname)" = Darwin ]; then
    xcrun clang -DLITER8_LOCALAUTH_TEST \
        -DLITER8_LOCALAUTH_MARKER="\"/tmp/l8la-sandbox/marker\"" \
        -DLITER8_LOCALAUTH_MARKER_UID="$(id -u)" \
        -framework Foundation -framework LocalAuthentication \
        l8localauth.m l8_acm.m l8_acmpool.m l8_acmdaemon.m l8_passcodematch.m l8_acm_core.c -o .l8localauth-test
    mkdir -p /tmp/l8la-sandbox
    ./.l8localauth-test
    rm -f .l8localauth-test /tmp/l8la-sandbox/marker
fi

xcrun clang -isysroot "$SDK" -arch arm64 -arch arm64e \
    -miphoneos-version-min=15.0 -O2 -Wall -Wextra -dynamiclib \
    -Wl,-not_for_dyld_shared_cache -install_name /var/jb/usr/lib/TweakInject/l8localauth.dylib \
    -framework Foundation \
    l8localauth.m l8_acm.m l8_acmpool.m l8_acmdaemon.m l8_passcodematch.m l8_acm_core.c -o l8localauth.dylib
# The filter reaches every Objective-C process; linking LocalAuthentication
# would load it into all of them. The hook installs when LAContext appears.
otool -L l8localauth.dylib | grep -q LocalAuthentication \
    && { echo "[!] l8localauth links LocalAuthentication" >&2; exit 1; }
"$LDID" -S -Icom.liter8.l8localauth -Cadhoc l8localauth.dylib
codesign -d --entitlements :- l8localauth.dylib 2>/dev/null | grep -q get-task-allow \
    && { echo "[!] l8localauth carries get-task-allow, AMFI will kill it"; exit 1; }
echo "[+] l8localauth.dylib  $(wc -c < l8localauth.dylib | tr -d ' ') bytes"
