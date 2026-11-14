#!/bin/sh
# l8keychain v2 status and cleanup helper.
#
# The v1 TweakInject route (dylib + Foundation filter plist in
# /var/jb/usr/lib/TweakInject, MSHookFunction) is RETIRED: securityd never
# loads TweakInject, and shipping an interposer of aks_wrap_key/aks_unwrap_key
# to every app process is wrong by construction. The active route is the
# weak-load one: /usr/lib/l8keychain.dylib on the sealed System volume plus an
# LC_LOAD_WEAK_DYLIB appended to securityd, installed by the keychain step of
# sshrd_provision.sh. This script reports that state and removes the v1
# leftovers; it changes nothing about the active route.
#
# Requires SSH (sshrd or the normal-boot dropbear) via liter8/tools/sshdev.
set -e
SSH="${SSH:-/Volumes/vinay-ssd/iphone11-usbliter8/liter8/tools/sshdev}"

echo "== active weak-load route =="
"$SSH" 'ls -la /usr/lib/l8keychain.dylib /usr/lib/.liter8-keychain 2>/dev/null; echo ---; /usr/bin/otool -L /usr/libexec/securityd 2>/dev/null | grep -i l8keychain || echo "securityd has no weak load command (not provisioned yet)"'

echo "== retired TweakInject leftovers =="
"$SSH" 'ls -la /var/jb/usr/lib/TweakInject/l8keychain.dylib /var/jb/usr/lib/TweakInject/l8keychain.plist 2>/dev/null || echo none'

echo
echo "Removing retired leftovers? [y/N]"
read -r answer
if [ "$answer" = "y" ]; then
    "$SSH" 'rm -f /var/jb/usr/lib/TweakInject/l8keychain.dylib /var/jb/usr/lib/TweakInject/l8keychain.plist && echo removed'
fi
