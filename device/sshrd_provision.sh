#!/bin/sh
# sshrd_provision.sh - everything that has to happen from SSHRD, in one pass.
#
# Run on the HOST with the device booted into SSHRD. It stages payloads over
# ssh and runs the device-side work, then verifies. Every step is idempotent:
# re-running is safe and already-done steps are skipped, so this can be used
# both for a fresh restore and to top up a device after a partial run.
#
# The System volume is read-only on a normal boot, which is the only reason any
# of this needs SSHRD at all. Group it here so one trip does the lot.
#
#   ./sshrd_provision.sh              # everything
#   ./sshrd_provision.sh --list       # show the steps
#   ./sshrd_provision.sh resolv apps  # only the named steps
#   ./sshrd_provision.sh --check      # mount volumes and verify end state
#
# Nothing is deleted. Replaced files keep a .orig; replaced directories a .prev.

set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE"

# Host-side helper binaries. Resolved from $BASE rather than the working
# directory so the script works when invoked by an absolute path. Where tools/
# sits is the only thing that differs between the repo and research copies, so
# it is resolved once here rather than spelled out at each call site.
TOOLS="$BASE/../tools"

SSHPASS="$TOOLS/sshpass"
SSHOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=25 -p 2222"
DEV="root@localhost"
PW=alpine

IPSW_ROOT=${IPSW_ROOT:-/tmp/ios27-rootfs} # decrypted root filesystem, mounted
STAGE=/mnt2/_provision                # device-side staging, Data volume
LAUNCHD_SHA=${LITER8_LAUNCHD_SHA:?Liter8 did not provide the reviewed launchd hash}
LAUNCHD_CACHE_SHA=${LITER8_LAUNCHD_CACHE_SHA:?Liter8 did not provide the reviewed launchd cache hash}
LAUNCHD_CACHE_DAEMONS=${LITER8_LAUNCHD_CACHE_DAEMONS:?Liter8 did not provide the reviewed launchd daemon count}
SETUP_METHODS=${LITER8_SETUP_METHODS:?Liter8 did not provide the reviewed Setup method count}

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    [+] %s\n' "$1"; }
skip() { printf '    [=] %s\n' "$1"; }
die()  { printf '    [!] %s\n' "$1"; exit 1; }

# shellcheck disable=SC2086  # $SSHOPT is an option LIST and must word-split
sh_dev() { timeout 900 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" "$@"; }

# Single-quoted bodies passed to must_dev/sh_dev are deliberate: the variables
# inside them belong to the DEVICE and must not be expanded on the host. Linters
# will flag those quotes as a mistake; they are not. Run the linter with that
# check suppressed rather than "fixing" the quoting.
#
# Run device-side work and require it to print DONE_OK as its last act.
# ssh's exit status is not trustworthy enough on its own here: it reports the
# transport result, and `set -e` does not propagate out of $(...) or pipelines.
# An explicit marker is unambiguous.
must_dev() {
    _out=$(sh_dev "$1" 2>&1) || true
    if ! printf '%s' "$_out" | grep -q DONE_OK; then
        printf '%s\n' "$_out" | sed 's/^/        /'
        die "${2:-device step failed}"
    fi
    printf '%s' "$_out" | grep -v DONE_OK | sed 's/^/        /' || true
}

# Copy a file to the device and verify the byte count landed.
put() {
    [ -f "$1" ] || die "missing local file: $1"
    _sz=$(wc -c < "$1" | tr -d ' ')
    # shellcheck disable=SC2086  # same: $SSHOPT must word-split
    timeout 900 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" "cat > $2" < "$1" \
        || die "transfer failed: $1 -> $2"
    # tr runs on the HOST here (output of ssh), so it is fine
    _got=$(sh_dev "wc -c < $2" 2>/dev/null | tr -d ' \r')
    [ "$_got" = "$_sz" ] || die "short write: $2 is $_got bytes, expected $_sz"
}

STEPS="mounts ticket setup userland screentime injection cache jbtools sileo resolv apps verify"

usage() {
    echo "steps: $STEPS"
    echo "  mounts   mount System rw, Data and Preboot (always runs first)"
    echo "  ticket   extract this restore's APTicket from Preboot"
    echo "  setup    patch Setup.app to skip unavailable first-run panes"
    echo "  userland patch and re-sign the SEP/activation daemons"
    echo "  screentime make Setup's unavailable ScreenTime requests fail fast"
    echo "  injection install launchd hook plus icon grant, disabled for first boot"
    echo "  cache    deploy the launchd service cache (dropbear + jbboot)"
    echo "  jbtools  install boot helpers and the iOS 27 uicache"
    echo "  sileo      install Sileo (from payload/, built by fetch_payloads.sh)"
    # TrollStore is not installed here. It goes on after first boot from a deb,
    # so it can be updated without another DFU trip. See COMMANDS.md.
    echo "  resolv   write /private/etc/resolv.conf so CLI DNS works"
    echo "  apps     copy the 50 removable system apps into /Applications"
    echo "  verify   check the end state"
    exit 0
}

CHECK_ONLY=0
case "${1:-}" in
    --list|-h|--help) usage ;;
    --check) CHECK_ONLY=1; WANT="mounts verify" ;;
    "") WANT="$STEPS" ;;
    *) WANT="mounts $* verify" ;;
esac

wants() { case " $WANT " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Reap an owned USB forward before the shell exits. Provisioning runs directly
# after install_dropbear.sh, and allowing either phase's old iproxy to linger
# can make the next SSH connection authenticate through a dying transport.
stop_owned_iproxy() {
    kill "$IPROXY_PID" 2>/dev/null || true
    wait "$IPROXY_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------- preflight
say "preflight"
[ -x "$SSHPASS" ] || die "sshpass not found at $SSHPASS"
command -v timeout >/dev/null 2>&1 || die "timeout not found (brew install coreutils)"
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    command -v iproxy >/dev/null 2>&1 || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222 22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap stop_owned_iproxy EXIT
    sleep 2
fi
sh_dev 'exit 0' >/dev/null 2>&1 || die "cannot reach SSH on port 2222 (is SSHRD booted?)"

sh_dev '/sbin/mount | /usr/bin/grep -q "md0 on /"' \
    || die "device is NOT in SSHRD. Refusing; this would write to the wrong place."
ok "device is in SSHRD"

# ------------------------------------------------------------------ mounts
say "mounts"
# Preboot holds the restore-bound APTicket extracted by the ticket step below. The ramdisk
# mounts only System and Data on its own, so searching an unmounted /mnt6 would otherwise
# look like a missing ticket. The ticket step requires exactly one matching image.
must_dev '
mkdir -p /mnt1 /mnt2 /mnt6 2>/dev/null
/sbin/mount_apfs /dev/disk1s1 /mnt1 2>/dev/null
/sbin/mount_apfs /dev/disk1s2 /mnt2 2>/dev/null
/sbin/mount_apfs /dev/disk1s6 /mnt6 2>/dev/null
/sbin/mount -u -o rw /dev/disk1s1 2>/dev/null
/sbin/mount -u -o rw /dev/disk1s2 2>/dev/null
[ -d /mnt1/Applications ] || { echo "System volume not mounted"; exit 1; }
[ -d /mnt2/jb ] || { echo "bootstrap is absent at /mnt2/jb; run liter8 fw bootstrap first"; exit 1; }
touch /mnt1/Applications/.wtest 2>/dev/null || { echo "System volume NOT writable"; exit 1; }
rm -f /mnt1/Applications/.wtest
touch /mnt2/.wtest 2>/dev/null || { echo "Data volume NOT writable"; exit 1; }
rm -f /mnt2/.wtest
echo DONE_OK
' "could not mount System and Data read-write"
ok "System and Data rw, Preboot mounted"
sh_dev "mkdir -p $STAGE" >/dev/null

# --------------------------------------------------------------- APTicket
if wants ticket && [ "$CHECK_ONLY" = 0 ]; then
    say "restore-bound APTicket"
    mkdir -p payload/.work
    sep_paths=$(sh_dev '/usr/bin/find /mnt6 -type f -name sep-firmware.img4 2>/dev/null' \
        | tr -d '\r')
    sep_count=$(printf '%s\n' "$sep_paths" | sed '/^$/d' | wc -l | tr -d ' ')
    [ "$sep_count" = 1 ] \
        || die "expected one sep-firmware.img4 in Preboot, found $sep_count"
    sep_path=$(printf '%s\n' "$sep_paths" | sed -n '1p')

    sep_new=payload/.work/dev_sep.img4.new
    ticket_new=payload/.work/t8030_apticket.der.new
    rm -f "$sep_new" "$ticket_new"
    sh_dev "/bin/cat '$sep_path'" > "$sep_new" \
        || die "could not read $sep_path"
    [ -s "$sep_new" ] || die "downloaded sep-firmware.img4 is empty"
    "$TOOLS/img4tool" -e -m "$ticket_new" "$sep_new" >/dev/null \
        || die "img4tool could not extract the APTicket"
    [ -s "$ticket_new" ] || die "extracted APTicket is empty"

    [ ! -f dev_sep.img4 ] \
        || cp -p dev_sep.img4 payload/.work/dev_sep.img4.prev
    [ ! -f t8030_apticket.der ] \
        || cp -p t8030_apticket.der payload/.work/t8030_apticket.der.prev
    mv -f "$sep_new" dev_sep.img4
    mv -f "$ticket_new" t8030_apticket.der
    ok "t8030_apticket.der extracted ($(wc -c < t8030_apticket.der | tr -d ' ') bytes)"
fi

# ------------------------------------------------------------------- Setup
if wants setup && [ "$CHECK_ONLY" = 0 ]; then
    say "Setup.app first-run panes"
    mkdir -p payload/.work
    setup_dev=/mnt1/Applications/Setup.app/Setup
    setup_local=payload/.work/Setup.pristine
    setup_patched=payload/.work/Setup.patched
    setup_entitlements=payload/.work/Setup.entitlements.plist
    setup_stage=${setup_dev}.usbl8r-new

    sh_dev "[ -f '$setup_dev' ]" || die "Setup executable missing at $setup_dev"
    # Always rebuild from Apple's preserved executable. Re-patching the deployed
    # copy is byte-safe, but it cannot recover the signing metadata that an older
    # broken provisioning pass may already have invalidated.
    sh_dev "if [ -f '$setup_dev.orig' ]; then /bin/cat '$setup_dev.orig'; else /bin/cat '$setup_dev'; fi" \
        > "$setup_local" || die "could not read the pristine Setup executable"
    [ -s "$setup_local" ] || die "downloaded Setup executable is empty"
    cp "$setup_local" "$setup_patched"
    python3 patch_setup.py "$setup_patched" --apply \
        --expect-count "$SETUP_METHODS" \
        --records payload/.work/Setup.records.json >/dev/null \
        || die "Setup patch failed"

    # Raw instruction edits invalidate the embedded CodeDirectory. That reaches
    # launchd as BADEXEC (0x55), then SpringBoard aborts until launchd reboots the
    # phone. Preserve Apple's complete entitlement set and bundle identifier while
    # replacing the stale signature, exactly as the successful beta-4 research did.
    "$TOOLS/ldid_macosx_arm64" -e "$setup_local" > "$setup_entitlements" \
        || die "could not read Setup entitlements"
    [ -s "$setup_entitlements" ] || die "Setup entitlement plist is empty"
    setup_identifier=$(codesign -d --verbose=4 "$setup_local" 2>&1 \
        | sed -n 's/^Identifier=//p' | sed -n '1p')
    [ "$setup_identifier" = com.apple.purplebuddy ] \
        || die "unexpected Setup signing identifier: ${setup_identifier:-missing}"
    "$TOOLS/ldid_macosx_arm64" -I"$setup_identifier" \
        -S"$setup_entitlements" -Cadhoc "$setup_patched" \
        || die "could not re-sign patched Setup"
    codesign -v "$setup_patched" \
        || die "patched Setup has an invalid CodeDirectory"
    [ "$(codesign -d --verbose=4 "$setup_patched" 2>&1 | sed -n 's/^Identifier=//p' | sed -n '1p')" = "$setup_identifier" ] \
        || die "patched Setup signing identifier changed"
    [ "$("$TOOLS/ldid_macosx_arm64" -e "$setup_patched")" = "$(cat "$setup_entitlements")" ] \
        || die "patched Setup entitlements changed"

    setup_sha=$(shasum -a 256 "$setup_patched" | awk '{print $1}')
    put "$setup_patched" "$setup_stage"
    sh_dev "/bin/cat '$setup_stage'" > payload/.work/Setup.staged
    [ "$(shasum -a 256 payload/.work/Setup.staged | awk '{print $1}')" = "$setup_sha" ] \
        || die "staged Setup hash mismatch"
    must_dev "
[ -f '$setup_dev.orig' ] || cp '$setup_dev' '$setup_dev.orig'
chmod 0755 '$setup_stage'
mv -f '$setup_stage' '$setup_dev'
echo DONE_OK
" "could not activate patched Setup executable"
    sh_dev "/bin/cat '$setup_dev'" > payload/.work/Setup.readback
    [ "$(shasum -a 256 payload/.work/Setup.readback | awk '{print $1}')" = "$setup_sha" ] \
        || die "Setup readback hash mismatch"
    ok "Setup patched, entitlement-preserving signature verified, deployed and read back"
fi

# --------------------------------------------------------------- userland
# These three daemons are ordinary files on the System volume, but their
# failures happen late enough to resemble a bad kernel boot. Build every patch
# from the device's preserved .orig file so retries never patch an already
# modified executable. Swift finds the instructions; Python only preserves the
# original signing identity and entitlements.
build_userland_patch() {
    U_NAME=$1
    U_DEVICE=$2
    U_DIR=payload/.work/userland
    U_PRISTINE=$U_DIR/$U_NAME.pristine
    U_PATCHED=$U_DIR/$U_NAME.patched
    U_RECORDS=$U_DIR/$U_NAME.records.json
    mkdir -p "$U_DIR"

    sh_dev "if [ -f '$U_DEVICE.orig' ]; then /bin/cat '$U_DEVICE.orig'; else /bin/cat '$U_DEVICE'; fi" \
        > "$U_PRISTINE" || die "could not read pristine $U_NAME from the device"
    [ -s "$U_PRISTINE" ] || die "pristine $U_NAME is empty"

    python3 userland_fixups.py binary "$U_NAME" "$U_PRISTINE" "$U_PATCHED" "$U_RECORDS" \
        --liter8 "$LITER8_SELF" --ldid "$TOOLS/ldid_macosx_arm64" \
        || die "could not build the $U_NAME fix"
}

deploy_userland_patch() {
    U_NAME=$1
    U_DEVICE=$2
    U_PATCHED=payload/.work/userland/$U_NAME.patched
    U_STAGED=$U_DEVICE.liter8-new
    U_READBACK=payload/.work/userland/$U_NAME.readback
    U_WANT=$(shasum -a 256 "$U_PATCHED" | awk '{print $1}')

    put "$U_PATCHED" "$U_STAGED"
    must_dev "
[ -f '$U_DEVICE.orig' ] || cp '$U_DEVICE' '$U_DEVICE.orig'
chmod 0755 '$U_STAGED'
mv -f '$U_STAGED' '$U_DEVICE'
echo DONE_OK
" "could not activate patched $U_NAME"

    sh_dev "/bin/cat '$U_DEVICE'" > "$U_READBACK" \
        || die "could not read back $U_NAME"
    U_GOT=$(shasum -a 256 "$U_READBACK" | awk '{print $1}')
    [ "$U_GOT" = "$U_WANT" ] || die "$U_NAME readback hash mismatch"
    ok "$U_NAME deployed and read back ($U_WANT)"
}

if wants userland && [ "$CHECK_ONLY" = 0 ]; then
    say "post-restore userland crash fixes"
    for U_NAME in coreauthd mobileactivationd ctkd; do
        case "$U_NAME" in
            coreauthd)
                U_DEVICE=/mnt1/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd
                ;;
            mobileactivationd)
                U_DEVICE=/mnt1/usr/libexec/mobileactivationd
                ;;
            ctkd)
                U_DEVICE=/mnt1/System/Library/Frameworks/CryptoTokenKit.framework/ctkd
                ;;
        esac
        sh_dev "[ -f '$U_DEVICE' ]" || die "$U_NAME is absent at $U_DEVICE"
        build_userland_patch "$U_NAME" "$U_DEVICE"
        deploy_userland_patch "$U_NAME" "$U_DEVICE"
    done
fi

# ------------------------------------------------------------- ScreenTime
# ScreenTimeAgent accepts Setup's XPC request but cannot answer in this SEP-less
# environment. Refusing its on-demand launch makes Setup fail fast instead of
# waiting for the watchdog and restarting at the Hello screen.
if wants screentime && [ "$CHECK_ONLY" = 0 ]; then
    say "ScreenTime Setup deadlock override"
    DISABLED_DEVICE=/mnt2/db/com.apple.xpc.launchd/disabled.plist
    DISABLED_LOCAL=payload/.work/disabled.plist
    DISABLED_STAGE=$DISABLED_DEVICE.liter8-new
    mkdir -p payload/.work

    if sh_dev "[ -f '$DISABLED_DEVICE' ]"; then
        sh_dev "/bin/cat '$DISABLED_DEVICE'" > "$DISABLED_LOCAL" \
            || die "could not read launchd disabled overrides"
    else
        # userland_fixups.py deliberately treats a missing input as an empty
        # database. Do not create a zero-byte file, which is not a valid plist.
        unlink "$DISABLED_LOCAL" 2>/dev/null || true
    fi
    python3 userland_fixups.py screen-time "$DISABLED_LOCAL" \
        || die "could not build ScreenTime overrides"
    put "$DISABLED_LOCAL" "$DISABLED_STAGE"
    must_dev "
mkdir -p /mnt2/db/com.apple.xpc.launchd
if [ -f '$DISABLED_DEVICE' ] && [ ! -f '$DISABLED_DEVICE.orig' ]; then
    cp '$DISABLED_DEVICE' '$DISABLED_DEVICE.orig'
fi
chmod 0644 '$DISABLED_STAGE'
mv -f '$DISABLED_STAGE' '$DISABLED_DEVICE'
echo DONE_OK
" "could not install ScreenTime overrides"
    sh_dev "/bin/cat '$DISABLED_DEVICE'" > payload/.work/disabled.readback \
        || die "could not read back ScreenTime overrides"
    cmp "$DISABLED_LOCAL" payload/.work/disabled.readback \
        || die "ScreenTime override readback mismatch"
    ok "five ScreenTime and FamilyControls override labels installed"
fi

# --------------------------------------------------------------- injection
if wants injection && [ "$CHECK_ONLY" = 0 ]; then
    say "launchd injection bootstrap"
    for required in payload/launchd.orig payload/launchd.hooked \
                    payload/lhook.dylib payload/systemhook.dylib payload/sbextissue \
                    launchdhook/lhook.deny; do
        [ -f "$required" ] || die "$required absent; run ./fetch_payloads.sh injection"
    done

    stock_sha=$(shasum -a 256 payload/launchd.orig | awk '{print $1}')
    hooked_sha=$(shasum -a 256 payload/launchd.hooked | awk '{print $1}')
    hook_sha=$(shasum -a 256 payload/lhook.dylib | awk '{print $1}')
    systemhook_sha=$(shasum -a 256 payload/systemhook.dylib | awk '{print $1}')
    sbextissue_sha=$(shasum -a 256 payload/sbextissue | awk '{print $1}')
    [ "$stock_sha" = "$LAUNCHD_SHA" ] \
        || die "payload/launchd.orig does not match the selected firmware profile"
    python3 launchdhook/verify_diff.py payload/launchd.orig payload/launchd.hooked >/dev/null \
        || die "launchd payload byte-diff verification failed"
    codesign -v payload/launchd.hooked \
        || die "launchd payload code-slot verification failed"
    for binary in payload/lhook.dylib payload/systemhook.dylib payload/sbextissue; do
        codesign -v "$binary" || die "$binary signature verification failed"
        [ -z "$("$TOOLS/ldid_macosx_arm64" -e "$binary")" ] \
            || die "$binary unexpectedly carries entitlements"
        archs=$(lipo -archs "$binary")
        case " $archs " in *" arm64 "*)  ;; *) die "$binary is missing arm64"  ;; esac
        case " $archs " in *" arm64e "*) ;; *) die "$binary is missing arm64e" ;; esac
    done
    otool -l payload/lhook.dylib | grep -q __interpose \
        || die "lhook has no __interpose section"
    ok "host payload verified before any boot-critical write"

    mkdir -p payload/.work
    sh_dev 'cat /mnt1/sbin/launchd' > payload/.work/launchd.ondevice \
        || die "could not read on-device /sbin/launchd"
    current_sha=$(shasum -a 256 payload/.work/launchd.ondevice | awk '{print $1}')
    case "$current_sha" in
        "$stock_sha") current_state=stock ;;
        "$hooked_sha") current_state=hooked ;;
        *) die "on-device /sbin/launchd is neither reviewed stock nor reviewed hooked ($current_sha)" ;;
    esac
    ok "on-device launchd is $current_state"

    if sh_dev '[ -f /mnt1/sbin/launchd.bak ]'; then
        sh_dev 'cat /mnt1/sbin/launchd.bak' > payload/.work/launchd.bak.ondevice \
            || die "could not read /sbin/launchd.bak"
        backup_sha=$(shasum -a 256 payload/.work/launchd.bak.ondevice | awk '{print $1}')
        [ "$backup_sha" = "$stock_sha" ] \
            || die "existing /sbin/launchd.bak is not exact stock ($backup_sha)"
    elif [ "$current_state" = stock ]; then
        sh_dev 'cp /mnt1/sbin/launchd /mnt1/sbin/launchd.bak' \
            || die "could not back up stock launchd"
    else
        put payload/launchd.orig /mnt1/sbin/launchd.bak
    fi
    sh_dev 'chmod 0755 /mnt1/sbin/launchd.bak' \
        || die "could not make launchd backup executable"
    ok "exact stock backup preserved at /sbin/launchd.bak"

    sh_dev 'mkdir -p /mnt1/usr/lib /mnt1/usr/local/bin /mnt2/jb/etc' \
        || die "could not create injection directories"
    must_dev '
if [ -f /mnt1/usr/lib/lhook.dylib ] && [ ! -f /mnt1/usr/lib/lhook.dylib.orig ]; then
    cp /mnt1/usr/lib/lhook.dylib /mnt1/usr/lib/lhook.dylib.orig
fi
if [ -f /mnt1/usr/lib/systemhook.dylib ] && [ ! -f /mnt1/usr/lib/systemhook.dylib.orig ]; then
    cp /mnt1/usr/lib/systemhook.dylib /mnt1/usr/lib/systemhook.dylib.orig
fi
if [ -f /mnt1/usr/local/bin/sbextissue ] && [ ! -f /mnt1/usr/local/bin/sbextissue.orig ]; then
    cp /mnt1/usr/local/bin/sbextissue /mnt1/usr/local/bin/sbextissue.orig
fi
if [ -f /mnt2/jb/etc/lhook.deny ] && [ ! -f /mnt2/jb/etc/lhook.deny.orig ]; then
    cp /mnt2/jb/etc/lhook.deny /mnt2/jb/etc/lhook.deny.orig
fi
echo DONE_OK
' "could not preserve existing injection files"
    put payload/launchd.hooked /mnt1/sbin/launchd.usbl8r-new
    put payload/lhook.dylib /mnt1/usr/lib/lhook.dylib.usbl8r-new
    put payload/systemhook.dylib /mnt1/usr/lib/systemhook.dylib.usbl8r-new
    put payload/sbextissue /mnt1/usr/local/bin/sbextissue.usbl8r-new
    put launchdhook/lhook.deny /mnt2/jb/etc/lhook.deny.new
    sh_dev 'cat /mnt1/sbin/launchd.usbl8r-new' > payload/.work/launchd.staged
    sh_dev 'cat /mnt1/usr/lib/lhook.dylib.usbl8r-new' > payload/.work/lhook.staged
    sh_dev 'cat /mnt1/usr/lib/systemhook.dylib.usbl8r-new' > payload/.work/systemhook.staged
    sh_dev 'cat /mnt1/usr/local/bin/sbextissue.usbl8r-new' > payload/.work/sbextissue.staged
    [ "$(shasum -a 256 payload/.work/launchd.staged | awk '{print $1}')" = "$hooked_sha" ] \
        || die "staged launchd hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/lhook.staged | awk '{print $1}')" = "$hook_sha" ] \
        || die "staged lhook hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/systemhook.staged | awk '{print $1}')" = "$systemhook_sha" ] \
        || die "staged systemhook hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/sbextissue.staged | awk '{print $1}')" = "$sbextissue_sha" ] \
        || die "staged sbextissue hash mismatch; original is still active"
    must_dev '
chmod 0755 /mnt1/sbin/launchd.usbl8r-new /mnt1/usr/lib/lhook.dylib.usbl8r-new
chmod 0755 /mnt1/usr/lib/systemhook.dylib.usbl8r-new /mnt1/usr/local/bin/sbextissue.usbl8r-new
chmod 0644 /mnt2/jb/etc/lhook.deny.new
mv -f /mnt1/sbin/launchd.usbl8r-new /mnt1/sbin/launchd
mv -f /mnt1/usr/lib/lhook.dylib.usbl8r-new /mnt1/usr/lib/lhook.dylib
mv -f /mnt1/usr/lib/systemhook.dylib.usbl8r-new /mnt1/usr/lib/systemhook.dylib
mv -f /mnt1/usr/local/bin/sbextissue.usbl8r-new /mnt1/usr/local/bin/sbextissue
mv -f /mnt2/jb/etc/lhook.deny.new /mnt2/jb/etc/lhook.deny
if [ -e /mnt2/jb/.lhook_enabled ]; then
    mv -f /mnt2/jb/.lhook_enabled /mnt2/jb/.lhook_enabled.pre-provision
fi
echo DONE_OK
' "could not install injection payload"

    sh_dev 'cat /mnt1/sbin/launchd' > payload/.work/launchd.readback
    sh_dev 'cat /mnt1/sbin/launchd.bak' > payload/.work/launchd.bak.readback
    sh_dev 'cat /mnt1/usr/lib/lhook.dylib' > payload/.work/lhook.readback
    sh_dev 'cat /mnt1/usr/lib/systemhook.dylib' > payload/.work/systemhook.readback
    sh_dev 'cat /mnt1/usr/local/bin/sbextissue' > payload/.work/sbextissue.readback
    [ "$(shasum -a 256 payload/.work/launchd.readback | awk '{print $1}')" = "$hooked_sha" ] \
        || die "launchd readback hash mismatch"
    [ "$(shasum -a 256 payload/.work/launchd.bak.readback | awk '{print $1}')" = "$stock_sha" ] \
        || die "launchd backup readback hash mismatch"
    [ "$(shasum -a 256 payload/.work/lhook.readback | awk '{print $1}')" = "$hook_sha" ] \
        || die "lhook readback hash mismatch"
    [ "$(shasum -a 256 payload/.work/systemhook.readback | awk '{print $1}')" = "$systemhook_sha" ] \
        || die "systemhook readback hash mismatch"
    [ "$(shasum -a 256 payload/.work/sbextissue.readback | awk '{print $1}')" = "$sbextissue_sha" ] \
        || die "sbextissue readback hash mismatch"
    ok "installed launch hook and icon grant payload; first-boot injection is disabled"
fi

# ------------------------------------------------------------------- cache
if wants cache && [ "$CHECK_ONLY" = 0 ]; then
    say "launchd service cache"
    CACHE=boot/work/launchd.plist
    if [ ! -f "$CACHE" ]; then
        skip "no patched cache at $CACHE; build it with patch_launchd_cache.py + add_jbboot.py"
    else
        n=$(python3 -c "import plistlib,sys;print(len(plistlib.load(open('$CACHE','rb'))['LaunchDaemons']))")
        [ "$n" = "$((LAUNCHD_CACHE_DAEMONS + 2))" ] \
            || die "$CACHE has $n daemons, expected $((LAUNCHD_CACHE_DAEMONS + 2)) for this profile"
        for j in com.dropbear com.jbboot; do
            python3 -c "
import plistlib,sys
d=plistlib.load(open('$CACHE','rb'))['LaunchDaemons']
sys.exit(0 if '/System/Library/LaunchDaemons/$j.plist' in d else 1)" \
                || die "$CACHE is missing the $j job; build it before deploying"
        done
        python3 -c "
import plistlib,sys
from patch_launchd_cache import CACHE_KEY, DROPBEAR_JOB
d=plistlib.load(open('$CACHE','rb'))['LaunchDaemons']
sys.exit(0 if d.get(CACHE_KEY) == DROPBEAR_JOB else 1)" \
            || die "$CACHE contains a stale or modified com.dropbear job"
        ok "cache has $n daemons including com.dropbear and com.jbboot"
        # A stale .orig from another build would make a later rollback worse
        # than the active patch. Bind the preserved source to this profile
        # before changing the boot-critical service cache.
        sh_dev 'T=/mnt1/System/Library/xpc/launchd.plist; if [ -f "$T.orig" ]; then cat "$T.orig"; else cat "$T"; fi' \
            > payload/.work/device.launchd.plist.pristine \
            || die "could not read the device's pristine launchd cache"
        device_cache_sha=$(shasum -a 256 payload/.work/device.launchd.plist.pristine | awk '{print $1}')
        [ "$device_cache_sha" = "$LAUNCHD_CACHE_SHA" ] \
            || die "device launchd cache belongs to another build: $device_cache_sha"
        put "$CACHE" "$STAGE/launchd.plist"
        want=$(wc -c < "$CACHE" | tr -d ' ')
        must_dev "
T=/mnt1/System/Library/xpc/launchd.plist
[ -f \$T ] || { echo 'service cache missing on device'; exit 1; }
[ -f \$T.orig ] || cp \$T \$T.orig
cat $STAGE/launchd.plist > \$T
rm -f $STAGE/launchd.plist
set -- \$(wc -c < \$T); got=\$1
[ \"\$got\" = \"$want\" ] || { echo \"deployed cache is \$got bytes, expected $want\"; exit 1; }
[ -f \$T.sig ] || { echo 'detached launchd.plist.sig is absent'; exit 1; }
echo DONE_OK
" "failed to deploy the service cache"
        ok "deployed, $want bytes (the detached .sig is left in place deliberately)"
    fi
fi

# ----------------------------------------------------------------- jbtools
if wants jbtools && [ "$CHECK_ONLY" = 0 ]; then
    say "per-boot tools into System /usr/local and /var/jb"
    mkdir -p payload/.work
    for required in boot/jbboot.sh spawnprobe/personaalloc \
                    photoforce/pfwatch photoforce/pfruntimeprobe payload/uicache; do
        [ -f "$required" ] || die "$required absent; run ./fetch_payloads.sh helpers"
    done
    sh_dev "mkdir -p /mnt1/usr/local/bin /mnt2/jb/bin /mnt2/jb/usr/bin" >/dev/null
    put boot/jbboot.sh /mnt1/usr/local/bin/jbboot.sh
    sh_dev 'chmod 755 /mnt1/usr/local/bin/jbboot.sh'
    put boot/jbboot.sh /mnt2/jb/bin/jbboot.sh
    sh_dev 'chmod 755 /mnt2/jb/bin/jbboot.sh'
    ok "jbboot.sh"
    for b in spawnprobe/personaalloc photodiag/photodiag spawnprobe/personaprobe; do
        [ -f "$b" ] || continue
        n=$(basename "$b")
        put "$b" "/mnt2/jb/usr/bin/$n"
        sh_dev "chmod 755 /mnt2/jb/usr/bin/$n"
        ok "$n"
    done
    put spawnprobe/personaalloc /mnt1/usr/local/bin/personaalloc
    sh_dev 'chmod 755 /mnt1/usr/local/bin/personaalloc'
    ok "personaalloc (System copy)"
    put photoforce/pfwatch /mnt1/usr/local/bin/pfwatch
    sh_dev 'chmod 755 /mnt1/usr/local/bin/pfwatch'
    put photoforce/pfwatch /mnt2/jb/usr/bin/pfwatch
    sh_dev 'chmod 755 /mnt2/jb/usr/bin/pfwatch'
    ok "pfwatch"
    put photoforce/pfruntimeprobe /mnt2/jb/usr/bin/pfruntimeprobe
    sh_dev 'chmod 755 /mnt2/jb/usr/bin/pfruntimeprobe'
    ok "pfruntimeprobe"

    # Preserve the Procursus copy once, then install the iOS 27 transport. Package upgrades
    # can replace this file, so normal-boot verification checks its hash explicitly.
    sh_dev '[ ! -f /mnt2/jb/usr/bin/uicache ] || [ -f /mnt2/jb/usr/bin/uicache.stock.bak ] || cp /mnt2/jb/usr/bin/uicache /mnt2/jb/usr/bin/uicache.stock.bak' \
        || die "could not preserve the bootstrap uicache"
    put payload/uicache /mnt2/jb/usr/bin/uicache.usbl8r-new
    uicache_sha=$(shasum -a 256 payload/uicache | awk '{print $1}')
    sh_dev 'cat /mnt2/jb/usr/bin/uicache.usbl8r-new' > payload/.work/uicache.staged
    [ "$(shasum -a 256 payload/.work/uicache.staged | awk '{print $1}')" = "$uicache_sha" ] \
        || die "staged uicache hash mismatch"
    sh_dev 'chmod 755 /mnt2/jb/usr/bin/uicache.usbl8r-new && mv -f /mnt2/jb/usr/bin/uicache.usbl8r-new /mnt2/jb/usr/bin/uicache' \
        || die "could not activate the iOS 27 uicache"
    ok "uicache (iOS 27 containerized registration)"
fi

# ----------------------------------------------------------------- bundles
# Sileo comes from payload/, built by fetch_payloads.sh from the upstream
# release. It used to be scraped off the device (installed via dpkg, then pulled
# back and re-signed), which made provisioning depend on the device already being
# half-configured and meant a fresh clone could not reproduce it.
#
# TrollStore used to be installed here too. It is not any more: anything placed
# in /Applications lives on the sealed System volume and cannot be updated
# without another DFU trip, and the build that went here was the full TrollStore
# renamed to TrollStoreLite.app, whose helper cannot register apps on iOS 27.
# It now installs after first boot from a deb. See COMMANDS.md.
#
# Sent as a tar with ownership baked in, because the ramdisk has no chown, and
# extracted device-side as root so modes survive. giveMeRoot's setuid bit is the
# one that matters: without it Sileo cannot escalate and installs fail silently.
for pair in "Sileo.app:sileo"; do
    bundle=${pair%%:*}; step=${pair#*:}
    wants "$step" || continue
    [ "$CHECK_ONLY" = 0 ] || continue
    say "$bundle"
    if [ ! -d "payload/$bundle" ]; then
        skip "payload/$bundle absent; run ./fetch_payloads.sh first"
        continue
    fi
    TARB="payload/.work/$bundle.tar.gz"
    mkdir -p payload/.work
    "$TOOLS/gtar" czf "$TARB" --owner=0 --group=80 --numeric-owner --no-xattrs \
        -C payload "$bundle"
    timeout 900 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" \
        "cd /mnt1/Applications && tar xzf - --numeric-owner" < "$TARB" \
        || die "failed to extract $bundle on the device"
    must_dev "
B=/mnt1/Applications/$bundle
[ -d \$B ] || { echo '$bundle missing after extract'; exit 1; }
if [ -f \$B/giveMeRoot ]; then
    chmod 4755 \$B/giveMeRoot
    [ -u \$B/giveMeRoot ] || { echo 'giveMeRoot LOST its setuid bit'; exit 1; }
fi
if [ -d /mnt2/jb ]; then
    : > /mnt2/jb/.installed_usbl8r
    chmod 0644 /mnt2/jb/.installed_usbl8r
    # Retire the temporary live-device compatibility marker. The patched
    # Sileo recognizes only .installed_usbl8r, so other software should no
    # longer be told this custom CFW is XinaA15.
    if [ -e /mnt2/jb/.installed_xina15 ]; then
        mv -f /mnt2/jb/.installed_xina15 /mnt2/jb/.installed_xina15.sileo-compat.bak
    fi
fi
echo DONE_OK
" "$bundle did not land correctly"
    ok "$bundle deployed"
done

# ------------------------------------------------------------------ resolv
if wants resolv && [ "$CHECK_ONLY" = 0 ]; then
    say "resolv.conf"
    # -s not -e: a failed earlier run once left a 0-byte file that an
    # exists-check happily skipped, and an empty resolv.conf is no better
    # than none. printf not heredoc: the ramdisk root is read-only, no /tmp.
    must_dev '
R=/mnt1/private/etc/resolv.conf
if [ -s "$R" ]; then
  echo "already present, leaving alone"
else
  printf "%s\n" \
    "# Added so command-line tools (apt) can resolve names." \
    "# iOS system APIs use mDNSResponder and do not need this." \
    "nameserver 1.1.1.1" "nameserver 8.8.8.8" "nameserver 8.8.4.4" > "$R"
  chmod 644 "$R"
  echo "wrote $R"
fi
# -s not -e: a failed run once left a 0-byte file that an exists-check skipped,
# and an empty resolv.conf is no better than none.
[ -s "$R" ] || { echo "resolv.conf is empty after write"; exit 1; }
echo DONE_OK
' "could not write resolv.conf"
    ok "resolv.conf in place"
fi

# -------------------------------------------------------------------- apps
if wants apps && [ "$CHECK_ONLY" = 0 ]; then
    say "system apps"
    # Check for actual bundles rather than a count threshold: a device could
    # have 260+ bundles and still be missing ours.
    missing=$(sh_dev '
n=0
for a in Camera MobileSafari Calculator Maps Photos; do
    [ -d "/mnt1/Applications/$a.app" ] || n=$((n+1))
done
echo $n' | tr -d ' \r')
    have=$(sh_dev 'ls /mnt1/Applications | wc -l' | tr -d ' \r')
    if [ "$missing" = 0 ]; then
        skip "the system apps are already present ($have bundles), skipping the 659 MB copy"
    elif [ ! -d "$IPSW_ROOT/private/var/staged_system_apps" ]; then
        skip "IPSW not mounted at $IPSW_ROOT; cannot source the apps"
    else
        SRC="$IPSW_ROOT/private/var/staged_system_apps"
        TAR=payload/apps50.tar.gz
        if [ ! -f "$TAR" ]; then
            ok "building $TAR (659 MB, about a minute)"
            mkdir -p payload
            # -C "$SRC" . rather than a word-split $(ls): archives the whole
            # directory without relying on app names being space-free.
            # Entries come out as ./Calculator.app/..., which extracts correctly.
            "$TOOLS/gtar" czf "$TAR" --owner=0 --group=80 --numeric-owner \
                --no-xattrs --mode='g+w' -C "$SRC" .
        fi
        ok "streaming $(du -h "$TAR" | cut -f1) to /Applications"
        timeout 1800 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" \
            'cd /mnt1/Applications && tar xzf - --numeric-owner' < "$TAR"
        ok "extracted"
    fi
fi

# ------------------------------------------------------------------ verify
say "verify"
FAIL=0
# Empty output is also a failure. A dropped SSH command used to render a blank
# value here and then fall through to the misleading "safe to reboot" result.
note() {
    printf '    %-24s %s\n' "$1" "${2:-NO RESULT}"
    case "$2" in
        ""|*ABSENT*|*MISSING*|*LOST*|*MISMATCH*|*UNREADABLE*|ENABLED) FAIL=1 ;;
    esac
}
mkdir -p payload/.work

note "/Applications bundles"  "$(sh_dev 'ls /mnt1/Applications | wc -l' | tr -d ' \r')"
for b in Sileo.app; do
    note "$b" "$(sh_dev "[ -d /mnt1/Applications/$b ] && echo present || echo ABSENT" | tr -d '\r')"
done
note "giveMeRoot setuid" "$(sh_dev '[ -u /mnt1/Applications/Sileo.app/giveMeRoot ] && echo OK || echo LOST' | tr -d '\r')"
note "Sileo private marker" "$(sh_dev '[ -f /mnt2/jb/.installed_usbl8r ] && echo present || echo ABSENT' | tr -d '\r')"
sh_dev '/bin/cat /mnt1/Applications/Setup.app/Setup' > payload/.work/verify.Setup 2>/dev/null || true
sh_dev '/bin/cat /mnt1/Applications/Setup.app/Setup.orig' > payload/.work/verify.Setup.orig 2>/dev/null || true
if [ -s payload/.work/verify.Setup ] && \
   python3 patch_setup.py payload/.work/verify.Setup --verify \
       --expect-count "$SETUP_METHODS" >/dev/null 2>&1; then
    setup_state=OK
else
    setup_state=MISMATCH
fi
note "Setup pane patch" "$setup_state"
if [ -s payload/.work/verify.Setup ] && \
   [ -s payload/.work/verify.Setup.orig ] && \
   codesign -v payload/.work/verify.Setup >/dev/null 2>&1 && \
   [ "$(codesign -d --verbose=4 payload/.work/verify.Setup 2>&1 | sed -n 's/^Identifier=//p' | sed -n '1p')" = com.apple.purplebuddy ] && \
   [ "$("$TOOLS/ldid_macosx_arm64" -e payload/.work/verify.Setup)" = \
     "$("$TOOLS/ldid_macosx_arm64" -e payload/.work/verify.Setup.orig)" ]; then
    setup_signing_state=OK
else
    setup_signing_state=MISMATCH
fi
note "Setup CodeDirectory/id" "$setup_signing_state"
note "Setup original backup" "$(sh_dev '[ -f /mnt1/Applications/Setup.app/Setup.orig ] && echo present || echo ABSENT' | tr -d '\r')"
note "System /bin/sh" "$(sh_dev '[ -x /mnt1/bin/sh ] && echo present || echo ABSENT' | tr -d '\r')"

# Rebuild the expected signed daemon from the immutable on-device .orig and
# compare the whole file. ldid's ad-hoc output is deterministic for these
# inputs, so this catches missing patches, wrong entitlements, wrong signing
# identifiers and unrelated byte changes in one check.
verify_userland_patch() {
    V_NAME=$1
    V_DEVICE=$2
    V_DIR=payload/.work/userland-verify
    V_PRISTINE=$V_DIR/$V_NAME.pristine
    V_EXPECTED=$V_DIR/$V_NAME.expected
    V_ACTIVE=$V_DIR/$V_NAME.active
    V_RECORDS=$V_DIR/$V_NAME.records.json
    mkdir -p "$V_DIR"

    if ! sh_dev "[ -f '$V_DEVICE.orig' ]"; then
        note "$V_NAME original backup" "MISSING"
        note "$V_NAME patch" "MISSING"
        return
    fi
    note "$V_NAME original backup" "present"
    sh_dev "/bin/cat '$V_DEVICE.orig'" > "$V_PRISTINE" 2>/dev/null || true
    sh_dev "/bin/cat '$V_DEVICE'" > "$V_ACTIVE" 2>/dev/null || true
    if [ ! -s "$V_PRISTINE" ] || [ ! -s "$V_ACTIVE" ]; then
        note "$V_NAME patch" "UNREADABLE"
        return
    fi

    if python3 userland_fixups.py binary "$V_NAME" "$V_PRISTINE" "$V_EXPECTED" "$V_RECORDS" \
            --liter8 "$LITER8_SELF" --ldid "$TOOLS/ldid_macosx_arm64" \
            >/dev/null 2>&1 && cmp -s "$V_EXPECTED" "$V_ACTIVE"; then
        note "$V_NAME patch" "OK"
    else
        note "$V_NAME patch" "MISMATCH"
    fi
}

verify_userland_patch coreauthd \
    /mnt1/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd
verify_userland_patch mobileactivationd /mnt1/usr/libexec/mobileactivationd
verify_userland_patch ctkd \
    /mnt1/System/Library/Frameworks/CryptoTokenKit.framework/ctkd

sh_dev '/bin/cat /mnt2/db/com.apple.xpc.launchd/disabled.plist' \
    > payload/.work/verify.disabled.plist 2>/dev/null || true
if [ -s payload/.work/verify.disabled.plist ] && \
   python3 userland_fixups.py screen-time payload/.work/verify.disabled.plist --verify \
       >/dev/null 2>&1; then
    screentime_state=OK
else
    screentime_state=MISSING
fi
note "ScreenTime overrides" "$screentime_state"

if [ -s t8030_apticket.der ]; then
    ticket_state="$(wc -c < t8030_apticket.der | tr -d ' ') bytes"
else
    ticket_state=MISSING
fi
note "local APTicket" "$ticket_state"
note "resolv.conf bytes"  "$(sh_dev '[ -s /mnt1/private/etc/resolv.conf ] && wc -c < /mnt1/private/etc/resolv.conf || echo MISSING' | tr -d ' \r')"
note "System applications" "$(sh_dev 'for a in Camera MobileSafari Calculator Maps Photos; do [ -d "/mnt1/Applications/$a.app" ] || { echo MISSING; exit; }; done; echo OK' | tr -d '\r')"
note "jbboot.sh System"   "$(sh_dev '[ -x /mnt1/usr/local/bin/jbboot.sh ] && echo present || echo ABSENT' | tr -d '\r')"
note "personaalloc System" "$(sh_dev '[ -x /mnt1/usr/local/bin/personaalloc ] && echo present || echo ABSENT' | tr -d '\r')"
note "pfwatch System"     "$(sh_dev '[ -x /mnt1/usr/local/bin/pfwatch ] && echo present || echo ABSENT' | tr -d '\r')"
note "sbextissue System"  "$(sh_dev '[ -x /mnt1/usr/local/bin/sbextissue ] && echo present || echo ABSENT' | tr -d '\r')"
note "pfruntimeprobe"     "$(sh_dev '[ -x /mnt2/jb/usr/bin/pfruntimeprobe ] && echo present || echo ABSENT' | tr -d '\r')"

if [ -f payload/uicache ]; then
    expected_uicache=$(shasum -a 256 payload/uicache | awk '{print $1}')
    sh_dev 'cat /mnt2/jb/usr/bin/uicache' > payload/.work/verify.uicache 2>/dev/null || true
    [ -s payload/.work/verify.uicache ] && \
        [ "$(shasum -a 256 payload/.work/verify.uicache | awk '{print $1}')" = "$expected_uicache" ] \
        && uicache_state=OK || uicache_state=MISMATCH
else
    uicache_state=MISSING
fi
note "uicache iOS 27" "$uicache_state"

if [ -f payload/launchd.orig ] && [ -f payload/launchd.hooked ] && \
   [ -f payload/lhook.dylib ] && [ -f payload/systemhook.dylib ] && \
   [ -f payload/sbextissue ]; then
    verify_stock=$(shasum -a 256 payload/launchd.orig | awk '{print $1}')
    verify_hooked=$(shasum -a 256 payload/launchd.hooked | awk '{print $1}')
    verify_lhook=$(shasum -a 256 payload/lhook.dylib | awk '{print $1}')
    verify_systemhook=$(shasum -a 256 payload/systemhook.dylib | awk '{print $1}')
    verify_sbextissue=$(shasum -a 256 payload/sbextissue | awk '{print $1}')
    if [ "$verify_stock" != "$LAUNCHD_SHA" ] || \
       ! python3 launchdhook/verify_diff.py payload/launchd.orig payload/launchd.hooked >/dev/null; then
        injection_launchd=MISMATCH
        injection_backup=MISMATCH
        injection_hook=MISMATCH
        injection_systemhook=MISMATCH
        injection_sbextissue=MISMATCH
    else
        sh_dev 'cat /mnt1/sbin/launchd' > payload/.work/verify.launchd 2>/dev/null || true
        sh_dev 'cat /mnt1/sbin/launchd.bak' > payload/.work/verify.launchd.bak 2>/dev/null || true
        sh_dev 'cat /mnt1/usr/lib/lhook.dylib' > payload/.work/verify.lhook 2>/dev/null || true
        sh_dev 'cat /mnt1/usr/lib/systemhook.dylib' > payload/.work/verify.systemhook 2>/dev/null || true
        sh_dev 'cat /mnt1/usr/local/bin/sbextissue' > payload/.work/verify.sbextissue 2>/dev/null || true
        [ -s payload/.work/verify.launchd ] && \
            [ "$(shasum -a 256 payload/.work/verify.launchd | awk '{print $1}')" = "$verify_hooked" ] && \
            sh_dev '[ -x /mnt1/sbin/launchd ]' \
            && injection_launchd=OK || injection_launchd=MISMATCH
        [ -s payload/.work/verify.launchd.bak ] && \
            [ "$(shasum -a 256 payload/.work/verify.launchd.bak | awk '{print $1}')" = "$verify_stock" ] && \
            sh_dev '[ -x /mnt1/sbin/launchd.bak ]' \
            && injection_backup=OK || injection_backup=MISMATCH
        [ -s payload/.work/verify.lhook ] && \
            [ "$(shasum -a 256 payload/.work/verify.lhook | awk '{print $1}')" = "$verify_lhook" ] && \
            sh_dev '[ -x /mnt1/usr/lib/lhook.dylib ]' \
            && injection_hook=OK || injection_hook=MISMATCH
        [ -s payload/.work/verify.systemhook ] && \
            [ "$(shasum -a 256 payload/.work/verify.systemhook | awk '{print $1}')" = "$verify_systemhook" ] && \
            sh_dev '[ -x /mnt1/usr/lib/systemhook.dylib ]' \
            && injection_systemhook=OK || injection_systemhook=MISMATCH
        [ -s payload/.work/verify.sbextissue ] && \
            [ "$(shasum -a 256 payload/.work/verify.sbextissue | awk '{print $1}')" = "$verify_sbextissue" ] && \
            sh_dev '[ -x /mnt1/usr/local/bin/sbextissue ]' \
            && injection_sbextissue=OK || injection_sbextissue=MISMATCH
    fi
else
    injection_launchd=MISSING
    injection_backup=MISSING
    injection_hook=MISSING
    injection_systemhook=MISSING
    injection_sbextissue=MISSING
fi
note "launchd injection" "$injection_launchd"
note "launchd stock backup" "$injection_backup"
note "lhook.dylib" "$injection_hook"
note "icon systemhook" "$injection_systemhook"
note "icon token issuer" "$injection_sbextissue"
note "lhook deny policy" "$(sh_dev '[ -s /mnt2/jb/etc/lhook.deny ] && ! grep -qx xpcproxy /mnt2/jb/etc/lhook.deny && echo OK || echo MISSING' | tr -d '\r')"
note "lhook first boot" "$(sh_dev '[ -e /mnt2/jb/.lhook_enabled ] && echo ENABLED || echo disabled' | tr -d '\r')"

# The cache is the one file that can be the right SIZE and still be wrong, and
# it is what provides SSH on a normal boot. Pull it back and check its contents.
sh_dev '/bin/cat /mnt1/System/Library/xpc/launchd.plist' > payload/.work/dev_cache.plist 2>/dev/null || true
if [ -s payload/.work/dev_cache.plist ]; then
    cache_state=$(python3 - <<'PY'
import plistlib
try:
    ld = plistlib.load(open("payload/.work/dev_cache.plist","rb"))["LaunchDaemons"]
except Exception as e:
    print(f"UNREADABLE ({e})"); raise SystemExit
need = ["com.dropbear", "com.jbboot"]
missing = [j for j in need if f"/System/Library/LaunchDaemons/{j}.plist" not in ld]
from patch_launchd_cache import CACHE_KEY, DROPBEAR_JOB
dropbear_ok = ld.get(CACHE_KEY) == DROPBEAR_JOB
if missing:
    state = f"MISSING {missing}"
elif not dropbear_ok:
    state = "MISMATCH com.dropbear"
else:
    state = "all jobs present"
expected = int(__import__("os").environ["LITER8_LAUNCHD_CACHE_DAEMONS"]) + 2
if len(ld) != expected:
    state = f"MISMATCH count, expected {expected}"
print(f"{len(ld)} daemons, {state}")
PY
)
    note "launchd cache" "$cache_state"
else
    note "launchd cache" "MISSING"
fi

sh_dev 'sync; sync' >/dev/null 2>&1 || true

if [ "$FAIL" != 0 ]; then
    printf '\n\033[1m==> INCOMPLETE\033[0m\n'
    echo "    something above is absent, mismatched, lost, or unsafely enabled. Do not boot."
    exit 1
fi

say "done, safe to reboot"
echo "    next: pwn DFU, then  ./get_boot.py && ./boot.py"
echo "    first normal boot:  liter8 fw finalize --check"
echo "                        liter8 fw finalize"
