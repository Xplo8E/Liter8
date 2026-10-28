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

STEPS="mounts ticket setup userland pairing cellular screentime injection tweaks cache jbtools sileo resolv apps verify"

usage() {
    echo "steps: $STEPS"
    echo "  mounts   mount System rw, Data and Preboot (always runs first)"
    echo "  ticket   extract this restore's APTicket from Preboot"
    echo "  setup    patch Setup.app to skip unavailable first-run panes"
    echo "  userland patch and re-sign the SEP/activation daemons"
    echo "  pairing  install lockdownd, coreauthd companion guard and RemoteXPC repair"
    echo "  cellular unseal baseband calibration and stop CommCenter refusing a data context"
    echo "           (only on a profile with a baseband; Wi-Fi-only boards such as j171aap skip it)"
    echo "  screentime make Setup's unavailable ScreenTime requests fail fast"
    echo "  injection install launchd hook plus icon grant, disabled for first boot"
    echo "  tweaks   install the tweak loader and the TweakInject payloads"
    echo "  cache    deploy the launchd service cache (dropbear + jbboot + DDI watcher + watchdogd mitigation)"
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
DEFAULT_RUN=0
case "${1:-}" in
    --list|-h|--help) usage ;;
    --check) CHECK_ONLY=1; WANT="mounts verify" ;;
    "") WANT="$STEPS"; DEFAULT_RUN=1 ;;
    *) WANT="mounts $* verify" ;;
esac

wants() { case " $WANT " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ssh's own askpass hook rather than sshpass, which races this dropbear's
# password prompt and intermittently sends the wrong secret. The shim keeps the
# `-p <password> ssh|scp ...` call shape, so the call sites below are unchanged.
# Its header has the measurements.
SSHPASS="$BASE/askpass-sshpass"
# Prefer a native ldid. The bundled one is arm64 only, so it cannot run on an
# Intel Mac. See https://github.com/Xplo8E/Liter8/issues/2.
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# The bundled gtar is x86_64, so it needs Rosetta on Apple Silicon. Liter8 also
# puts tools/ first on PATH, so `command -v gtar` finds that same x86_64 copy
# and falling back to "$TOOLS/gtar" lands on the binary that just failed. Walk
# every directory for one that runs before accepting the bundled copy. The two
# Homebrew prefixes come last because the inherited PATH may carry neither,
# matching HostTool.homebrewBinaryDirectories.
GTAR=""
gtar_ifs=$IFS
IFS=:
for gtar_directory in $PATH /opt/homebrew/bin /usr/local/bin; do
    [ -x "$gtar_directory/gtar" ] || continue
    "$gtar_directory/gtar" --version >/dev/null 2>&1 || continue
    GTAR="$gtar_directory/gtar"
    break
done
IFS=$gtar_ifs
[ -n "$GTAR" ] || GTAR="$TOOLS/gtar"
# Allow the device's ECDSA key and AES-CTR cipher without dropping SSH defaults.
SSHOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=25 -o HostKeyAlgorithms=+ecdsa-sha2-nistp521 -o Ciphers=+aes128-ctr -p 2222"
DEV="root@localhost"
PW=alpine
SSH_ATTEMPTS=5

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

# Whether this board has a modem, from the exact firmware profile
# (DeviceWorkflowProfile.hasBaseband). The cellular step fixes CommCenter's
# baseband calibration and data context. A Wi-Fi-only board (j171aap) has
# neither to fix, and the CommCenter resolver was written for the iOS 27
# iPhone builds, so there the step is left out of the default run, refused
# when named, and not expected by verify.
HAS_BASEBAND=${LITER8_HAS_BASEBAND:?Liter8 did not provide the reviewed baseband policy}
case "$HAS_BASEBAND" in
    0|1) ;;
    *) die "LITER8_HAS_BASEBAND must be 0 or 1, not $HAS_BASEBAND" ;;
esac
if [ "$HAS_BASEBAND" = 0 ] && wants cellular; then
    [ "$DEFAULT_RUN" = 1 ] \
        || die "this firmware profile has no baseband; the cellular step does not apply"
    no_cellular=
    for step in $WANT; do
        [ "$step" = cellular ] || no_cellular="$no_cellular $step"
    done
    WANT=${no_cellular# }
fi

# SSHRD's old Dropbear occasionally rejects a valid password when the workflow
# opens several connections back-to-back. Buffer each attempt independently so
# a partial failed read cannot be concatenated with the successful retry.
sh_dev() {
    _L8_SSH_OUT=$(mktemp "${TMPDIR:-/tmp}/liter8-ssh-out.XXXXXX")
    _L8_SSH_ERR=$(mktemp "${TMPDIR:-/tmp}/liter8-ssh-err.XXXXXX")
    _L8_SSH_TRY=1
    while [ "$_L8_SSH_TRY" -le "$SSH_ATTEMPTS" ]; do
        : > "$_L8_SSH_OUT"
        : > "$_L8_SSH_ERR"
        # The SSH ramdisk shell runs with umask 0000, so every directory a
        # step creates implicitly would come out world-writable (777). Set the
        # usual 022 here rather than trusting each mkdir to chmod.
        # shellcheck disable=SC2086  # $SSHOPT is an option LIST and must word-split
        if timeout 900 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" "umask 022;" "$@" \
                > "$_L8_SSH_OUT" 2> "$_L8_SSH_ERR"; then
            cat "$_L8_SSH_OUT"
            rm -f "$_L8_SSH_OUT" "$_L8_SSH_ERR"
            return 0
        else
            _L8_SSH_STATUS=$?
        fi
        if [ "$_L8_SSH_TRY" -eq "$SSH_ATTEMPTS" ]; then
            cat "$_L8_SSH_OUT"
            cat "$_L8_SSH_ERR" >&2
            rm -f "$_L8_SSH_OUT" "$_L8_SSH_ERR"
            return "$_L8_SSH_STATUS"
        fi
        _L8_SSH_TRY=$((_L8_SSH_TRY + 1))
        sleep 1
    done
}

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
    _L8_PUT_ERR=$(mktemp "${TMPDIR:-/tmp}/liter8-ssh-put.XXXXXX")
    _L8_PUT_TRY=1
    while :; do
        : > "$_L8_PUT_ERR"
        # shellcheck disable=SC2086  # same: $SSHOPT must word-split
        if timeout 900 "$SSHPASS" -p "$PW" ssh $SSHOPT "$DEV" "umask 022; cat > $2" \
                < "$1" 2> "$_L8_PUT_ERR"; then
            rm -f "$_L8_PUT_ERR"
            break
        fi
        if [ "$_L8_PUT_TRY" -eq "$SSH_ATTEMPTS" ]; then
            cat "$_L8_PUT_ERR" >&2
            rm -f "$_L8_PUT_ERR"
            die "transfer failed: $1 -> $2"
        fi
        _L8_PUT_TRY=$((_L8_PUT_TRY + 1))
        sleep 1
    done
    # tr runs on the HOST here (output of ssh), so it is fine
    _got=$(sh_dev "wc -c < $2" 2>/dev/null | tr -d ' \r')
    [ "$_got" = "$_sz" ] || die "short write: $2 is $_got bytes, expected $_sz"
}

# Reap an owned USB forward before the shell exits. Provisioning runs directly
# after install_dropbear.sh, and allowing either phase's old iproxy to linger
# can make the next SSH connection authenticate through a dying transport.
stop_owned_iproxy() {
    kill "$IPROXY_PID" 2>/dev/null || true
    wait "$IPROXY_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------- preflight
say "preflight"
# -x passes for an arm64 binary on an Intel Mac, so the native helpers below are
# run rather than just tested. They fail far into provisioning otherwise, with
# only "Bad CPU type in executable". askpass-sshpass is a /bin/sh script with no
# architecture to get wrong, so -x is the whole check for it.
[ -x "$SSHPASS" ] || die "missing $SSHPASS"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || die "ldid at $LDID cannot run on this host; brew install ldid-procursus"
"$GTAR" --version >/dev/null 2>&1 \
    || die "gtar at $GTAR cannot run on this host; brew install gnu-tar"
command -v timeout >/dev/null 2>&1 || die "timeout not found (brew install coreutils)"
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    command -v iproxy >/dev/null 2>&1 || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222:22 >/dev/null 2>&1 &
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
# Preboot's partition number differs by device (disk1s6 on n104, disk1s5 on j171aap,
# where disk1s6 is Update), so select it by its APFS role. /mnt6 stays the mountpoint.
mkdir -p payload/.work
sh_dev '/usr/sbin/ioreg -r -c AppleAPFSVolume -l' > payload/.work/apfs-volumes.txt \
    || die "could not read APFS volume roles"
preboot_device=$(python3 apfs_role.py Preboot < payload/.work/apfs-volumes.txt) \
    || die "could not identify the Preboot volume"
must_dev "
mkdir -p /mnt1 /mnt2 /mnt6 2>/dev/null
/sbin/mount | /usr/bin/grep -q '^$preboot_device on /mnt6 ' || {
    /sbin/umount /mnt6 2>/dev/null
    /sbin/mount_apfs -o rdonly '$preboot_device' /mnt6 || { echo 'could not mount Preboot'; exit 1; }
}
echo DONE_OK
" "could not mount the Preboot volume"
must_dev '
mkdir -p /mnt1 /mnt2 /mnt6 2>/dev/null
/sbin/mount_apfs /dev/disk1s1 /mnt1 2>/dev/null
/sbin/mount_apfs /dev/disk1s2 /mnt2 2>/dev/null
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
    "$LITER8_SELF" img4 extract-manifest "$sep_new" "$ticket_new" >/dev/null \
        || die "could not extract the APTicket from $sep_path"
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
    "$LDID" -e "$setup_local" > "$setup_entitlements" \
        || die "could not read Setup entitlements"
    [ -s "$setup_entitlements" ] || die "Setup entitlement plist is empty"
    setup_identifier=$(codesign -d --verbose=4 "$setup_local" 2>&1 \
        | sed -n 's/^Identifier=//p' | sed -n '1p')
    [ "$setup_identifier" = com.apple.purplebuddy ] \
        || die "unexpected Setup signing identifier: ${setup_identifier:-missing}"
    "$LDID" -I"$setup_identifier" \
        -S"$setup_entitlements" -Cadhoc "$setup_patched" \
        || die "could not re-sign patched Setup"
    codesign -v "$setup_patched" \
        || die "patched Setup has an invalid CodeDirectory"
    [ "$(codesign -d --verbose=4 "$setup_patched" 2>&1 | sed -n 's/^Identifier=//p' | sed -n '1p')" = "$setup_identifier" ] \
        || die "patched Setup signing identifier changed"
    [ "$("$LDID" -e "$setup_patched")" = "$(cat "$setup_entitlements")" ] \
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
# These daemons are ordinary files on the System volume, but their
# failures happen late enough to resemble a bad kernel boot. Build every patch
# from the device's preserved .orig file so retries never patch an already
# modified executable. Swift finds the instruction patches; lockdownd uses one
# reviewed structural load-command edit. Python preserves the original signing
# identity and entitlements for both paths.
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
        --liter8 "$LITER8_SELF" --ldid "$LDID" \
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

deploy_pairing_library() {
    P_LOCAL=payload/l8pair.dylib
    P_DEVICE=/mnt1/usr/lib/l8pair.dylib
    P_STAGED=$P_DEVICE.liter8-new
    P_READBACK=payload/.work/userland/l8pair.readback
    mkdir -p payload/.work/userland

    [ -f "$P_LOCAL" ] || die "missing $P_LOCAL; run fetch_payloads.sh pairing"
    codesign -v "$P_LOCAL" || die "l8pair.dylib has an invalid CodeDirectory"
    P_WANT=$(shasum -a 256 "$P_LOCAL" | awk '{print $1}')
    put "$P_LOCAL" "$P_STAGED"
    must_dev "
[ -f '$P_DEVICE' ] && [ ! -f '$P_DEVICE.orig' ] && cp '$P_DEVICE' '$P_DEVICE.orig'
chmod 0755 '$P_STAGED'
mv -f '$P_STAGED' '$P_DEVICE'
echo DONE_OK
" "could not activate l8pair.dylib"
    sh_dev "/bin/cat '$P_DEVICE'" > "$P_READBACK" \
        || die "could not read back l8pair.dylib"
    P_GOT=$(shasum -a 256 "$P_READBACK" | awk '{print $1}')
    [ "$P_GOT" = "$P_WANT" ] || die "l8pair.dylib readback hash mismatch"
    ok "l8pair.dylib deployed and read back ($P_WANT)"
}

deploy_remotepairing_library() {
    R_LOCAL=payload/l8remotepairing.dylib
    R_DEVICE=/mnt1/usr/lib/l8remotepairing.dylib
    R_STAGED=$R_DEVICE.liter8-new
    R_READBACK=payload/.work/userland/l8remotepairing.readback
    mkdir -p payload/.work/userland

    [ -f "$R_LOCAL" ] || die "missing $R_LOCAL; run fetch_payloads.sh pairing"
    codesign -v "$R_LOCAL" \
        || die "l8remotepairing.dylib has an invalid CodeDirectory"
    R_WANT=$(shasum -a 256 "$R_LOCAL" | awk '{print $1}')
    put "$R_LOCAL" "$R_STAGED"
    must_dev "
[ -f '$R_DEVICE' ] && [ ! -f '$R_DEVICE.orig' ] && cp '$R_DEVICE' '$R_DEVICE.orig'
chmod 0755 '$R_STAGED'
mv -f '$R_STAGED' '$R_DEVICE'
echo DONE_OK
" "could not activate l8remotepairing.dylib"
    sh_dev "/bin/cat '$R_DEVICE'" > "$R_READBACK" \
        || die "could not read back l8remotepairing.dylib"
    R_GOT=$(shasum -a 256 "$R_READBACK" | awk '{print $1}')
    [ "$R_GOT" = "$R_WANT" ] \
        || die "l8remotepairing.dylib readback hash mismatch"
    ok "l8remotepairing.dylib deployed and read back ($R_WANT)"
}

deploy_coreauth_library() {
    C_LOCAL=payload/l8coreauth.dylib
    C_DEVICE=/mnt1/usr/lib/l8coreauth.dylib
    C_STAGED=$C_DEVICE.liter8-new
    C_READBACK=payload/.work/userland/l8coreauth.readback
    mkdir -p payload/.work/userland

    [ -f "$C_LOCAL" ] || die "missing $C_LOCAL; run fetch_payloads.sh pairing"
    codesign -v "$C_LOCAL" || die "l8coreauth.dylib has an invalid CodeDirectory"
    C_WANT=$(shasum -a 256 "$C_LOCAL" | awk '{print $1}')
    put "$C_LOCAL" "$C_STAGED"
    must_dev "
[ -f '$C_DEVICE' ] && [ ! -f '$C_DEVICE.orig' ] && cp '$C_DEVICE' '$C_DEVICE.orig'
chmod 0755 '$C_STAGED'
mv -f '$C_STAGED' '$C_DEVICE'
echo DONE_OK
" "could not activate l8coreauth.dylib"
    sh_dev "/bin/cat '$C_DEVICE'" > "$C_READBACK" \
        || die "could not read back l8coreauth.dylib"
    C_GOT=$(shasum -a 256 "$C_READBACK" | awk '{print $1}')
    [ "$C_GOT" = "$C_WANT" ] || die "l8coreauth.dylib readback hash mismatch"
    ok "l8coreauth.dylib deployed and read back ($C_WANT)"
}

enable_pairing_fallback() {
    P_DIR=/mnt2/root/Library/Lockdown
    P_MARKER=$P_DIR/.liter8-pairing-fallback
    R_MARKER=/mnt1/usr/lib/.liter8-remotepairing-fallback
    must_dev "
mkdir -p '$P_DIR'
: > '$P_MARKER.new'
chmod 0600 '$P_MARKER.new'
mv -f '$P_MARKER.new' '$P_MARKER'
: > '$R_MARKER.new'
chmod 0600 '$R_MARKER.new'
mv -f '$R_MARKER.new' '$R_MARKER'
echo DONE_OK
" "could not enable the marker-gated pairing fallback"
    ok "lockdownd and RemoteXPC fallbacks enabled by scoped markers"
}

deploy_fdr_library() {
    F_LOCAL=payload/l8fdr.dylib
    # Sealed System volume on purpose: see the comment in userland_fixups.py.
    F_DEVICE=/mnt1/usr/lib/l8fdr.dylib
    F_STAGED=$F_DEVICE.liter8-new
    F_READBACK=payload/.work/userland/l8fdr.readback
    mkdir -p payload/.work/userland

    [ -f "$F_LOCAL" ] || die "missing $F_LOCAL; run fetch_payloads.sh cellular"
    codesign -v "$F_LOCAL" || die "l8fdr.dylib has an invalid CodeDirectory"
    F_WANT=$(shasum -a 256 "$F_LOCAL" | awk '{print $1}')
    put "$F_LOCAL" "$F_STAGED"
    must_dev "
[ -f '$F_DEVICE' ] && [ ! -f '$F_DEVICE.orig' ] && cp '$F_DEVICE' '$F_DEVICE.orig'
chmod 0755 '$F_STAGED'
mv -f '$F_STAGED' '$F_DEVICE'
echo DONE_OK
" "could not activate l8fdr.dylib"
    sh_dev "/bin/cat '$F_DEVICE'" > "$F_READBACK" \
        || die "could not read back l8fdr.dylib"
    F_GOT=$(shasum -a 256 "$F_READBACK" | awk '{print $1}')
    [ "$F_GOT" = "$F_WANT" ] || die "l8fdr.dylib readback hash mismatch"
    ok "l8fdr.dylib deployed and read back ($F_WANT)"
}

# The dylib is inert without this marker, so a boot where CommCenter misbehaves
# is recovered by deleting one file from SSHRD rather than by restoring a 40 MB
# re-signed binary.
enable_fdr_bypass() {
    F_MARKER=/mnt1/usr/lib/.liter8-fdr-sik-bypass
    must_dev "
: > '$F_MARKER.new'
chmod 0600 '$F_MARKER.new'
mv -f '$F_MARKER.new' '$F_MARKER'
echo DONE_OK
" "could not enable the FDR sik bypass marker"
    ok "CommCenter FDR sik bypass enabled by scoped marker"
}

deploy_userland_daemon() {
    U_NAME=$1
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
        lockdownd)
            U_DEVICE=/mnt1/usr/libexec/lockdownd
            ;;
        remotepairingdeviced)
            U_DEVICE=/mnt1/usr/libexec/remotepairingdeviced
            ;;
        CommCenter)
            U_DEVICE=/mnt1/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter
            ;;
        *)
            die "unsupported userland daemon: $U_NAME"
            ;;
    esac
    sh_dev "[ -f '$U_DEVICE' ]" || die "$U_NAME is absent at $U_DEVICE"
    build_userland_patch "$U_NAME" "$U_DEVICE"
    deploy_userland_patch "$U_NAME" "$U_DEVICE"
}

if wants userland && [ "$CHECK_ONLY" = 0 ]; then
    say "post-restore userland crash fixes"
    deploy_coreauth_library
    for U_NAME in coreauthd mobileactivationd ctkd; do
        deploy_userland_daemon "$U_NAME"
    done
fi

if wants pairing && [ "$CHECK_ONLY" = 0 ]; then
    say "lockdownd and RemoteXPC pairing fallbacks"
    # The Trust path asks coreauthd to parse ACM's empty SEP ratchet state.
    # A selective `pairing` run therefore needs the companion guard even when
    # the broader `userland` step was not requested. The normal full workflow
    # already installed it immediately above, so do not rebuild it twice.
    if ! wants userland; then
        deploy_coreauth_library
        deploy_userland_daemon coreauthd
    fi
    deploy_pairing_library
    deploy_remotepairing_library
    for U_NAME in lockdownd remotepairingdeviced; do
        deploy_userland_daemon "$U_NAME"
    done
    enable_pairing_fallback
fi

# -------------------------------------------------------------- cellular
# Baseband calibration is sealed to an AP identity key this device cannot
# reproduce, so CommCenter cannot unseal it from FactoryData and the modem comes
# up without calibration. The dylib reaches libFDR's own "ignore sik
# verification" path inside CommCenter only.
#
# CommCenter also gets a semantic instruction patch so canActivateDataSettings
# stops refusing a cellular data context because the device has no real
# activation record, which is what leaves IMS without a PDN and voice without
# VoLTE. Both are applied by userland_fixups.py in one re-sign. See
# docs/design/BASEBAND_AND_CELLULAR.md.
if wants cellular && [ "$CHECK_ONLY" = 0 ]; then
    say "baseband calibration FDR bypass"
    deploy_fdr_library
    deploy_userland_daemon CommCenter
    enable_fdr_bypass
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
    # launchd.hooked-legacy is deliberately absent on a build whose launchd has
    # under 48 bytes of load-command slack, because the previous 48-byte hook
    # path could never have fitted there and so is not a state to recognise.
    # fetch_payloads.sh skips it on exactly that condition; requiring it here
    # would move the same abort one stage later.
    for required in payload/launchd.orig payload/launchd.hooked \
                    payload/lhook.dylib payload/systemhook.dylib payload/sbextissue payload/lhookctl \
                    launchdhook/lhook.deny; do
        [ -f "$required" ] || die "$required absent; run ./fetch_payloads.sh injection"
    done

    stock_sha=$(shasum -a 256 payload/launchd.orig | awk '{print $1}')
    hooked_sha=$(shasum -a 256 payload/launchd.hooked | awk '{print $1}')
    # An unset legacy hash can never equal a real one, so the recognition case
    # below simply never fires where no legacy image exists.
    legacy_sha=
    [ -f payload/launchd.hooked-legacy ] \
        && legacy_sha=$(shasum -a 256 payload/launchd.hooked-legacy | awk '{print $1}')
    hook_sha=$(shasum -a 256 payload/lhook.dylib | awk '{print $1}')
    systemhook_sha=$(shasum -a 256 payload/systemhook.dylib | awk '{print $1}')
    sbextissue_sha=$(shasum -a 256 payload/sbextissue | awk '{print $1}')
    lhookctl_sha=$(shasum -a 256 payload/lhookctl | awk '{print $1}')
    [ "$stock_sha" = "$LAUNCHD_SHA" ] \
        || die "payload/launchd.orig does not match the selected firmware profile"
    python3 launchdhook/verify_diff.py payload/launchd.orig payload/launchd.hooked >/dev/null \
        || die "launchd payload byte-diff verification failed"
    codesign -v payload/launchd.hooked \
        || die "launchd payload code-slot verification failed"
    # The previous-path image is never installed, only recognised, so it is
    # verified by the same rules before its hash is allowed to mean anything.
    if [ -n "$legacy_sha" ]; then
        python3 launchdhook/verify_diff.py payload/launchd.orig payload/launchd.hooked-legacy \
            /usr/lib/lhook.dylib >/dev/null \
            || die "previous-path launchd byte-diff verification failed"
        codesign -v payload/launchd.hooked-legacy \
            || die "previous-path launchd code-slot verification failed"
        [ "$legacy_sha" != "$hooked_sha" ] \
            || die "the two hook paths hash identically; the path change is not in effect"
    fi
    for binary in payload/lhook.dylib payload/systemhook.dylib payload/sbextissue payload/lhookctl; do
        codesign -v "$binary" || die "$binary signature verification failed"
        [ -z "$("$LDID" -e "$binary")" ] \
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
    # hooked-legacy is a device this repo hooked before the load command moved
    # from /usr/lib/lhook.dylib to /usr/lib/lhook. It is an image this script
    # built and verified above, so it is as known a state as the other two, and
    # it is replaced the same way. Without this case every device provisioned by
    # an older revision hit a hard die on its first upgrade, naming no cause and
    # offering no recovery.
    case "$current_sha" in
        "$stock_sha") current_state=stock ;;
        "$hooked_sha") current_state=hooked ;;
        "$legacy_sha") current_state=hooked-legacy ;;
        *) die "on-device /sbin/launchd is none of reviewed stock, reviewed hooked or the previous hook path ($current_sha)" ;;
    esac
    ok "on-device launchd is $current_state"
    [ "$current_state" != hooked-legacy ] \
        || ok "upgrading from the previous hook path; the inert /usr/lib/lhook.dylib is left in place"

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

    sh_dev 'mkdir -p /mnt1/usr/lib /mnt1/usr/local/bin /mnt2/jb/etc /mnt2/jb/usr/bin' \
        || die "could not create injection directories"
    must_dev '
if [ -f /mnt1/usr/lib/lhook ] && [ ! -f /mnt1/usr/lib/lhook.orig ]; then
    cp /mnt1/usr/lib/lhook /mnt1/usr/lib/lhook.orig
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
    put payload/lhook.dylib /mnt1/usr/lib/lhook.usbl8r-new
    put payload/systemhook.dylib /mnt1/usr/lib/systemhook.dylib.usbl8r-new
    put payload/sbextissue /mnt1/usr/local/bin/sbextissue.usbl8r-new
    put payload/lhookctl /mnt2/jb/usr/bin/lhookctl.new
    put launchdhook/lhook.deny /mnt2/jb/etc/lhook.deny.new
    sh_dev 'cat /mnt1/sbin/launchd.usbl8r-new' > payload/.work/launchd.staged
    sh_dev 'cat /mnt1/usr/lib/lhook.usbl8r-new' > payload/.work/lhook.staged
    sh_dev 'cat /mnt1/usr/lib/systemhook.dylib.usbl8r-new' > payload/.work/systemhook.staged
    sh_dev 'cat /mnt1/usr/local/bin/sbextissue.usbl8r-new' > payload/.work/sbextissue.staged
    sh_dev 'cat /mnt2/jb/usr/bin/lhookctl.new' > payload/.work/lhookctl.staged
    [ "$(shasum -a 256 payload/.work/lhookctl.staged | awk '{print $1}')" = "$lhookctl_sha" ] \
        || die "staged lhookctl hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/launchd.staged | awk '{print $1}')" = "$hooked_sha" ] \
        || die "staged launchd hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/lhook.staged | awk '{print $1}')" = "$hook_sha" ] \
        || die "staged lhook hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/systemhook.staged | awk '{print $1}')" = "$systemhook_sha" ] \
        || die "staged systemhook hash mismatch; original is still active"
    [ "$(shasum -a 256 payload/.work/sbextissue.staged | awk '{print $1}')" = "$sbextissue_sha" ] \
        || die "staged sbextissue hash mismatch; original is still active"
    must_dev '
chmod 0755 /mnt1/sbin/launchd.usbl8r-new /mnt1/usr/lib/lhook.usbl8r-new
chmod 0755 /mnt1/usr/lib/systemhook.dylib.usbl8r-new /mnt1/usr/local/bin/sbextissue.usbl8r-new
chmod 0644 /mnt2/jb/etc/lhook.deny.new
chmod 0755 /mnt2/jb/usr/bin/lhookctl.new
mv -f /mnt2/jb/usr/bin/lhookctl.new /mnt2/jb/usr/bin/lhookctl
mv -f /mnt1/sbin/launchd.usbl8r-new /mnt1/sbin/launchd
mv -f /mnt1/usr/lib/lhook.usbl8r-new /mnt1/usr/lib/lhook
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
    sh_dev 'cat /mnt1/usr/lib/lhook' > payload/.work/lhook.readback
    sh_dev 'cat /mnt1/usr/lib/systemhook.dylib' > payload/.work/systemhook.readback
    sh_dev 'cat /mnt1/usr/local/bin/sbextissue' > payload/.work/sbextissue.readback
    sh_dev 'cat /mnt2/jb/usr/bin/lhookctl' > payload/.work/lhookctl.readback
    [ "$(shasum -a 256 payload/.work/lhookctl.readback | awk '{print $1}')" = "$lhookctl_sha" ] \
        || die "lhookctl readback hash mismatch"
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

# ------------------------------------------------------------------ tweaks
# What lhook dlopens, and what the loader then loads. Separate from injection
# because it is all Data-volume content: it can be reinstalled without touching
# /sbin/launchd, and a failure here cannot affect booting.
#
# Installing this changes no behaviour on its own. Injection still needs
# lhookctl enable for the current boot session, and l8localauth stays dormant
# until the root-owned /var/jb/.liter8-localauth marker exists. Two separate
# switches, neither of which this step touches.
#
# local:device:mode:package-form, declared here rather than inside the step
# because the verification at the bottom of this script reads the same table.
# Two copies drifted: one listed the mode and the other did not check it.
#
# libinjector lands twice: at the canonical path it names internally, and at the
# loader path lhook dlopens. Two copies rather than a symlink because nothing
# else in these scripts creates one, so ln is not a tool the ramdisk is known to
# have, and a copy is hash-verifiable.
#
# The fourth field is what ElleKit's own deb puts at that path, because
# finalize.sh installs that deb on a booted device and its dpkg -i replaces
# some of them. Verification has to accept both forms: requiring the
# bytes and mode provisioning wrote reported a correctly finalized device
# MISMATCH, and re-provisioning then overwrote package-owned files, after which
# the next finalize saw ellekit registered and never put them back.
#
#   pkg=<member>      the package ships a regular file; this is its tar member
#   pkglink=<member>  the package ships a symlink resolving to that member
#   -                 not in the package, so only the provisioned form is valid
#
# Taken from the package: ar x, then tar tvf on data.tar.xz. The two ellekit/
# dylibs are its own unsigned 0644 copies and TweakLoader.dylib is a symlink to
# ellekit/libinjector.dylib. The mode is not re-checked for those three: dpkg
# owns them after finalize and this script is not the authority on them.
TWEAK_SET="
payload/tweaks/libinjector.dylib:/mnt2/jb/usr/lib/ellekit/libinjector.dylib:0755:pkg=./var/jb/usr/lib/ellekit/libinjector.dylib
payload/tweaks/libinjector.dylib:/mnt2/jb/usr/lib/TweakLoader.dylib:0755:pkglink=./var/jb/usr/lib/ellekit/libinjector.dylib
payload/tweaks/MobileSafety.dylib:/mnt2/jb/usr/lib/ellekit/MobileSafety.dylib:0755:pkg=./var/jb/usr/lib/ellekit/MobileSafety.dylib
payload/tweaks/LICENSE:/mnt2/jb/usr/share/doc/ellekit/LICENSE:0644:pkg=./var/jb/usr/share/doc/ellekit/LICENSE
payload/tweaks/TweakInject/l8localauth.dylib:/mnt2/jb/usr/lib/TweakInject/l8localauth.dylib:0755:-
payload/tweaks/TweakInject/l8localauth.plist:/mnt2/jb/usr/lib/TweakInject/l8localauth.plist:0644:-
payload/tweaks/TweakInject/l8persona.dylib:/mnt2/jb/usr/lib/TweakInject/l8persona.dylib:0755:-
payload/tweaks/TweakInject/l8persona.plist:/mnt2/jb/usr/lib/TweakInject/l8persona.plist:0644:-
"

# Split one table entry into tweak_src/tweak_dst/tweak_mode/tweak_pkg. Written
# once because four colon-separated fields parsed inline three times is where
# the install and verify copies drifted apart in the first place.
tweak_fields() {
    tweak_src=${1%%:*}
    _rest=${1#*:}
    tweak_dst=${_rest%%:*}
    _rest=${_rest#*:}
    tweak_mode=${_rest%%:*}
    tweak_pkg=${_rest#*:}
}

# How much of the set the host built, decided once so this step and the
# verification at the bottom cannot disagree about what "nothing built" means.
TWEAK_PAYLOAD=complete
tweak_any=0
for entry in $TWEAK_SET; do
    if [ -f "${entry%%:*}" ]; then tweak_any=1; else TWEAK_PAYLOAD=partial; fi
done
[ "$tweak_any" = 1 ] || TWEAK_PAYLOAD=none

# The deb is the oracle for the post-finalize form of the three paths dpkg owns,
# so it has to be the pinned archive and not whatever is sitting in a mutable
# work directory. Without this, replacing payload/tweaks/ellekit.deb made the
# check agree with a device carrying the same replaced bytes. Same pin
# fetch_payloads.sh verifies on download and finalize.sh verifies before
# installing; checked here at the top because the comparison itself runs inside
# a command substitution, where a die would only end the subshell.
. ./ellekit.pin
if [ -f payload/tweaks/ellekit.deb ]; then
    ek_got=$(shasum -a 256 payload/tweaks/ellekit.deb | awk '{print $1}')
    [ "$ek_got" = "$ELLEKIT_SHA" ] \
        || die "payload/tweaks/ellekit.deb does not match the pinned digest; got $ek_got"
fi

# The package members the table refers to, deduplicated. Derived from TWEAK_SET
# so the extraction below and the comparisons above cannot ask for different
# files.
tweak_pkg_members() {
    for entry in $TWEAK_SET; do
        case "${entry##*:}" in pkg=*|pkglink=*) echo "${entry##*=}" ;; esac
    done | sort -u
}

# The mode ellekit.pin records for one device path, or nothing if the pin does
# not describe it. Same table finalize.sh checks against, so the two scripts
# cannot disagree about what the package ships.
tweak_pkg_mode() {
    for entry in $ELLEKIT_FILE_MODES; do
        [ "${entry#*:}" = "$1" ] && { echo "${entry%%:*}"; return 0; }
    done
    return 0
}

# sha256 of one member of ElleKit's deb, extracted once and cached. Needed to
# recognise the post-finalize form of the three paths dpkg owns. Prints nothing
# when the deb is absent, which the callers treat as "cannot compare".
tweak_pkg_hash() {
    [ -f payload/tweaks/ellekit.deb ] || return 0
    # Keyed on a marker written only after the extraction finished and every
    # member was checked present. The directory's own existence was the key
    # before, so an extraction interrupted after its mkdir left an empty
    # directory that every later run took for a finished cache: this returned
    # nothing, a correctly finalized device was reported MISMATCH, and
    # `fw provision --check` refused to call the boot safe until someone deleted
    # the directory by hand. Testing for the members instead is not enough
    # either, because tar interrupted mid-member leaves a short file that exists.
    # The marker carries the digest it was extracted from, not just its own
    # existence. A persistent work directory survives a pin bump, so a marker
    # that said only "finished" kept serving the previous package's members as
    # the oracle and would have accepted a device still on the old layout.
    if [ "$(cat payload/.work/ekpkg/.complete 2>/dev/null)" != "$ELLEKIT_SHA" ]; then
        rm -rf payload/.work/ekpkg
        mkdir -p payload/.work/ekpkg || return 0
        # Named members only, for the reason fetch_payloads.sh gives: the full
        # payload would also unpack symlinks pointing at absolute /var/jb paths
        # that do not exist on a Mac, and a dangling one under device/ breaks
        # the copytree in prepare_runtime.
        # The member list comes from the same helper the check above uses, so a
        # path added to the table cannot be verified against a file this never
        # extracts.
        # shellcheck disable=SC2046  # one tar argument per member, so it must split
        ( cd payload/.work/ekpkg \
            && ar x "$PWD/../../tweaks/ellekit.deb" \
            && xz -dc data.tar.xz | tar xf - $(tweak_pkg_members) ) >/dev/null 2>&1 \
            || return 0
        for member in $(tweak_pkg_members); do
            [ -f "payload/.work/ekpkg/$member" ] || return 0
        done
        printf '%s\n' "$ELLEKIT_SHA" > payload/.work/ekpkg/.complete
    fi
    [ -f "payload/.work/ekpkg/$1" ] || return 0
    shasum -a 256 "payload/.work/ekpkg/$1" | awk '{print $1}'
}

# Which of the two valid layouts the device is in. finalize.sh installs
# ElleKit's deb on a booted device, and its dpkg -i replaces three of the seven
# paths with the package's own copies, TweakLoader.dylib among them as a
# symlink. A symlink there is therefore the one observable that says dpkg has
# been through, since provisioning only ever writes a regular file.
#
# Read from the device, not assumed: this is the post-finalize form the package
# ships, and the transition itself has not been watched on hardware yet.
#
# ssh's status is checked before the answer is matched. This ended in a pipe
# into tr, which exits 0 whatever sh_dev did, so an exhausted retry returned an
# empty string: not `finalized`, so the install loop below took the provisioned
# branch and overwrote the files dpkg owns.
tweak_stage() {
    ts_out=$(sh_dev '[ -L /mnt2/jb/usr/lib/TweakLoader.dylib ] && echo finalized || echo provisioned') \
        || { echo unreadable; return; }
    # Matched as substrings so a trailing carriage return needs no stripping.
    case "$ts_out" in
        *finalized*)   echo finalized ;;
        *provisioned*) echo provisioned ;;
        *)             echo unreadable ;;
    esac
}

# Why the three tweak destinations are unacceptable, or nothing. lhook loads
# whatever ends up under them into root processes, so a symlink or a directory
# another account can write replaces a verified tweak.
#
# Shared with the verify step, which is the finding: this ran only on the
# install path, so `--check` called a symlinked or mode-0777 TweakInject clean.
# Absent is not a fault here; the per-entry content checks report that.
tweak_dir_faults() {
    td_out=$(sh_dev '
for d in /mnt2/jb/usr/lib/ellekit /mnt2/jb/usr/lib/TweakInject /mnt2/jb/usr/share/doc/ellekit; do
    if [ -L "$d" ]; then echo "symlink $d"; continue; fi
    [ -e "$d" ] || continue
    if [ ! -d "$d" ]; then echo "not a directory $d"; continue; fi
    set -- $(ls -ldn "$d")
    case "$1" in
        ?????w*)    echo "group writable $d" ;;
        ????????w*) echo "other writable $d" ;;
    esac
    [ "$3" = 0 ] || echo "owner uid $3 $d"
done
echo CHECKED_OK') || { echo "could not read the tweak destinations"; return; }
    case "$td_out" in
        *CHECKED_OK*) ;;
        *) echo "could not read the tweak destinations"; return ;;
    esac
    printf '%s\n' "$td_out" | tr -d '\r' | grep -v CHECKED_OK || true
}

# Same policy the injection step applies to .lhook_enabled: a provision leaves
# the device inert, so an armed marker from a previous run is set aside rather
# than carried into a boot nobody asked to arm. Both tweaks read their own
# marker, so both are set aside.
#
# Shared with the nothing-to-install path below, which is the case that made
# this a function. Having it only on the install path meant a device that had
# been provisioned before, revisited from a fresh work directory with no host
# payload, kept whatever marker was already armed: the run reported no loader
# installed while leaving a tweak live for the next boot.
set_aside_tweak_markers() {
    must_dev '
for m in .liter8-localauth .liter8-persona; do
    if [ -e "/mnt2/jb/$m" ]; then
        mv -f "/mnt2/jb/$m" "/mnt2/jb/$m.pre-provision"
    fi
done
echo DONE_OK
' "could not set aside an existing tweak marker"
}

# Nothing built, rather than a bad build: fetch_payloads.sh skips the whole set
# when ellekit.space is unreachable instead of ending a provision before
# Dropbear is installed, so this skips to match. A set that is partly there is
# a different thing and still stops the run below.
if wants tweaks && [ "$CHECK_ONLY" = 0 ] && [ "$TWEAK_PAYLOAD" = none ]; then
    say "tweak loader and TweakInject payloads"
    skip "payload/tweaks absent; run ./fetch_payloads.sh tweaks with network"
    # Nothing to install is not nothing to do. The device may already carry a
    # loader and an armed marker from an earlier provision, so report what is
    # actually there and leave the markers disarmed either way.
    skip "installed loader: $(tweak_stage)"
    set_aside_tweak_markers
    skip "any armed tweak marker has been set aside; injection needs lhookctl enable"
elif wants tweaks && [ "$CHECK_ONLY" = 0 ]; then
    say "tweak loader and TweakInject payloads"
    for entry in $TWEAK_SET; do
        required=${entry%%:*}
        [ -f "$required" ] || die "$required absent; run ./fetch_payloads.sh tweaks"
    done

    for binary in payload/tweaks/libinjector.dylib payload/tweaks/MobileSafety.dylib \
                  payload/tweaks/TweakInject/l8localauth.dylib \
                  payload/tweaks/TweakInject/l8persona.dylib; do
        codesign -v "$binary" || die "$binary code-slot verification failed"
        # ElleKit ships its dylibs at flags=0x0, which needs a trust cache this
        # device does not have. fetch_payloads.sh re-signs them; assert it ran.
        codesign -dv "$binary" 2>&1 | grep -q 'flags=0x2(adhoc)' \
            || die "$binary is not ad-hoc signed"
        [ -z "$("$LDID" -e "$binary")" ] \
            || die "$binary unexpectedly carries entitlements"
        archs=$(lipo -archs "$binary")
        case " $archs " in *" arm64 "*)  ;; *) die "$binary is missing arm64"  ;; esac
        case " $archs " in *" arm64e "*) ;; *) die "$binary is missing arm64e" ;; esac
    done
    for filter in payload/tweaks/TweakInject/*.plist; do
        plutil -lint "$filter" >/dev/null || die "$filter does not lint"
    done
    ok "host payload verified: ad-hoc, both slices, no entitlements, filters lint"

    mkdir -p payload/.work
    # Real directories, not links to them. mkdir -p is happy with an existing
    # symlink, and every upload and root readback then follows it: point
    # TweakInject at /mnt1/usr/lib and the payloads land on the System volume
    # while verification reads them back through the same link and says OK.
    # Create, then judge with the same function verify uses. The link test is
    # before mkdir -p, which is happy with an existing symlink; the fault check
    # is after it, because mkdir keeps an existing directory's permissions.
    must_dev '
for d in /mnt2/jb/usr/lib/ellekit /mnt2/jb/usr/lib/TweakInject /mnt2/jb/usr/share/doc/ellekit; do
    if [ -L "$d" ]; then echo "SYMLINK $d"; exit 1; fi
    mkdir -p "$d" || exit 1
done
echo DONE_OK
' "could not create a tweak destination directory"
    tweak_dirs=$(tweak_dir_faults)
    # Deliberately not repaired here: a directory another account could write
    # may already hold a planted dylib, and fixing its mode would keep it. A run
    # from before the umask fix leaves these 0777; check their contents, then
    # chmod go-w them and rerun.
    [ -z "$tweak_dirs" ] || {
        printf '%s\n' "$tweak_dirs" | sed 's/^/        /'
        die "a tweak destination is unsafe or could not be read (if a pre-umask-fix run made it 0777, check its contents, chmod go-w, rerun)"
    }

    # TWEAK_SET above is deliberately the minimum that makes injection work with
    # no network and no dpkg: the injector, the safe-mode payload it names, and
    # the two tweaks. Both tweaks are Objective-C method swizzles linking only
    # Foundation, so none of it needs the hooking library.
    #
    # The hooking library, the substrate compatibility names and the dpkg record
    # that lets a repo tweak declare Depends: mobilesubstrate all arrive when
    # finalize.sh installs ElleKit's own deb on a booted device. They cannot come
    # from here: the names have to be symlinks and ln is not a tool the ramdisk
    # is known to have, and dpkg needs a booted bootstrap.
    # After finalize, dpkg owns four of these eight. Writing our re-signed
    # copies back over them puts unowned content under the package's name, turns
    # the symlink the package wants at TweakLoader.dylib back into a regular
    # file, and the next finalize sees ellekit registered so it never restores
    # either. The four TweakInject payloads are ours and always install.
    # Checked here rather than inside tweak_stage, where a die would only end
    # the command substitution's subshell. The layout decides whether four paths
    # are left to dpkg or overwritten, so a failed read stops the step.
    TWEAK_AT=$(tweak_stage)
    case "$TWEAK_AT" in
        finalized|provisioned) ;;
        *) die "could not read the tweak layout from the device" ;;
    esac
    [ "$TWEAK_AT" = finalized ] \
        && skip "ellekit's deb is installed; the files it owns are left to dpkg"
    # Before the first write, not after the last. Any failure in the loop below
    # exits the script, so disarming afterwards left an armed marker over a
    # half-replaced tweak set: the next lhookctl enable would activate whatever
    # mixture of old and new files the run happened to stop at. The promise is
    # that a provisioned device is inert, and that has to hold on the failure
    # paths too.
    set_aside_tweak_markers
    for entry in $TWEAK_SET; do
        tweak_fields "$entry"
        src=$tweak_src
        dst=$tweak_dst
        mode=$tweak_mode
        if [ "$TWEAK_AT" = finalized ] && [ "$tweak_pkg" != - ]; then
            skip "/var/jb${dst#/mnt2/jb} (package owned)"
            continue
        fi
        want=$(shasum -a 256 "$src" | awk '{print $1}')
        # Unlinked first: put writes with `cat > $dst.new`, which follows a
        # symlink already sitting there and would have root overwrite its
        # target. Also clears a stale .new left by an interrupted run.
        must_dev "rm -f '$dst.new' && echo DONE_OK" "could not clear $dst.new"
        put "$src" "$dst.new"
        sh_dev "cat '$dst.new'" > payload/.work/tweak.staged
        [ "$(shasum -a 256 payload/.work/tweak.staged | awk '{print $1}')" = "$want" ] \
            || die "staged $dst hash mismatch; nothing was activated"
        must_dev "chmod $mode '$dst.new' && mv -f '$dst.new' '$dst' && echo DONE_OK" \
            "could not install $dst"
        sh_dev "cat '$dst'" > payload/.work/tweak.readback
        [ "$(shasum -a 256 payload/.work/tweak.readback | awk '{print $1}')" = "$want" ] \
            || die "$dst readback hash mismatch"
        ok "/var/jb${dst#/mnt2/jb} ($mode)"
    done

    ok "loader in place; injection needs lhookctl enable, each tweak needs its marker"
fi

# ------------------------------------------------------------------- cache
if wants cache && [ "$CHECK_ONLY" = 0 ]; then
    say "launchd service cache"
    CACHE=boot/work/launchd.plist
    if [ ! -f "$CACHE" ]; then
        skip "no patched cache at $CACHE; build it with fetch_payloads.sh cache"
    else
        n=$(python3 -c "import plistlib,sys;print(len(plistlib.load(open('$CACHE','rb'))['LaunchDaemons']))")
        [ "$n" = "$((LAUNCHD_CACHE_DAEMONS + 3))" ] \
            || die "$CACHE has $n daemons, expected $((LAUNCHD_CACHE_DAEMONS + 3)) for this profile"
        for j in com.dropbear com.jbboot com.liter8.ddi-services; do
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
        python3 -c "
import plistlib,sys
from patch_watchdogd_job import watchdogd_job_is_mitigated
d=plistlib.load(open('$CACHE','rb'))
sys.exit(0 if watchdogd_job_is_mitigated(d) else 1)" \
            || die "$CACHE does not contain the reviewed watchdogd mitigation"
        python3 -c "
import plistlib,sys
from add_ddi_services import CACHE_KEY, DDI_SERVICES_JOB
d=plistlib.load(open('$CACHE','rb'))['LaunchDaemons']
sys.exit(0 if d.get(CACHE_KEY) == DDI_SERVICES_JOB else 1)" \
            || die "$CACHE contains a stale or modified DeveloperDiskImage registration job"
        ok "cache has $n daemons including Dropbear, jbboot, DDI registration and the watchdogd mitigation"
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
    for required in boot/jbboot.sh spawnprobe/personaalloc ddiwatch/ddiwatch boothelper/l8boot \
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
    ddiwatch_sha=$(shasum -a 256 ddiwatch/ddiwatch | awk '{print $1}')
    put ddiwatch/ddiwatch /mnt1/usr/local/bin/ddiwatch.usbl8r-new
    put ddiwatch/ddiwatch /mnt2/jb/usr/bin/ddiwatch.usbl8r-new
    sh_dev '
chmod 755 /mnt1/usr/local/bin/ddiwatch.usbl8r-new /mnt2/jb/usr/bin/ddiwatch.usbl8r-new
mv -f /mnt1/usr/local/bin/ddiwatch.usbl8r-new /mnt1/usr/local/bin/ddiwatch
mv -f /mnt2/jb/usr/bin/ddiwatch.usbl8r-new /mnt2/jb/usr/bin/ddiwatch
'
    sh_dev '/bin/cat /mnt1/usr/local/bin/ddiwatch' > payload/.work/ddiwatch.readback
    [ "$(shasum -a 256 payload/.work/ddiwatch.readback | awk '{print $1}')" = "$ddiwatch_sha" ] \
        || die "ddiwatch readback hash mismatch"
    codesign -v payload/.work/ddiwatch.readback \
        || die "ddiwatch readback signature verification failed"
    ok "ddiwatch ($ddiwatch_sha)"

    # System copy only: jbboot.sh runs it from the com.jbboot job, and launchd
    # cannot exec anything under /var/jb.
    l8boot_sha=$(shasum -a 256 boothelper/l8boot | awk '{print $1}')
    put boothelper/l8boot /mnt1/usr/local/bin/l8boot.usbl8r-new
    sh_dev 'chmod 755 /mnt1/usr/local/bin/l8boot.usbl8r-new && mv -f /mnt1/usr/local/bin/l8boot.usbl8r-new /mnt1/usr/local/bin/l8boot' \
        || die "could not activate l8boot"
    sh_dev '/bin/cat /mnt1/usr/local/bin/l8boot' > payload/.work/l8boot.readback
    [ "$(shasum -a 256 payload/.work/l8boot.readback | awk '{print $1}')" = "$l8boot_sha" ] \
        || die "l8boot readback hash mismatch"
    codesign -v payload/.work/l8boot.readback \
        || die "l8boot readback signature verification failed"
    ok "l8boot ($l8boot_sha)"

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
    "$GTAR" czf "$TARB" --owner=0 --group=80 --numeric-owner --no-xattrs \
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
        # Bound to the firmware it was built from, not just to its own
        # existence. A work directory reused across builds kept a 659 MB archive
        # of the previous firmware's system apps and streamed it onto
        # /Applications, which is the wrong apps installed quietly. The reviewed
        # stock launchd hash is the build fingerprint this script already has.
        TAR_BUILD=payload/apps50.build
        if [ ! -f "$TAR" ] || [ "$(cat "$TAR_BUILD" 2>/dev/null)" != "$LAUNCHD_SHA" ]; then
            [ -f "$TAR" ] && ok "$TAR was built from another firmware; rebuilding"
            rm -f "$TAR" "$TAR_BUILD"
            ok "building $TAR (659 MB, about a minute)"
            mkdir -p payload
            # -C "$SRC" . rather than a word-split $(ls): archives the whole
            # directory without relying on app names being space-free.
            # Entries come out as ./Calculator.app/..., which extracts correctly.
            "$GTAR" czf "$TAR" --owner=0 --group=80 --numeric-owner \
                --no-xattrs --mode='g+w' -C "$SRC" . \
                || die "could not build $TAR"
            # After the archive, so an interrupted build is not taken for a
            # finished one on the next run.
            printf '%s\n' "$LAUNCHD_SHA" > "$TAR_BUILD"
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
        ""|*ABSENT*|*MISSING*|*LOST*|*MISMATCH*|*UNREADABLE*|*UNSAFE*|ENABLED) FAIL=1 ;;
    esac
}

# Decide a presence marker exactly as the code that reads it decides: a regular
# file, root owned, and not group or other writable. l8fdr.c:bypass_enabled(),
# l8localauth.m:marker_enabled() and l8persona.m:marker_enabled() all test that,
# so testing only for existence reported markers live that every consumer then
# rejects, which leaves the feature off while provisioning calls it on.
#
# Parsed out of `ls -ln` rather than stat(1), whose format flag is not portable:
# this ramdisk carries GNU coreutils, where `stat -f` asks about the filesystem
# instead of the file and the owner test silently reads as a failure. awk is not
# present either, so the mode string is matched with shell globs. Fields are
# mode, links, uid; mode positions 6 and 9 are the group and other write bits.
#
# Prints MISSING, OK, or BAD with the reason.
marker_state() {
    sh_dev "M='$1'"'
if [ ! -f "$M" ] || [ -L "$M" ]; then echo MISSING; exit 0; fi
set -- $(ls -ln "$M")
case "$1" in
    ?????w*)    echo "BAD (group writable)"; exit 0 ;;
    ????????w*) echo "BAD (other writable)"; exit 0 ;;
esac
[ "$3" = 0 ] && echo OK || echo "BAD (owner uid $3, not root)"' | tr -d '\r'
}

# The same verdict in the vocabulary the two tweak markers report in. A
# provision sets both aside, so one that is live here is an anomaly and ENABLED
# fails the run. A malformed one is not an anomaly: the tweak rejects it, so it
# reports dormant with the reason instead of failing on a device that is in fact
# inert.
tweak_marker() {
    state=$(marker_state "$1")
    case "$state" in
        MISSING) echo dormant ;;
        OK)      echo ENABLED ;;
        *)       echo "dormant, $state" ;;
    esac
}

# The opposite case: a marker the device is meant to be carrying, where both
# absent and malformed are faults. Testing only for existence reported OK for
# markers l8pair.c and l8remotepairing.c then reject on exactly the terms
# marker_state checks, which leaves the fallback off while this calls it on.
required_marker() {
    state=$(marker_state "$1")
    case "$state" in BAD*) echo "MISMATCH $state" ;; *) echo "$state" ;; esac
}

# `ls -ln` is the only mode reader this ramdisk can be relied on for, so the
# octal modes in TWEAK_SET are matched against their symbolic form. Listed
# rather than computed, and fatal on anything unlisted, so adding a mode to the
# table cannot quietly turn its verification into a no-op.
symbolic_mode() {
    case "$1" in
        0755) echo '-rwxr-xr-x' ;;
        0644) echo '-rw-r--r--' ;;
        *)    die "no symbolic form recorded for mode $1" ;;
    esac
}

# Say why one tweak-set entry's device copy is unacceptable, or print nothing.
#
# Two layouts are valid and a correct device can be in either: what provisioning
# wrote, and what ElleKit's deb leaves at the three paths it owns once finalize
# has installed it. Accepting only the first reported MISMATCH for a finalized
# device, which is the normal end state of the documented workflow.
tweak_entry_fault() {
    tweak_fields "$1"
    # Which path the content is read from. Normally the entry's own, but not for
    # a path the package replaced with a symlink: ElleKit's link text is the
    # absolute /var/jb/usr/lib/ellekit/libinjector.dylib, and in SSHRD /var is
    # the ramdisk's own read-only tree while the Data volume is /mnt2 (the same
    # mapping install_bootstrap.sh records). Following it from here lands in the
    # wrong root and returns nothing, so a correctly finalized loader read as
    # absent. The link names an image that is itself an entry in this table, so
    # its target is translated to the mounted path and read there.
    tf_read=$tweak_dst
    tf_islink=0
    case "$tweak_pkg" in
        pkglink=*)
            if sh_dev "[ -L '$tweak_dst' ]" >/dev/null 2>&1; then
                tf_islink=1
                tf_read=/mnt2/jb${tweak_pkg#*=./var/jb}
            fi ;;
    esac
    sh_dev "cat '$tf_read'" > payload/.work/verify.tweak 2>/dev/null || true
    [ -s payload/.work/verify.tweak ] || { echo absent; return; }
    tf_got=$(shasum -a 256 payload/.work/verify.tweak | awk '{print $1}')

    # Content alone is not enough: these reads run as root over ssh, so cat of a
    # mode-000 loader returns the right bytes while dlopen from every ordinary
    # process fails. Compared symbolically because `ls -ln` is what this ramdisk
    # can be relied on to produce; see marker_state above for why not stat(1).
    # GNU ls appends '.' or '+' for an ACL, so a trailing one is dropped.
    tf_ls=$(sh_dev "ls -ln '$tweak_dst'" | tr -d '\r')
    tf_mode=$(printf '%s\n' "$tf_ls" | awk '{print $1}')
    tf_mode=${tf_mode%[.+]}
    tf_uid=$(printf '%s\n' "$tf_ls" | awk '{print $3}')
    [ "$tf_uid" = 0 ] || { echo "owner uid $tf_uid, not root"; return; }

    # The form provisioning writes. Its mode is ours to require.
    if [ "$tf_got" = "$(shasum -a 256 "$tweak_src" | awk '{print $1}')" ]; then
        [ "$tf_mode" = "$(symbolic_mode "$tweak_mode")" ] || echo "mode $tf_mode"
        return
    fi

    # The form ElleKit's package leaves behind. Only the paths carrying a package
    # form may take it.
    case "$tweak_pkg" in
        pkg=*|pkglink=*) ;;
        *) echo "content"; return ;;
    esac
    tf_pkg=$(tweak_pkg_hash "${tweak_pkg#*=}")
    [ -n "$tf_pkg" ] \
        || { echo "content, and no ellekit.deb here to compare the package form"; return; }
    [ "$tf_got" = "$tf_pkg" ] || { echo content; return; }
    # The mode is the package's to choose, but not anyone else's to change. An
    # earlier comment here said it was dpkg's business and checked nothing,
    # which accepted a mode-000 injector that no ordinary process can load,
    # exactly as the provisioned form did before it was checked. The expectation
    # is the one finalize.sh uses, out of ellekit.pin.
    tf_want=$(tweak_pkg_mode "/var/jb${tweak_pkg#*=./var/jb}")
    if [ -n "$tf_want" ] && [ "$tf_islink" = 0 ] && [ "$tf_mode" != "$tf_want" ]; then
        echo "mode $tf_mode, the package ships $tf_want"
        return
    fi
    case "$tweak_pkg" in
        pkglink=*)
            [ "$tf_islink" = 1 ] \
                || { echo "the package ships a symlink here, found $tf_mode"; return; }
            # Where the link actually points, not just that it is one. Reading
            # the declared canonical path rather than following the link fixed
            # the wrong-root problem but stopped checking the link at all: a
            # loader repointed at MobileSafety.dylib still produced the expected
            # injector hash and passed, while the next normal boot followed the
            # wrong link and loaded no injector.
            #
            # Taken from the `ls -ln` already fetched above, which prints
            # "... name -> target" for a symlink, so this needs no readlink;
            # that tool is not part of this ramdisk's known set.
            tf_target=${tf_ls#*" -> "}
            [ "$tf_target" != "$tf_ls" ] \
                || { echo "could not read the link target from: $tf_ls"; return; }
            [ "$tf_target" = "/var/jb${tweak_pkg#*=./var/jb}" ] \
                || echo "link points at $tf_target" ;;
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
   [ "$("$LDID" -e payload/.work/verify.Setup)" = \
     "$("$LDID" -e payload/.work/verify.Setup.orig)" ]; then
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
            --liter8 "$LITER8_SELF" --ldid "$LDID" \
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
verify_userland_patch lockdownd /mnt1/usr/libexec/lockdownd
verify_userland_patch remotepairingdeviced /mnt1/usr/libexec/remotepairingdeviced
if [ "$HAS_BASEBAND" = 1 ]; then
    verify_userland_patch CommCenter \
        /mnt1/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter
else
    note "CommCenter patch" "not used: this board has no baseband"
fi

if [ -f payload/l8pair.dylib ]; then
    pairing_want=$(shasum -a 256 payload/l8pair.dylib | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/lib/l8pair.dylib' \
        > payload/.work/verify.l8pair 2>/dev/null || true
    if [ -s payload/.work/verify.l8pair ] && \
       [ "$(shasum -a 256 payload/.work/verify.l8pair | awk '{print $1}')" = "$pairing_want" ] && \
       codesign -v payload/.work/verify.l8pair >/dev/null 2>&1; then
        pairing_library_state=OK
    else
        pairing_library_state=MISMATCH
    fi
else
    pairing_library_state=MISSING
fi
note "l8pair dylib" "$pairing_library_state"
if [ -f payload/l8remotepairing.dylib ]; then
    remotepairing_want=$(shasum -a 256 payload/l8remotepairing.dylib | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/lib/l8remotepairing.dylib' \
        > payload/.work/verify.l8remotepairing 2>/dev/null || true
    if [ -s payload/.work/verify.l8remotepairing ] && \
       [ "$(shasum -a 256 payload/.work/verify.l8remotepairing | awk '{print $1}')" = "$remotepairing_want" ] && \
       codesign -v payload/.work/verify.l8remotepairing >/dev/null 2>&1; then
        remotepairing_library_state=OK
    else
        remotepairing_library_state=MISMATCH
    fi
else
    remotepairing_library_state=MISSING
fi
note "l8remotepairing dylib" "$remotepairing_library_state"
if [ -f payload/l8coreauth.dylib ]; then
    coreauth_want=$(shasum -a 256 payload/l8coreauth.dylib | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/lib/l8coreauth.dylib' \
        > payload/.work/verify.l8coreauth 2>/dev/null || true
    if [ -s payload/.work/verify.l8coreauth ] && \
       [ "$(shasum -a 256 payload/.work/verify.l8coreauth | awk '{print $1}')" = "$coreauth_want" ] && \
       codesign -v payload/.work/verify.l8coreauth >/dev/null 2>&1; then
        coreauth_library_state=OK
    else
        coreauth_library_state=MISMATCH
    fi
else
    coreauth_library_state=MISSING
fi
note "l8coreauth dylib" "$coreauth_library_state"
if [ "$HAS_BASEBAND" = 0 ]; then
    fdr_library_state="not used: this board has no baseband"
elif [ -f payload/l8fdr.dylib ]; then
    fdr_want=$(shasum -a 256 payload/l8fdr.dylib | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/lib/l8fdr.dylib' \
        > payload/.work/verify.l8fdr 2>/dev/null || true
    if [ -s payload/.work/verify.l8fdr ] && \
       [ "$(shasum -a 256 payload/.work/verify.l8fdr | awk '{print $1}')" = "$fdr_want" ] && \
       codesign -v payload/.work/verify.l8fdr >/dev/null 2>&1; then
        fdr_library_state=OK
    else
        fdr_library_state=MISMATCH
    fi
else
    fdr_library_state=MISSING
fi
note "l8fdr dylib" "$fdr_library_state"
# Reported separately from the dylib: with the dylib present and the marker gone the
# bypass is deliberately inert, which is a recovery state rather than a broken one.
if [ "$HAS_BASEBAND" = 1 ]; then
    note "FDR sik bypass marker" "$(required_marker /mnt1/usr/lib/.liter8-fdr-sik-bypass)"
fi
note "pairing fallback marker" "$(required_marker /mnt2/root/Library/Lockdown/.liter8-pairing-fallback)"
note "RemoteXPC fallback marker" "$(required_marker /mnt1/usr/lib/.liter8-remotepairing-fallback)"
note "pairing fallback key" "$(sh_dev '[ -s /mnt2/root/Library/Lockdown/liter8_pairing_key.der ] && echo generated || echo pending' | tr -d '\r')"

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
if [ -f ddiwatch/ddiwatch ]; then
    expected_ddiwatch=$(shasum -a 256 ddiwatch/ddiwatch | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/local/bin/ddiwatch' \
        > payload/.work/verify.ddiwatch 2>/dev/null || true
    if [ -s payload/.work/verify.ddiwatch ] && \
       [ "$(shasum -a 256 payload/.work/verify.ddiwatch | awk '{print $1}')" = "$expected_ddiwatch" ] && \
       codesign -v payload/.work/verify.ddiwatch >/dev/null 2>&1; then
        ddiwatch_state=OK
    else
        ddiwatch_state=MISMATCH
    fi
else
    ddiwatch_state=MISSING
fi
note "ddiwatch System" "$ddiwatch_state"
if [ -f boothelper/l8boot ]; then
    expected_l8boot=$(shasum -a 256 boothelper/l8boot | awk '{print $1}')
    sh_dev '/bin/cat /mnt1/usr/local/bin/l8boot' \
        > payload/.work/verify.l8boot 2>/dev/null || true
    if [ -s payload/.work/verify.l8boot ] && \
       [ "$(shasum -a 256 payload/.work/verify.l8boot | awk '{print $1}')" = "$expected_l8boot" ] && \
       codesign -v payload/.work/verify.l8boot >/dev/null 2>&1; then
        l8boot_state=OK
    else
        l8boot_state=MISMATCH
    fi
else
    l8boot_state=MISSING
fi
note "l8boot System" "$l8boot_state"
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
        sh_dev 'cat /mnt1/usr/lib/lhook' > payload/.work/verify.lhook 2>/dev/null || true
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
            sh_dev '[ -x /mnt1/usr/lib/lhook ]' \
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

if [ -f payload/lhookctl ]; then
    verify_lhookctl=$(shasum -a 256 payload/lhookctl | awk '{print $1}')
    sh_dev 'cat /mnt2/jb/usr/bin/lhookctl' > payload/.work/verify.lhookctl 2>/dev/null || true
    [ -s payload/.work/verify.lhookctl ] && \
        [ "$(shasum -a 256 payload/.work/verify.lhookctl | awk '{print $1}')" = "$verify_lhookctl" ] && \
        sh_dev '[ -x /mnt2/jb/usr/bin/lhookctl ]' \
        && lhookctl_state=OK || lhookctl_state=MISMATCH
else
    lhookctl_state=MISSING
fi
# Without the controller the session-bound hook cannot be enabled through the
# documented interface, so --check reporting the injection setup complete while
# it is absent is a false pass. The write path hashed it; this is the path that
# runs on its own.
note "lhookctl" "$lhookctl_state"

# A marker observed from the ramdisk is stale by construction: it holds the UUID
# of a boot session that has already ended, and kern.bootsessionuuid is new on
# every boot, so the guard in lhook_session.h cannot match it. Reporting its
# presence as ENABLED made `fw provision --check` call a safe device unsafe,
# because --check runs only mounts and verify and so never reaches the step that
# moves the marker aside. Report the file, not a verdict the guard contradicts.
note "lhook first boot" "$(sh_dev '[ -e /mnt2/jb/.lhook_enabled ] && echo "stale marker, guard disables it" || echo disabled' | tr -d '\r')"

# The tweak set. Every file compared byte-for-byte against what the host built,
# including the second copy of the loader at the path lhook dlopens: that one is
# the whole point, and a missing TweakLoader.dylib is exactly the state where
# injection silently does nothing.
if [ "$TWEAK_PAYLOAD" = none ]; then
    # Not a failure. fetch_payloads.sh skips the whole set when ellekit.space is
    # unreachable and the provisioning step skips with it, so an operator who
    # ran without network has no tweak stack by design. Nothing on the device
    # needs one to boot, and calling this MISSING failed a run that is fine.
    tweak_state="not built"
elif [ "$TWEAK_PAYLOAD" = partial ]; then
    tweak_state="MISSING part of the host tweak payload"
else
    tweak_state=OK
    for entry in $TWEAK_SET; do
        tweak_fields "$entry"
        v_fault=$(tweak_entry_fault "$entry")
        [ -z "$v_fault" ] || {
            tweak_state="MISMATCH /var/jb${tweak_dst#/mnt2/jb} ($v_fault)"
            break
        }
    done
fi
note "tweak loader set" "$tweak_state"

# The directories, not just their contents: a verified tweak in a directory
# another account can write is one rename away from being replaced.
tweak_dirs=$(tweak_dir_faults)
if [ -n "$tweak_dirs" ]; then
    note "tweak destinations" "UNSAFE $(printf '%s' "$tweak_dirs" | tr '\n' ',')"
else
    note "tweak destinations" "no symlink, nothing writable by another account"
fi
# ENABLED is a failure for these two but not for .lhook_enabled above, and the
# difference is real rather than an oversight. The injection marker is session
# bound: it carries a boot-session UUID the guard compares, so a leftover one is
# inert. These two have no session to compare, so a well-formed leftover is live
# on the next boot. Nothing neutralises them, which is why a provision sets them
# aside and why finding one here is a genuine anomaly.
note "l8localauth first boot" "$(tweak_marker /mnt2/jb/.liter8-localauth)"
note "l8persona first boot" "$(tweak_marker /mnt2/jb/.liter8-persona)"

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
need = ["com.dropbear", "com.jbboot", "com.liter8.ddi-services"]
missing = [j for j in need if f"/System/Library/LaunchDaemons/{j}.plist" not in ld]
from patch_launchd_cache import CACHE_KEY, DROPBEAR_JOB
dropbear_ok = ld.get(CACHE_KEY) == DROPBEAR_JOB
from add_ddi_services import CACHE_KEY as DDI_CACHE_KEY, DDI_SERVICES_JOB
ddi_ok = ld.get(DDI_CACHE_KEY) == DDI_SERVICES_JOB
from patch_watchdogd_job import watchdogd_job_is_mitigated
watchdogd_ok = watchdogd_job_is_mitigated({"LaunchDaemons": ld})
if missing:
    state = f"MISSING {missing}"
elif not dropbear_ok:
    state = "MISMATCH com.dropbear"
elif not ddi_ok:
    state = "MISMATCH com.liter8.ddi-services"
elif not watchdogd_ok:
    state = "MISMATCH watchdogd mitigation"
else:
    state = "all jobs present, watchdogd mitigated"
expected = int(__import__("os").environ["LITER8_LAUNCHD_CACHE_DAEMONS"]) + 3
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
