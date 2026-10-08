#!/bin/zsh
#
# Install debugserver. RUN FROM THE MAC, with the device on a NORMAL BOOT.
#
#   ./setup_debugger.sh            install
#   ./setup_debugger.sh --check    report device state, change nothing
#
# Needs ./fetch_payloads.sh debugserver first. That downloads three pinned debs
# from the Procursus index, verifies their SHA256, and re-signs debugserver with
# the three entitlements it ships without. Everything here just moves those
# artifacts onto the device, so the phone itself needs no network and no apt.
#
# Deliberately NOT part of sshrd_provision.sh: /var/jb lives on the Data volume
# and is writable on a normal boot, so none of this needs the System volume
# mounted read-write and folding it in would force a DFU cycle for a debugger.
#
# Deliberately NOT part of finalize.sh either. finalize completes the bootstrap
# and must stay on the critical path; a 53 MB optional debugger does not belong
# there.
#
# Why debugserver is re-signed at all: the stock binary can attach to a platform
# daemon, but it CANNOT set a hardware breakpoint. lldb reports the breakpoint as
# set and it then never fires. Verified by an A/B on one boot against one target.
#
# And why hardware breakpoints specifically: software breakpoints do not work on
# this platform at all. The write to a shared-cache code page is silently
# discarded, so `breakpoint set -H` is mandatory. Before the TXM debug-mapping
# gates were understood, the same attempt SIGKILLed the target with
# CODESIGNING / Invalid Page. See docs/design/DEBUGGING_PLATFORM_DAEMONS.md.

set -e
cd "${0:A:h}"

SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=25
        -o HostKeyAlgorithms=+ecdsa-sha2-nistp521 -o Ciphers=+aes128-ctr
        -p "${LITER8_SSH_PORT:-2222}")
DEV="root@${LITER8_SSH_HOST:-localhost}"
PW=alpine
SSHPASS=$(command -v sshpass || true)
"$SSHPASS" -V >/dev/null 2>&1 || SSHPASS=../tools/sshpass

CHECK_ONLY=0
[[ "$1" == "--check" ]] && CHECK_ONLY=1

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1" }
ok()   { printf '    [+] %s\n' "$1" }
skip() { printf '    [=] %s\n' "$1" }
die()  { printf '    [!] %s\n' "$1"; exit 1 }

sh_dev() { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "$@" }
put()    { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "cat > $2" < "$1" }

RPATH='export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'

# Must match the pins in fetch_payloads.sh. Asserted below so a bumped payload
# with a stale installer, or the reverse, stops here.
LLVM_VER="16.0.0~5.9.2~RELEASE-1"
DEBS=(
    "debugserver-16_${LLVM_VER}_iphoneos-arm64.deb"
    "libllvm16_${LLVM_VER}_iphoneos-arm64.deb"
    "libclang-cpp16_${LLVM_VER}_iphoneos-arm64.deb"
)
DS_PATH=/var/jb/usr/lib/llvm-16/bin/debugserver

say "checking payloads"
[[ -f payload/debugserver ]] \
    || die "payload/debugserver missing. Run ./fetch_payloads.sh debugserver first."
for d in "${DEBS[@]}"; do
    [[ -f "payload/$d" ]] || die "payload/$d missing. Run ./fetch_payloads.sh debugserver first."
done
for k in set-exception-port thread-set-state cs.debugger; do
    ../tools/ldid_macosx_arm64 -e payload/debugserver 2>/dev/null \
        | grep -q "com.apple.private.$k" \
        || die "payload/debugserver is missing com.apple.private.$k; re-run fetch_payloads.sh"
done
PAYLOAD_SHA=$(shasum -a 256 payload/debugserver | awk '{print $1}')
ok "payload present, re-signed, all three entitlements"

say "checking the device"
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    [[ "$DEV" == root@localhost && "${LITER8_SSH_PORT:-2222}" == 2222 ]] \
        || die "cannot reach $DEV on port ${LITER8_SSH_PORT:-2222}"
    command -v iproxy >/dev/null 2>&1 || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222:22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap 'kill "$IPROXY_PID" 2>/dev/null' EXIT
    sleep 2
fi

if ! MOUNTS=$(sh_dev '/sbin/mount' 2>/dev/null); then
    die "cannot reach normal-boot SSH on port 2222; the device may still be booting"
fi
if print -r -- "$MOUNTS" | grep -q 'md0 on /'; then
    die "device is in SSHRD. This one runs on a NORMAL boot."
fi
ok "normal boot"

sh_dev "$RPATH; command -v dpkg >/dev/null" \
    || die "dpkg not found. Run ./install_bootstrap.sh first."

# The device has no shasum and no openssl, so the file is read back and hashed
# on the Mac. Same approach as the uicache staging check in sshrd_provision.sh.
dev_sha_of() {
    local staged="payload/.work/setup_debugger.readback"
    mkdir -p payload/.work
    rm -f "$staged"
    sh_dev "$RPATH; [ -f $1 ] && cat $1" > "$staged" 2>/dev/null || true
    [[ -s "$staged" ]] || { print -n ""; return }
    shasum -a 256 "$staged" | awk '{print $1}'
}

DEV_SHA=$(dev_sha_of "$DS_PATH")
if [[ "$DEV_SHA" == "$PAYLOAD_SHA" ]]; then
    skip "device already has this exact re-signed debugserver"
    INSTALLED=1
else
    [[ -n "$DEV_SHA" ]] && ok "device has a different debugserver, will replace" \
                        || ok "debugserver not installed yet"
    INSTALLED=0
fi

if (( CHECK_ONLY )); then
    say "check only, nothing changed"
    # dpkg-query -f uses ${variable} substitution, not printf conversions.
    sh_dev "$RPATH; dpkg-query -W -f='    \${Package} \${Version} \${db:Status-Status}\n' \
        debugserver-16 libllvm16 libclang-cpp16 2>&1" || true
    exit 0
fi

if (( ! INSTALLED )); then
    say "installing the packages"
    # Pushed and installed from the Mac's verified copies, so the device needs
    # neither network nor a configured apt.
    sh_dev "$RPATH; mkdir -p /var/root/.liter8-debs"
    for d in "${DEBS[@]}"; do
        put "payload/$d" "/var/root/.liter8-debs/$d"
        ok "pushed $d"
    done
    sh_dev "$RPATH; cd /var/root/.liter8-debs && dpkg -i ${DEBS[*]} 2>&1 | tail -4" \
        || die "dpkg -i failed"
    sh_dev "$RPATH; rm -rf /var/root/.liter8-debs"
    ok "packages installed"

    say "installing the re-signed debugserver"
    # dpkg has just written the stock binary. Replace it in place, so the
    # packaged debugserver-16 symlink keeps working and there is no second copy
    # to keep in sync.
    put payload/debugserver "$DS_PATH.liter8-new"
    sh_dev "$RPATH; chmod 755 $DS_PATH.liter8-new && mv -f $DS_PATH.liter8-new $DS_PATH"
    GOT=$(dev_sha_of "$DS_PATH")
    [[ "$GOT" == "$PAYLOAD_SHA" ]] \
        || die "on-device debugserver hash is ${GOT:-unreadable}, expected $PAYLOAD_SHA"
    ok "re-signed debugserver in place"
fi

say "holding the packages"
# Without this an apt upgrade reinstalls the stock binary over the re-signed one
# and hardware breakpoints silently stop firing, which is a miserable thing to
# debug. --check reports drift via the hash comparison above.
sh_dev "$RPATH; apt-mark hold debugserver-16 libllvm16 libclang-cpp16 2>&1 | sed 's/^/    /'" || true

say "verifying"
VER=$(sh_dev "$RPATH; /var/jb/usr/bin/debugserver-16 --version 2>&1 | head -1" | tr -d '\r')
print -r -- "$VER" | grep -q 'PROJECT:lldb' || die "debugserver did not report a version: $VER"
ok "$VER"

say "done"
cat <<'EOF'
    Start a session (one pid or process name):

      ssh -p 2222 root@localhost \
        'nohup /var/jb/usr/bin/debugserver-16 127.0.0.1:1237 --attach=<pid> >/var/root/ds.log 2>&1 &'
      ssh -N -L 1237:127.0.0.1:1237 -p 2222 root@127.0.0.1

      lldb -o 'platform select remote-ios' -o 'process connect connect://127.0.0.1:1237'
      (lldb) breakpoint set -H -n <symbol>

    breakpoint set -H is required. Software breakpoints are silently dropped.
    Always `detach` in lldb before stopping debugserver: killing debugserver
    takes the attached process with it.

    Attaching to a daemon needs a DeviceSupport tree for this exact build or
    lldb hangs on connect. See docs/design/DEBUGGING_PLATFORM_DAEMONS.md.
EOF
