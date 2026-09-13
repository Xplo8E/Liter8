#!/bin/zsh
#
# Finish the extracted rootless bootstrap after the first normal boot.
#
# This cannot run from SSHRD. Procursus is mounted at /var/jb only during a
# normal boot, and LaunchServices plus SpringBoard do not exist in the ramdisk.
#
#   ./finalize.sh           finish bootstrap, shell and app registration
#   ./finalize.sh --check   report state without changing the device
#
# Every mutation is one-time and guarded. In particular, uicache -a must never
# become a per-boot repair: after container applications exist it can classify
# them incorrectly and make them disappear from the home screen.

set -e
cd "${0:A:h}"

SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=25 -p 2222)
DEV=root@localhost
PW=alpine
SSHPASS=../tools/sshpass
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

RPATH='export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
REGISTRATION_MARKER=/var/jb/.liter8-system-apps-registered

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1" }
ok()   { printf '    [+] %s\n' "$1" }
skip() { printf '    [=] %s\n' "$1" }
die()  { printf '    [!] %s\n' "$1"; exit 1 }

sh_dev() { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "$@" }

[[ -x "$SSHPASS" ]] || die "sshpass is missing at $SSHPASS"
[[ -x setup_shell.sh ]] || die "setup_shell.sh is missing beside finalize.sh"

say "normal-boot connection"

# Reuse an operator-owned forward when one exists. Otherwise Liter8 owns this
# temporary process and reliably stops it on every exit path.
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    command -v iproxy >/dev/null 2>&1 \
        || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222 22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap 'kill "$IPROXY_PID" 2>/dev/null' EXIT
    sleep 2
fi

if ! MOUNTS=$(sh_dev '/sbin/mount' 2>/dev/null); then
    die "SSH handshake on port 2222 failed; if Dropbear sends a banner but closes during key exchange, rerun fw provision from SSHRD to generate its host keys"
fi
if print -r -- "$MOUNTS" | grep -q 'md0 on /'; then
    die "device is in SSHRD; finalize requires a normal boot"
fi
ok "normal boot and root SSH"

# Reaching this point proves Dropbear completed key exchange. Check the durable
# reason it can do so, rather than accepting a one-off process state.
sh_dev '[ -s /private/var/dropbear/dropbear_rsa_host_key ] &&
        [ -s /private/var/dropbear/dropbear_ecdsa_host_key ] &&
        [ -s /private/var/dropbear/dropbear_dss_host_key ]' \
    || die "Dropbear connected but one or more per-device host keys are missing"
ok "per-device Dropbear host keys present on Data"

sh_dev "$RPATH; [ -x /var/jb/bin/sh ] && [ -x /var/jb/usr/bin/zsh ]" \
    || die "bootstrap shells are missing under /var/jb"
ok "bootstrap shells present"

bootstrap_complete() {
    sh_dev "$RPATH
        [ ! -e /var/jb/prep_bootstrap.sh ] &&
        [ -s /var/jb/etc/pwd.db ] &&
        [ -s /var/jb/etc/spwd.db ] &&
        grep -q '^root:.*:/var/jb/usr/bin/zsh$' /var/jb/etc/master.passwd &&
        grep -q '^mobile:.*:/var/jb/usr/bin/zsh$' /var/jb/etc/master.passwd" \
        >/dev/null 2>&1
}

say "Procursus bootstrap"
if bootstrap_complete; then
    skip "already finalized"
elif (( CHECK_ONLY )); then
    skip "PENDING: prep_bootstrap.sh has not completed"
    FINALIZE_INCOMPLETE=1
else
    sh_dev "$RPATH; [ -f /var/jb/prep_bootstrap.sh ]" \
        || die "bootstrap is incomplete but prep_bootstrap.sh is absent"

    # The script removes itself. Preserve a retry copy until its concrete
    # outputs have been checked, otherwise an internal failure could leave no
    # way to resume without extracting the entire bootstrap again.
    sh_dev "$RPATH
        cp /var/jb/prep_bootstrap.sh /var/jb/prep_bootstrap.sh.liter8-backup &&
        NO_PASSWORD_PROMPT=1 /var/jb/bin/sh /var/jb/prep_bootstrap.sh" \
        || die "prep_bootstrap.sh failed"

    if ! bootstrap_complete; then
        sh_dev "$RPATH
            [ ! -f /var/jb/prep_bootstrap.sh.liter8-backup ] ||
            cp /var/jb/prep_bootstrap.sh.liter8-backup /var/jb/prep_bootstrap.sh" \
            >/dev/null 2>&1 || true
        die "bootstrap outputs failed verification; retry script was restored"
    fi
    sh_dev "$RPATH; rm -f /var/jb/prep_bootstrap.sh.liter8-backup"
    ok "packages, passwd databases and root/mobile zsh shells configured"
fi

say "root shell profile"
if (( CHECK_ONLY )); then
    if ./setup_shell.sh --check; then
        ok "shell profile complete"
    else
        FINALIZE_INCOMPLETE=1
    fi
else
    ./setup_shell.sh
    ok "shell profile installed and parsed"
fi

say "one-time System application registration"
if sh_dev "$RPATH; [ -f '$REGISTRATION_MARKER' ]" >/dev/null 2>&1; then
    skip "already completed"
elif (( CHECK_ONLY )); then
    skip "PENDING: System applications have not been registered by Liter8"
    FINALIZE_INCOMPLETE=1
else
    # A rebuild is proven for the fresh beta-4 System-app population, but it is
    # unsafe after user/container bundles exist. Refuse instead of guessing.
    container_app=$(sh_dev "$RPATH
        find /var/containers/Bundle/Application -mindepth 2 -maxdepth 2 \
            -name '*.app' -print -quit 2>/dev/null" | tr -d '\r')
    [[ -z "$container_app" ]] \
        || die "container app already exists at $container_app; refusing one-time uicache -a"

    sh_dev "$RPATH
        /var/jb/usr/bin/uicache -a &&
        touch '$REGISTRATION_MARKER' && chmod 0644 '$REGISTRATION_MARKER'" \
        || die "System application registration failed"
    ok "System applications registered; completion marker written"
fi

say "automatic boot job"
boot_job=$(sh_dev "$RPATH
    log=/var/mobile/jbboot.log
    [ -s \"\$log\" ] &&
    grep -q 'persona 99 created' \"\$log\" &&
    grep -q 'icon read token ready' \"\$log\" &&
    [ -s /private/var/tmp/sbext.token ] &&
    /bin/ps aux | grep -q '[p]fwatch' && echo OK || echo INCOMPLETE" \
    2>/dev/null | tr -d '\r')
if [[ "$boot_job" == "OK" ]]; then
    ok "persona 99 and icon token recorded"
else
    skip "INCOMPLETE: jbboot did not record persona 99 and icon token"
    FINALIZE_INCOMPLETE=1
fi

if (( CHECK_ONLY )); then
    if (( ${FINALIZE_INCOMPLETE:-0} )); then
        printf '\n    post-boot finalization is incomplete; run without --check\n'
        exit 1
    fi
    printf '\n    post-boot finalization is complete\n'
    exit 0
fi

if (( ${FINALIZE_INCOMPLETE:-0} )); then
    die "persistent setup completed, but the automatic boot job is unhealthy"
fi

# Restart only after every persistent result has been verified. SpringBoard is
# not responsible for SSH, so the remote command should return normally while
# the UI restarts and rereads the rebuilt application database.
say "SpringBoard restart"
sh_dev "$RPATH; /var/jb/usr/bin/killall -9 SpringBoard" \
    || die "could not restart SpringBoard"
ok "SpringBoard restart requested"

printf '\n[+] Liter8 post-boot finalization complete\n'
