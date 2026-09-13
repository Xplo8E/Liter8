#!/bin/zsh
#
# Make the SSH shell usable. RUN FROM THE MAC, with the device on a NORMAL BOOT.
#
#   ./setup_shell.sh            install
#   ./setup_shell.sh --check    compare device against repo, change nothing
#
# Three separate annoyances, all fixed here:
#
#   1. dropbear complains twice per login that /var/log/lastlog does not exist.
#   2. The prompt is a bare `-sh-3.2#`, because /etc/passwd gives root /bin/sh
#      and sh has no prompt configured.
#   3. zsh has to be started by hand, and then has no prompt either.
#
# The proper fix for 2 is changing root's login shell in /etc/passwd, but that
# file is on the read-only System volume and would need an SSHRD trip. Everything
# here lives on the Data volume instead: /var/root and /var/log are both writable
# on a normal boot, and both survive reboots. Only an erase restore wipes them,
# which is why this is a script rather than something you do by hand.
#
# Deliberately NOT part of sshrd_provision.sh. That script exists for things that
# require the System volume mounted read-write, and refuses to run on a normal
# boot for that reason. None of this needs SSHRD, so folding it in there would
# force a DFU cycle for a cosmetic change.
#
# Requires the bootstrap, since zsh comes from it. Run install_bootstrap.sh first.
# The Liter8 command owns its temporary iproxy just like the SSHRD workflows;
# callers should not need to keep a separate forwarding terminal open.

set -e
cd "${0:A:h}"

SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=25 -p 2222)
DEV=root@localhost
PW=alpine
SSHPASS=../tools/sshpass

CHECK_ONLY=0
[[ "$1" == "--check" ]] && CHECK_ONLY=1

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1" }
ok()   { printf '    [+] %s\n' "$1" }
skip() { printf '    [=] %s\n' "$1" }
die()  { printf '    [!] %s\n' "$1"; exit 1 }

sh_dev() { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "$@" }
put()    { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "cat > $2" < "$1" }

# Remote PATH. The System volume ships about five commands, so anything beyond
# the shell builtins has to come from the bootstrap.
RPATH='export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'

[[ -f shell/profile && -f shell/zshrc ]] || die "shell/profile and shell/zshrc must be next to this script"

say "checking the device"

# Try an existing forward first, then create a temporary one when Liter8 owns
# the session. The trap closes only the process started here.
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    command -v iproxy >/dev/null 2>&1 || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222 22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap 'kill "$IPROXY_PID" 2>/dev/null' EXIT
    sleep 2
fi

# Refuse SSHRD. There /var/root is the ramdisk's own root, not the device's, so
# the files would be written somewhere that vanishes on reboot. This is the
# mirror image of the guard in sshrd_provision.sh.
if ! MOUNTS=$(sh_dev '/sbin/mount' 2>/dev/null); then
    die "cannot reach normal-boot SSH on port 2222; the device may still be booting"
fi
if print -r -- "$MOUNTS" | grep -q 'md0 on /'; then
    die "device is in SSHRD. This one runs on a NORMAL boot; /var/root there is the ramdisk."
fi
ok "normal boot"

if ! ZSH_STATE=$(sh_dev "$RPATH; [ -x /var/jb/bin/zsh ] && echo present || echo absent" 2>/dev/null); then
    die "normal-boot SSH disconnected while checking the bootstrap"
fi
[[ "$ZSH_STATE" == "present" ]] \
    || die "zsh not found at /var/jb/bin/zsh. Run ./install_bootstrap.sh first."
ok "zsh present"

# ---------------------------------------------------------------- compare
say "comparing"
FAIL=0
for f in profile zshrc; do
    want=$(shasum -a 256 "shell/$f" | awk '{print $1}')
    got=$(sh_dev "$RPATH; sha256sum /var/root/.$f 2>/dev/null" | awk '{print $1}')
    if [[ "$want" == "$got" ]]; then
        ok ".$f up to date"
    elif [[ -z "$got" ]]; then
        skip ".$f absent on device"
        FAIL=1
    else
        skip ".$f differs from repo"
        FAIL=1
    fi
done

if sh_dev "$RPATH; [ -f /var/log/lastlog ]" 2>/dev/null; then
    ok "lastlog present"
else
    skip "lastlog absent, dropbear will warn on every login"
    FAIL=1
fi

if (( CHECK_ONLY )); then
    if (( FAIL )); then
        printf '\n    run without --check to fix\n'
        exit 1
    fi
    printf '\n    nothing to do\n'
    exit 0
fi

# ---------------------------------------------------------------- install
say "installing"

# Keep one copy of whatever was there first, and only the first time, so
# re-running this never overwrites a real original with our own file.
sh_dev "$RPATH
for f in .profile .zprofile .zshrc; do
    if [ -f /var/root/\$f ] && [ ! -f /var/root/\$f.orig ]; then
        cp /var/root/\$f /var/root/\$f.orig || exit 1
    fi
done"
ok "originals preserved as .orig (first run only)"

put shell/profile /var/root/.profile
put shell/zshrc   /var/root/.zshrc
ok "profile and zshrc written"

# .zprofile only needs PATH: .zshrc does the rest, and is what interactive
# shells read. Written inline rather than shipped, since it is one line.
sh_dev "printf '%s\n' '$RPATH' > /var/root/.zprofile"
ok "zprofile written"

sh_dev "$RPATH; : > /var/log/lastlog && chmod 644 /var/log/lastlog"
ok "lastlog created"

# ---------------------------------------------------------------- verify
say "verifying"
for f in profile zshrc; do
    want=$(shasum -a 256 "shell/$f" | awk '{print $1}')
    got=$(sh_dev "$RPATH; sha256sum /var/root/.$f" | awk '{print $1}')
    [[ "$want" == "$got" ]] || die ".$f did not land intact"
    ok ".$f matches repo"
done

# A syntax error in either file would break every future login, so both are
# parsed on the device before we call this done.
sh_dev '/bin/sh -n /var/root/.profile'      || die ".profile has a syntax error, reverting is advised"
sh_dev '/var/jb/bin/zsh -n /var/root/.zshrc' || die ".zshrc has a syntax error"
ok "both parse on the device"

printf '\n    Reconnect to pick it up. Expect:\n'
printf '        <device-name>:~ #            normal boot\n'
printf '        [SSHRD] <device-name>:~ #    SSH ramdisk\n\n'
