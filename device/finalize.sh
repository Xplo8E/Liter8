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

# Allow the device's ECDSA key and AES-CTR cipher without dropping SSH defaults.
SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=25
        -o HostKeyAlgorithms=+ecdsa-sha2-nistp521 -o Ciphers=+aes128-ctr
        -p "${LITER8_SSH_PORT:-2222}")
DEV="root@${LITER8_SSH_HOST:-localhost}"
PW=alpine
# ssh's own askpass hook rather than sshpass, which races this dropbear's
# password prompt and intermittently sends the wrong secret. The shim keeps the
# `-p <password> ssh|scp ...` call shape, so the call sites below are unchanged.
# Its header has the measurements.
SSHPASS=${0:A:h}/askpass-sshpass
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

RPATH='export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
REGISTRATION_MARKER=/var/jb/.liter8-system-apps-registered
ASSISTIVE_STAGING_DIR=/var/root

cleanup() {
    [[ -z "${IPROXY_PID:-}" ]] || kill "$IPROXY_PID" 2>/dev/null
    [[ -z "${ASSISTIVE_TMP:-}" ]] || rm -rf -- "$ASSISTIVE_TMP"
}
trap cleanup EXIT

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1" }
ok()   { printf '    [+] %s\n' "$1" }
skip() { printf '    [=] %s\n' "$1" }
die()  { printf '    [!] %s\n' "$1"; exit 1 }

sh_dev() { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "$@" }

assistive_probe_remote_plist() {
    # `path` is a special zsh array tied to PATH. A local named `path` would
    # dynamically replace PATH while sh_dev runs and break askpass-sshpass.
    local remote_path=$1
    local state
    if ! state=$(sh_dev "
        if [ -L $remote_path ]; then printf symlink
        elif [ -f $remote_path ]; then printf file
        elif [ -e $remote_path ]; then printf other
        else printf absent
        fi" \
        < /dev/null 2>/dev/null); then
        die "could not inspect $remote_path"
        return 1
    fi
    case "$state" in
        file) assistive_present=yes ;;
        absent) assistive_present=no ;;
        symlink)
            die "refusing symlink at $remote_path"
            return 1
            ;;
        other)
            die "refusing non-regular file at $remote_path"
            return 1
            ;;
        *)
            die "unexpected response while inspecting $remote_path"
            return 1
            ;;
    esac
}

assistive_push_plist_atomically() {
    local local_path=$1
    local remote_path=$2
    local remote_tmp suffix

    # The Preferences directory is mobile-writable, so a predictable sibling
    # path can be planted as a symlink before root opens it. mktemp creates the
    # staging file exclusively in root's home instead. /var/root and
    # /var/mobile are on the Data volume, so the final rename remains atomic.
    if ! remote_tmp=$(sh_dev "$RPATH; umask 077; mktemp $ASSISTIVE_STAGING_DIR/.liter8-accessibility.XXXXXX" \
        < /dev/null 2>/dev/null); then
        die "could not allocate staging for $remote_path"
        return 1
    fi
    remote_tmp=${remote_tmp//$'\r'/}
    case "$remote_tmp" in
        "$ASSISTIVE_STAGING_DIR"/.liter8-accessibility.*) ;;
        *)
            die "unexpected staging path for $remote_path"
            return 1
            ;;
    esac
    suffix=${remote_tmp#"$ASSISTIVE_STAGING_DIR"/.liter8-accessibility.}
    if [[ -z "$suffix" || "$suffix" == *[^A-Za-z0-9]* ]]; then
        die "unexpected staging path for $remote_path"
        return 1
    fi

    if ! sh_dev "cat > $remote_tmp" < "$local_path"; then
        sh_dev "rm -f $remote_tmp" < /dev/null >/dev/null 2>&1 || true
        die "could not stage $remote_path"
        return 1
    fi
    if ! sh_dev "chown mobile:mobile $remote_tmp && chmod 0644 $remote_tmp && mv -f $remote_tmp $remote_path" \
        < /dev/null; then
        sh_dev "rm -f $remote_tmp" < /dev/null >/dev/null 2>&1 || true
        die "could not install $remote_path"
        return 1
    fi
}

restart_springboard() {
    say "SpringBoard restart"
    sh_dev "$RPATH; /var/jb/usr/bin/killall -9 SpringBoard" \
        || die "could not restart SpringBoard"
    ok "SpringBoard restart requested"
}

[[ -x "$SSHPASS" ]] || die "missing $SSHPASS"
[[ -x setup_shell.sh ]] || die "setup_shell.sh is missing beside finalize.sh"

ENABLE_ASSISTIVE_TOUCH=${LITER8_ENABLE_ASSISTIVE_TOUCH:-}
[[ $ENABLE_ASSISTIVE_TOUCH == 0 || $ENABLE_ASSISTIVE_TOUCH == 1 ]] \
    || die "LITER8_ENABLE_ASSISTIVE_TOUCH must be 0 or 1; Liter8 sets it from the workflow profile"

say "normal-boot connection"

# Reuse an operator-owned forward when one exists. Otherwise Liter8 owns this
# temporary process and reliably stops it on every exit path.
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    [[ "$DEV" == root@localhost && "${LITER8_SSH_PORT:-2222}" == 2222 ]] \
        || die "cannot reach $DEV on port ${LITER8_SSH_PORT:-2222}"
    command -v iproxy >/dev/null 2>&1 \
        || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222:22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    sleep 2
fi

if ! MOUNTS=$(sh_dev '/sbin/mount' 2>/dev/null); then
    die "SSH handshake with $DEV failed; if Dropbear sends a banner but closes during key exchange, rerun fw provision from SSHRD to generate its host keys"
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

# ElleKit, installed as its own package on a booted device. This is what brings
# the hooking library, the six substrate compatibility names and, most
# importantly, the dpkg record: without a package declaring it, a tweak whose
# control says Depends: mobilesubstrate cannot be configured, and PreferenceLoader
# and most repo tweaks say exactly that.
#
# It is upstream's deb, unmodified and hash-pinned by fetch_payloads.sh, so
# ElleKit stays ElleKit's in dpkg: its control, its maintainer, its version.
#
# It cannot happen during provisioning. dpkg needs a booted bootstrap, and the
# compatibility names have to be symlinks, which the deb creates and the ramdisk
# has no known ln for. Provisioning installs only the injector and the two
# tweaks, which is enough for injection to work before this step ever runs.
#
# It overwrites the injector and safe-mode payload provisioning installed, with
# upstream's own unsigned copies. Measured: those load and run perfectly well, so
# the overwrite is harmless.
say "ElleKit package"
# Version and digest come from device/ellekit.pin, the same file fetch_payloads.sh
# checked on download.
. ./ellekit.pin
EK_DEB=payload/tweaks/ellekit.deb

# link:target, read out of the package itself rather than guessed:
#   ar x ellekit.deb && xz -dc data.tar.xz | tar tvf -
# lists all seven as symlinks with these targets. The pin carries a digest, so
# a version that changed them could not be installed without bumping the pin.
EK_LINKS=(
    "/var/jb/usr/lib/TweakLoader.dylib:/var/jb/usr/lib/ellekit/libinjector.dylib"
    "/var/jb/usr/lib/TweakInject.dylib:/var/jb/usr/lib/ellekit/libinjector.dylib"
    "/var/jb/usr/lib/libsubstrate.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/usr/lib/libhooker.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/usr/lib/libblackjack.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/Library/MobileSubstrate/DynamicLibraries:/var/jb/usr/lib/TweakInject"
)

# What has to be true after this step whether or not it installed anything.
# A finalize interrupted between dpkg registering the package and this running
# leaves the competing boot script in place and the links unchecked, and the
# retry must not accept that state just because dpkg says "installed".
#
# Resolution alone is not the check. `[ -e ]` passed for a link repointed at any
# other existing file: aim TweakLoader.dylib at MobileSafety.dylib and the old
# check reported ElleKit complete while lhook dlopens the wrong image and no
# TweakInject payload loads at all. The target is compared, and a symlink is
# required, so a regular file left where the package wants a link is caught too.
#
# readlink is read once and cached: an absent tool prints nothing, which would
# read as "every target is wrong" instead of "this was not checked".
EK_READLINK=""
# Read once and cached. Its own function because ek_readlink_complaint needs the
# same answer, and because this must not print to ek_broken_links' stdout: that
# stdout IS the broken-link list and the callers word-split it, so a warning
# emitted there became fake broken links.
ek_probe_readlink() {
    [[ -n "$EK_READLINK" ]] && return 0
    EK_READLINK=$(sh_dev "$RPATH; command -v readlink >/dev/null && echo yes || echo no" | tr -d '\r')
}

ek_broken_links() {
    local bad=() spec link want got
    ek_probe_readlink
    for spec in $EK_LINKS; do
        link=${spec%%:*}
        want=${spec#*:}
        if [[ "$EK_READLINK" != yes ]]; then
            sh_dev "$RPATH; [ -e '$link' ]" >/dev/null 2>&1 || bad+=("$link")
            continue
        fi
        got=$(sh_dev "$RPATH; [ -L '$link' ] && [ -e '$link' ] && readlink '$link'" | tr -d '\r')
        [[ "$got" == "$want" ]] || bad+=("$link")
    done
    print -r -- "${bad[@]}"
}
EK_BOOT_SCRIPT=/var/jb/etc/rc.d/ellekit-loader
EK_BOOT_DIVERSION="$EK_BOOT_SCRIPT.liter8-disabled"

ek_boot_script_present() {
    sh_dev "$RPATH; [ -e '$EK_BOOT_SCRIPT' ]" >/dev/null 2>&1
}

# Divert the package's boot script instead of deleting it.
#
# Deleting it was a one-time act, so any later `dpkg -i`, apt reinstall or
# upgrade put it straight back: measured on device, a reinstall of the pinned
# deb recreates ellekit-loader as a symlink to usr/libexec/ellekit/loader. A
# local diversion survives that, because dpkg writes the package's copy to the
# diverted name and leaves rc.d alone. Confirmed on device: with the diversion
# added, the same reinstall left rc.d holding only the diverted name.
#
# The reason is not that the script would otherwise run. Nothing on this
# bootstrap executes /var/jb/etc/rc.d: there is no runner in jbboot.sh, no
# ElleKit launchd job, and the postinst invokes the loader directly at install
# time, which is the assertion failure dpkg prints and carries on from. An
# earlier comment here claimed it runs at every boot, which is wrong. What the
# diversion buys is that the removal stays done across package operations, that
# `dpkg -V` becomes a clean signal rather than permanently reporting one missing
# file, and that this is still correct if a future bootstrap does add a runner.
ek_divert_boot_script() {
    if sh_dev "$RPATH; dpkg-divert --list '$EK_BOOT_SCRIPT'" 2>/dev/null \
        | grep -q "$EK_BOOT_DIVERSION"; then
        return 0
    fi
    sh_dev "$RPATH; command -v dpkg-divert >/dev/null" >/dev/null 2>&1 || {
        # No dpkg-divert: fall back to the old removal rather than leaving the
        # competing script in place, and say that it will not stay removed.
        sh_dev "$RPATH; rm -f '$EK_BOOT_SCRIPT'" >/dev/null
        printf '    [!] no dpkg-divert on the device; removed the boot script without a diversion\n'
        printf '    [!] a package reinstall will put it back\n'
        return 0
    }
    sh_dev "$RPATH; dpkg-divert --divert '$EK_BOOT_DIVERSION' --rename --add '$EK_BOOT_SCRIPT'" \
        >/dev/null 2>&1 \
        || die "could not divert $EK_BOOT_SCRIPT"
    # --rename moves an existing file; nothing to move is equally fine, but the
    # path itself must be clear either way before this is called a success.
    sh_dev "$RPATH; rm -f '$EK_BOOT_SCRIPT'" >/dev/null
    ek_boot_script_present && die "$EK_BOOT_SCRIPT is still present after diverting it"
    return 0
}

# What `dpkg -V` says about the package's own files, one line per complaint.
#
# The link checks above verify where each name points, not what is at the other
# end, so a truncated or replaced libinjector.dylib passed every one of them
# while TweakLoader.dylib resolved to an unloadable image. This asks dpkg to
# compare its recorded md5sums instead, which covers every file the package
# owns rather than the handful this script would otherwise pick.
#
# Judged by output, not exit status: measured on device, `dpkg -V` exits 0 even
# while reporting a missing file. A device diverted by this script is expected
# to be silent; one finalized before the diversion existed reports exactly the
# boot script as missing, which is that older intended state and not damage.
# `|| true` because no complaints is the good case and the last grep exits 1 on
# empty output, which under `set -e` aborted finalize at the assignment without
# printing anything at all.
ek_package_complaints() {
    sh_dev "$RPATH; dpkg -V ellekit 2>&1" | tr -d '\r' \
        | grep -v "^missing[[:space:]]*$EK_BOOT_SCRIPT\$" \
        | grep -v '^[[:space:]]*$' || true
    ek_mode_complaints
    ek_mode_table_drift
    ek_readlink_complaint
    ek_dir_complaints
}

# The directories the files live in, which neither dpkg -V nor the mode table
# looks at. Measured on device with every content, link and mode check passing:
# /var/jb/usr/lib/TweakInject at mode 0777, from a third-party tweak's package
# shipping Library/MobileSubstrate/DynamicLibraries (a symlink to it here) as a
# directory entry. lhook loads what is there into root processes.
ek_dir_complaints() {
    sh_dev "$RPATH"'
for d in /var/jb/usr/lib /var/jb/usr/lib/TweakInject /var/jb/usr/lib/ellekit /var/jb/usr/share/doc/ellekit; do
    # -L first: -d follows the link, so a redirected TweakInject would pass.
    if [ -L "$d" ]; then echo "unsafe directory $d is a symlink"; continue; fi
    [ -d "$d" ] || { echo "unsafe directory $d is absent"; continue; }
    set -- $(ls -ldn "$d")
    case "${1%[.+]}" in
        ?????w*)    echo "unsafe directory $d is group writable ($1)" ;;
        ????????w*) echo "unsafe directory $d is other writable ($1)" ;;
    esac
    [ "$3" = 0 ] || echo "unsafe directory $d is owned by uid $3"
done' < /dev/null | tr -d '\r'
}

# Modes and owners of the package's regular files, which dpkg -V does not look
# at: its only functional check is the stored MD5 digest, so `chmod 000` on
# ellekit/libinjector.dylib left every content and link check passing while no
# non-root process could load the injector. Measured on device before this
# existed: finalize --check reported complete and exited 0.
#
# The expected modes come out of the pinned archive rather than a list written
# here, so they cannot drift from the package. Regular files only: dpkg owns
# the symlinks' targets and ek_broken_links already covers the links.
# Expectations come from ellekit.pin, not from the archive in payload/.
#
# Reading them from the deb meant no deb, no checks: `fw finalize` does not
# fetch payloads, so on a fresh work directory the whole function returned
# early and said nothing was wrong. Measured on device: the loader at mode 000
# with no cached deb was reported complete, which is the common case rather
# than an edge one. It also meant device commands were built out of member
# names taken from a downloaded archive.
#
# Not `path` for the loop variable: in zsh that name is tied to $PATH, so
# declaring it local emptied PATH inside the function and ar and xz stopped
# resolving.
ek_mode_complaints() {
    local entry want member got
    for entry in ${(f)ELLEKIT_FILE_MODES}; do
        [[ -n "$entry" ]] || continue
        want=${entry%%:*}
        member=${entry#*:}
        got=$(sh_dev "$RPATH; ls -ln ${(q)member} 2>/dev/null" < /dev/null | tr -d '\r')
        [[ -n "$got" ]] || { print -r -- "absent $member"; continue; }
        [[ "${${got%% *}%[.+]}" == "$want" && "${${(z)got}[3]}" == 0 ]] \
            || print -r -- "mode/owner $member is ${${(z)got}[1]} uid ${${(z)got}[3]}, expected $want uid 0"
    done
}

# Whenever the archive is here, the table has to agree with it, so bumping the
# pin cannot leave the table describing the version before it.
ek_mode_table_drift() {
    [[ -f "$EK_DEB" ]] || return 0
    local from_archive from_pin
    from_archive=$(tar tvf <(xz -dc < <(ar p "$EK_DEB" data.tar.xz)) 2>/dev/null \
        | sed -n 's|^\(-[rwxsStT-]*\) .* \./\(.*\)$|\1:/\2|p' | sort)
    from_pin=$(print -rl -- ${(f)ELLEKIT_FILE_MODES} | grep -v '^[[:space:]]*$' | sort)
    [[ "$from_archive" == "$from_pin" ]] \
        || print -r -- "ellekit.pin's ELLEKIT_FILE_MODES does not match $EK_DEB"
}

# An unverifiable link is not a verified one. Without readlink the fallback can
# only ask whether each name resolves, which accepts a loader repointed at any
# other existing file, so the absence of the verifier is itself a reason to
# call finalization incomplete rather than a warning to print and carry on.
ek_readlink_complaint() {
    ek_probe_readlink
    [[ "$EK_READLINK" == yes ]] \
        || print -r -- "link targets unverified: no readlink on the device PATH"
}

# Ask for the status, not the version. A removed package keeps its version in
# dpkg's database while its state is "deinstall ok config-files" and every one
# of its files is gone, so a non-empty version means "dpkg has heard of it",
# not "it is installed".
EK_STATE=$(sh_dev "$RPATH; dpkg-query -W -f='\${Version} \${Status}' ellekit 2>/dev/null" | tr -d '\r')
EK_INSTALLED=0
[[ "$EK_STATE" == *"install ok installed"* ]] && EK_INSTALLED=1

if (( EK_INSTALLED )) && [[ "${EK_STATE%% *}" != "$ELLEKIT_VER" ]]; then
    skip "ellekit ${EK_STATE%% *} is installed, but this tree pins $ELLEKIT_VER"
    FINALIZE_INCOMPLETE=1
elif (( EK_INSTALLED )); then
    EK_BAD=(${=$(ek_broken_links)})
    EK_COMPLAINTS=(${(f)"$(ek_package_complaints)"})
    EK_COMPLAINTS=(${EK_COMPLAINTS:#})
    if ek_boot_script_present || (( ${#EK_BAD} )) || (( ${#EK_COMPLAINTS} )); then
        if (( CHECK_ONLY )); then
            printf '    [=] ellekit %s installed but incomplete: %s\n' "$ELLEKIT_VER" \
                "$(ek_boot_script_present && print -n 'boot script present; ')${EK_BAD:+broken links: ${${(@)EK_BAD:t}[*]}; }${EK_COMPLAINTS:+${EK_COMPLAINTS[*]}}"
            FINALIZE_INCOMPLETE=1
        else
            ek_divert_boot_script
            EK_BAD=(${=$(ek_broken_links)})
            EK_COMPLAINTS=(${(f)"$(ek_package_complaints)"})
            EK_COMPLAINTS=(${EK_COMPLAINTS:#})
            if (( ${#EK_BAD} )) || (( ${#EK_COMPLAINTS} )); then
                # The links and the files behind them are the package's own, so
                # this step cannot repair them without guessing. Say what is
                # wrong and let the rest of finalize run: nothing after this
                # depends on them.
                (( ${#EK_BAD} )) && printf '    [!] ellekit is installed but these do not resolve: %s\n' \
                    "${${(@)EK_BAD:t}[*]}"
                (( ${#EK_COMPLAINTS} )) && printf '    [!] the installed package is not as expected: %s\n' \
                    "${EK_COMPLAINTS[*]}"
                printf '    [!] reinstall it: dpkg -i /var/root/ellekit.deb on the device\n'
                FINALIZE_INCOMPLETE=1
            else
                ok "ellekit $ELLEKIT_VER already installed; boot script diverted, links and package files checked"
            fi
        fi
    else
        skip "ellekit $ELLEKIT_VER already installed and complete"
    fi
elif [[ ! -f "$EK_DEB" ]]; then
    # An absent archive is two different states, and treating both as incomplete
    # made the optional ElleKit download mandatory one stage after provisioning
    # stopped requiring it: with only ellekit.space blocked, fetch and provision
    # both skip the tweak set by design, and `fw finalize` then still exited
    # nonzero with every required bootstrap and boot-job check passing.
    #
    # The loader on the device is what separates them. Present means
    # provisioning installed the tweak stack and the package is still owed:
    # without its dpkg record a tweak declaring Depends: mobilesubstrate cannot
    # be configured. Absent means there is no tweak stack to finish.
    if sh_dev "$RPATH; [ -e /var/jb/usr/lib/TweakLoader.dylib ]" >/dev/null 2>&1; then
        skip "the loader is installed but $EK_DEB is absent; run ./fetch_payloads.sh tweaks"
        skip "until then a tweak needing Depends: mobilesubstrate cannot configure"
        FINALIZE_INCOMPLETE=1
    else
        skip "no tweak stack provisioned and no $EK_DEB; tweak support is off, not unfinished"
    fi
elif (( CHECK_ONLY )); then
    skip "ellekit is not installed; this step would install $EK_DEB"
    FINALIZE_INCOMPLETE=1
else
    # Re-verify the pinned digest here, not only at fetch time. finalize is a
    # separate action that does not rerun the fetch, and this file has sat in a
    # mutable work directory since. dpkg runs maintainer scripts as root, so the
    # thing being handed to it gets checked immediately before the handover.
    EK_GOT_SHA=$(shasum -a 256 "$EK_DEB" | awk '{print $1}')
    [[ "$EK_GOT_SHA" == "$ELLEKIT_SHA" ]] \
        || die "$EK_DEB does not match the pinned digest; refusing to install. got $EK_GOT_SHA"
    # Unlinked first, for the reason the tweak staging paths are: tee follows a
    # symlink already sitting there and would overwrite its target as root, and
    # the readback below follows the same link so the digest check would agree.
    sh_dev "$RPATH; rm -f /var/root/ellekit.deb" >/dev/null \
        || die "could not clear the staging path on the device"
    sh_dev "$RPATH; tee /var/root/ellekit.deb >/dev/null" < "$EK_DEB" \
        || die "could not copy $EK_DEB to the device"
    # Hash the readback here, not on the device: shasum is not part of the
    # on-device tool set, and a missing tool returns empty rather than failing.
    EK_LANDED=$(sh_dev "$RPATH; cat /var/root/ellekit.deb" | shasum -a 256 | awk '{print $1}')
    [[ "$EK_LANDED" == "$ELLEKIT_SHA" ]] \
        || die "the copy on the device does not match the pinned digest: ${EK_LANDED:-nothing}"
    # Its postinst runs ElleKit's own loader, which asserts and dies here
    # because lhook already owns launchd. dpkg carries on and the install is
    # fine, so the exit status is not the thing to judge this by: ask dpkg.
    sh_dev "$RPATH; dpkg -i /var/root/ellekit.deb 2>&1 | tail -4" | sed 's/^/        /'
    EK_STATE=$(sh_dev "$RPATH; dpkg-query -W -f='\${Version} \${Status}' ellekit 2>/dev/null" | tr -d '\r')
    [[ "$EK_STATE" == *"install ok installed"* ]] \
        || die "ellekit did not register with dpkg: ${EK_STATE:-nothing}"
    [[ "${EK_STATE%% *}" == "$ELLEKIT_VER" ]] \
        || die "dpkg registered ellekit ${EK_STATE%% *}, expected $ELLEKIT_VER"
    # The package's own loader has no business competing with lhook, so its
    # boot script is diverted rather than deleted. See ek_divert_boot_script for
    # what that does and, more to the point, what it does not: nothing on this
    # bootstrap runs rc.d, so this is about the removal staying done across
    # package operations rather than about stopping a boot-time loader.
    ek_divert_boot_script
    EK_BAD=(${=$(ek_broken_links)})
    (( ${#EK_BAD} == 0 )) \
        || die "these do not resolve after installing ellekit: ${${(@)EK_BAD:t}[*]}"
    EK_COMPLAINTS=(${(f)"$(ek_package_complaints)"})
    EK_COMPLAINTS=(${EK_COMPLAINTS:#})
    (( ${#EK_COMPLAINTS} == 0 )) \
        || die "what was just installed is not as expected: ${EK_COMPLAINTS[*]}"
    ok "ellekit $ELLEKIT_VER installed, digest verified; all ${#EK_LINKS} names resolve; package files verified; boot script diverted"
fi

# Theos signs tweaks with ldid's default flags=0x0, and SpringBoard once silently
# refused those on this device (tweaksign/tweaksign.sh has the measurement). A
# later test on the same build loaded a plain Theos flags=0x0 build without it, and
# the cause of the refusal is unknown, so this stays as a safety net. dpkg runs the
# re-signer after every run that changes packages, so repo tweaks load without
# rebuilding; this installs it and runs it once for what is already there.
#
# Installed as liter8-tweaksign with no extension: dpkg ignores any file in
# dpkg.cfg.d whose name contains a dot, which is also why a .new staging copy
# there is never read.
say "tweak signing hook"
TS_SCRIPT=/var/jb/usr/libexec/liter8/tweaksign
TS_CFG=/var/jb/etc/dpkg/dpkg.cfg.d/liter8-tweaksign
TS_SCRIPT_SHA=$(shasum -a 256 tweaksign/tweaksign.sh | cut -d' ' -f1)
TS_CFG_SHA=$(shasum -a 256 tweaksign/liter8-tweaksign.cfg | cut -d' ' -f1)

# Content, and the owner and exact mode: dpkg runs the script as root on every
# install, and a third-party package has already loosened a directory's mode on
# this device, so a correct hash in a file another account can rewrite is not an
# installed hook. Modes come from ls -ln, the reliable reader here; a trailing
# ACL marker is dropped.
ts_installed() {
    local got
    got=$(sh_dev "$RPATH
        [ -f $TS_SCRIPT ] && [ ! -L $TS_SCRIPT ] && [ -f $TS_CFG ] && [ ! -L $TS_CFG ] || exit 1
        set -- \$(ls -ln $TS_SCRIPT); [ \"\${1%[.+]}\" = -rwxr-xr-x ] && [ \"\$3\" = 0 ] || exit 1
        set -- \$(ls -ln $TS_CFG); [ \"\${1%[.+]}\" = -rw-r--r-- ] && [ \"\$3\" = 0 ] || exit 1
        sha256sum $TS_SCRIPT $TS_CFG" < /dev/null 2>/dev/null) || return 1
    [[ "$got" == *"$TS_SCRIPT_SHA"* && "$got" == *"$TS_CFG_SHA"* ]]
}

# Names of TweakInject dylibs that are not ad-hoc, decided by the script in this
# tree rather than a copy of its rule, and without installing anything. The
# status is the script's, not a pipe's: --list exits 2 when ldid is missing, and
# an empty list from a failed run would read as "all signed".
ts_pending() {
    local out
    out=$(sh_dev "$RPATH; /var/jb/bin/sh -s -- --list" < tweaksign/tweaksign.sh) || return 1
    print -r -- "${out//$'\r'/}"
}

if ts_installed; then
    skip "re-sign hook already installed"
elif (( CHECK_ONLY )); then
    skip "PENDING: the dpkg re-sign hook is missing, differs from this tree, or is not root-owned 0755/0644"
    FINALIZE_INCOMPLETE=1
else
    sh_dev "$RPATH; mkdir -p ${TS_SCRIPT:h} && rm -f $TS_SCRIPT.new &&
        cat > $TS_SCRIPT.new && chmod 0755 $TS_SCRIPT.new && mv -f $TS_SCRIPT.new $TS_SCRIPT" \
        < tweaksign/tweaksign.sh || die "could not install $TS_SCRIPT"
    sh_dev "$RPATH; mkdir -p ${TS_CFG:h} && rm -f $TS_CFG.new &&
        cat > $TS_CFG.new && chmod 0644 $TS_CFG.new && mv -f $TS_CFG.new $TS_CFG" \
        < tweaksign/liter8-tweaksign.cfg || die "could not install $TS_CFG"
    ts_installed || die "the dpkg re-sign hook does not read back as installed"
    ok "dpkg re-signs TweakInject dylibs ad-hoc after every package change"
fi

# The bundled bootstrap has no ldid; it arrives with apt, for instance as a
# Sileo dependency. Its absence is not a finalize failure: tweaks are optional,
# and the dpkg run that installs ldid triggers the hook, which signs whatever is
# waiting. Asked as a yes/no so a dropped connection is not read as "absent".
TS_LDID=$(sh_dev "$RPATH; command -v ldid >/dev/null && echo HAVE_LDID || echo NO_LDID" \
    < /dev/null 2>/dev/null) || true
if [[ "$TS_LDID" == *NO_LDID* ]]; then
    skip "ldid is not installed yet; the hook re-signs tweaks once apt installs it (apt install ldid)"
elif [[ "$TS_LDID" != *HAVE_LDID* ]]; then
    (( CHECK_ONLY )) || die "could not ask the device whether ldid is installed"
    skip "INCOMPLETE: could not ask the device whether ldid is installed"
    FINALIZE_INCOMPLETE=1
elif ! TS_LIST=$(ts_pending); then
    (( CHECK_ONLY )) || die "could not check TweakInject signatures"
    skip "INCOMPLETE: could not check TweakInject signatures"
    FINALIZE_INCOMPLETE=1
else
    TS_PENDING=(${(f)TS_LIST})
    TS_PENDING=(${TS_PENDING:#})
    if (( ${#TS_PENDING} == 0 )); then
        ok "every TweakInject dylib is ad-hoc signed"
    elif (( CHECK_ONLY )); then
        skip "INCOMPLETE: not ad-hoc, so SpringBoard will not load them: ${TS_PENDING[*]}"
        FINALIZE_INCOMPLETE=1
    else
        sh_dev "$RPATH; $TS_SCRIPT" < /dev/null | sed 's/^/        /'
        TS_LIST=$(ts_pending) || die "could not re-check TweakInject signatures"
        TS_PENDING=(${(f)TS_LIST})
        TS_PENDING=(${TS_PENDING:#})
        (( ${#TS_PENDING} == 0 )) \
            || die "these TweakInject dylibs could not be re-signed: ${TS_PENDING[*]}"
        ok "re-signed the TweakInject dylibs that were not ad-hoc"
    fi
fi

# Injection is on by default: at every boot l8boot, run by the com.jbboot job,
# enables it once SpringBoard is up and resprings once, provided this file
# exists, root-owned and not group or other writable (the predicate every
# liter8 marker uses). lhookctl still turns it off or on for the current boot.
# Removing the file stops the boot-time enable; that is a choice, not a fault,
# so --check reports it rather than failing, and re-running finalize puts it back.
say "injection auto-enable"
AUTO_MARKER=/var/jb/.lhook_autoenable
auto_state=$(sh_dev "$RPATH
    [ -x /usr/local/bin/l8boot ] || echo NO_HELPER
    if [ -L $AUTO_MARKER ]; then echo BAD
    elif [ ! -e $AUTO_MARKER ]; then echo ABSENT
    else
        set -- \$(ls -ln $AUTO_MARKER); m=\${1%[.+]}
        case \"\$m\" in -*) ;; *) echo BAD; exit 0 ;; esac
        case \"\$m\" in ?????w*|????????w*) echo BAD; exit 0 ;; esac
        [ \"\$3\" = 0 ] && echo OK || echo BAD
    fi" < /dev/null 2>/dev/null) || true

if [[ "$auto_state" == *NO_HELPER* ]]; then
    skip "INCOMPLETE: /usr/local/bin/l8boot is missing; re-provision from SSHRD so the boot job can enable injection and set up the SSH PATH"
    FINALIZE_INCOMPLETE=1
fi
if [[ "$auto_state" == *OK* ]]; then
    ok "on: injection is enabled at every boot once SpringBoard is up"
elif [[ "$auto_state" != *ABSENT* && "$auto_state" != *BAD* ]]; then
    (( CHECK_ONLY )) || die "could not read $AUTO_MARKER"
    skip "INCOMPLETE: could not read $AUTO_MARKER"
    FINALIZE_INCOMPLETE=1
elif (( CHECK_ONLY )) && [[ "$auto_state" == *ABSENT* ]]; then
    skip "off: $AUTO_MARKER is absent, so injection needs lhookctl enable each boot"
elif (( CHECK_ONLY )); then
    skip "INCOMPLETE: $AUTO_MARKER is not a root-owned file that only root can write; l8boot ignores it"
    FINALIZE_INCOMPLETE=1
else
    sh_dev "$RPATH; rm -f $AUTO_MARKER && : > $AUTO_MARKER && chmod 0644 $AUTO_MARKER" < /dev/null \
        || die "could not create $AUTO_MARKER"
    ok "on: created $AUTO_MARKER; injection is enabled at every boot once SpringBoard is up"
    # l8boot checked the marker before it existed, so enable this boot here;
    # the SpringBoard restart below then loads tweaks without a reboot.
    if sh_dev "$RPATH; /var/jb/usr/bin/lhookctl enable" < /dev/null >/dev/null 2>&1; then
        ok "injection enabled for this boot"
    else
        skip "could not enable injection for this boot; run lhookctl enable or reboot"
    fi
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
# Report each prerequisite independently. The old all-or-nothing expression
# blamed the token and persona when only the persistent wallpaper watcher was
# absent, which hid the actual RC failure during first device validation.
boot_job=$(sh_dev "$RPATH
    log=/var/mobile/jbboot.log
    [ -s \"\$log\" ] && grep -q 'persona 99 created' \"\$log\" && echo PERSONA_OK
    [ -s \"\$log\" ] && grep -q 'icon read token ready' \"\$log\" &&
        [ -s /private/var/tmp/sbext.token ] && echo TOKEN_OK
    /bin/ps aux | grep -q '[p]fwatch' && echo WATCHER_OK" \
    2>/dev/null | tr -d '\r')
if print -r -- "$boot_job" | grep -q '^PERSONA_OK$'; then
    ok "persona 99 recorded"
else
    skip "INCOMPLETE: jbboot did not create persona 99"
    FINALIZE_INCOMPLETE=1
fi
if print -r -- "$boot_job" | grep -q '^TOKEN_OK$'; then
    ok "icon read token recorded"
else
    skip "INCOMPLETE: jbboot did not create the icon read token"
    FINALIZE_INCOMPLETE=1
fi
if print -r -- "$boot_job" | grep -q '^WATCHER_OK$'; then
    ok "PosterBoard repair watcher running"
else
    skip "INCOMPLETE: PosterBoard repair watcher is not running"
    FINALIZE_INCOMPLETE=1
fi

say "AssistiveTouch"
# The d79ap Home button is a haptic sensor behind the SEP, and this boot runs
# without the SEP: the button reports nothing, and a Touch ID board has no
# gesture navigation, so Setup cannot be dismissed without AssistiveTouch.
# The flag lives in the mobile user's Accessibility preferences, and cfprefsd
# caches that file, so the edit is pulled to the Mac, merged with plistlib and
# pushed back, followed by a cfprefsd and assistivetouchd restart. The
# SpringBoard restart below then surfaces the button. Removing the keys turns
# AssistiveTouch off again; that is a choice, so --check reports it rather
# than failing, and re-running finalize puts them back.
ASSISTIVE_PLIST=/var/mobile/Library/Preferences/com.apple.Accessibility.plist
ASSISTIVE_TOUCH_NEEDS_RESTART=0
if (( ! ENABLE_ASSISTIVE_TOUCH )); then
    skip "AssistiveTouch is not required for this board"
else
    ASSISTIVE_TMP=$(mktemp -d) || die "could not create a local AssistiveTouch staging directory"
    ASSISTIVE_LOCAL="$ASSISTIVE_TMP/accessibility.plist"
    # A fresh erase install may not have the file yet; an existing one must
    # parse, or the state is unexpected and the run stops instead of guessing.
    assistive_probe_remote_plist "$ASSISTIVE_PLIST"
    allow_empty=0
    if [[ "$assistive_present" == yes ]]; then
        sh_dev "[ ! -L $ASSISTIVE_PLIST ] && [ -f $ASSISTIVE_PLIST ] && cat $ASSISTIVE_PLIST" \
            > "$ASSISTIVE_LOCAL" 2>/dev/null \
            || die "could not pull $ASSISTIVE_PLIST"
    else
        : > "$ASSISTIVE_LOCAL"
        allow_empty=1
    fi
    if (( CHECK_ONLY )); then
        state=$(python3 - "$ASSISTIVE_LOCAL" <<'PY'
import plistlib, sys
try:
    with open(sys.argv[1], "rb") as fh:
        data = plistlib.load(fh)
    enabled = data.get("AssistiveTouchEnabledBySystem") is True and data.get("AssistiveTouchEnabled") is True
except Exception:
    enabled = None
print("ON" if enabled else "OFF")
PY
)
        rm -rf "$ASSISTIVE_TMP"
        ASSISTIVE_TMP=
        if [[ "$state" == ON ]]; then
            ok "on: AssistiveTouch is enabled for the mobile user"
        else
            skip "INCOMPLETE: AssistiveTouch is not enabled; run without --check"
            FINALIZE_INCOMPLETE=1
        fi
    else
        if ! python3 - "$ASSISTIVE_LOCAL" "$allow_empty" <<'PY'
import os, plistlib, sys
path, allow_empty = sys.argv[1], sys.argv[2] == "1"
try:
    with open(path, "rb") as fh:
        data = plistlib.load(fh)
except Exception as error:
    if allow_empty and os.path.getsize(path) == 0:
        data = {}
    else:
        raise SystemExit(f"unparsable Accessibility plist: {error}")
data["AssistiveTouchEnabledBySystem"] = True
data["AssistiveTouchEnabled"] = True
with open(path, "wb") as fh:
    plistlib.dump(data, fh)
with open(path, "rb") as fh:
    check = plistlib.load(fh)
assert check["AssistiveTouchEnabledBySystem"] is True
assert check["AssistiveTouchEnabled"] is True
PY
        then
            die "could not merge the AssistiveTouch keys into the pulled plist"
        fi
        assistive_push_plist_atomically "$ASSISTIVE_LOCAL" "$ASSISTIVE_PLIST"
        sh_dev "$RPATH; /var/jb/usr/bin/killall cfprefsd 2>/dev/null; /var/jb/usr/bin/killall assistivetouchd 2>/dev/null; :" \
            < /dev/null >/dev/null 2>&1
        ASSISTIVE_TOUCH_NEEDS_RESTART=1
        ok "on: AssistiveTouch enabled for the mobile user"
        rm -rf "$ASSISTIVE_TMP"
        ASSISTIVE_TMP=
    fi
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
    # d79ap cannot navigate Setup without the overlay. Persistent work above
    # may still be incomplete, but a successfully installed Accessibility
    # preference must be surfaced before returning control to the operator.
    if (( ASSISTIVE_TOUCH_NEEDS_RESTART )); then
        restart_springboard
        ASSISTIVE_TOUCH_NEEDS_RESTART=0
    fi
    die "persistent setup completed, but the automatic boot job is unhealthy"
fi

# Restart only after every persistent result has been verified. SpringBoard is
# not responsible for SSH, so the remote command should return normally while
# the UI restarts and rereads the rebuilt application database.
restart_springboard

printf '\n[+] Liter8 post-boot finalization complete\n'
