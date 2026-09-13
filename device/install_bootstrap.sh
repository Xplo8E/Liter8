#!/bin/zsh
#
# Extract upstream's Procursus rootless bootstrap into the device's /var/jb.
# RUN FROM THE MAC, with the device booted into SSHRD.
#
#   ./install_bootstrap.sh            install
#   ./install_bootstrap.sh --check    report current state, change nothing
# Reuses `iproxy 2222 22` when running, or starts its own fallback.
#
# Source: bootstrap_1900.tar.zst here, byte-identical to ../work-27.0b2/bootstrap_1900.tar.zst
#   20.7 MB compressed, 103 MB extracted, 6529 entries, all uid 0.
#   1151 symlinks and 8 setuid binaries (sudo, su, passwd, login, chpass, newgrp,
#   quota, shshd).
#
# Why the archive is transferred and extracted ON THE DEVICE rather than scp -r'd:
# scp -r dereferences symlinks. With 1151 of them the tree would be wrong and far
# larger. The ramdisk has GNU tar 1.17, which preserves symlinks, ownership and
# setuid bits when run as root, so we send one .tar.gz and unpack it there.
#
# We ship .tar.gz rather than the original .zst because the ramdisk has no zstd.
# Repack verified lossless: uid 0 on all 6529 entries, all 8 setuid bits intact.
#
# Path mapping: on the device /var IS the Data volume, and under SSHRD the Data
# volume is /mnt2. Confirmed by /mnt2/db/com.apple.xpc.launchd/ existing, which on
# a booted device is /var/db/com.apple.xpc.launchd/. So /var/jb == /mnt2/jb.
#
# This installs FILES ONLY. It does not run prep_bootstrap.sh, which needs to
# execute on a booted device (all its paths are absolute /var/jb/..., and /var on
# the ramdisk is read-only so it cannot be redirected). See the closing note.

set -u
cd "${0:A:h}"

ZST=bootstrap_1900.tar.zst
ZST_SHA=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
STAGE=${TMPDIR:-/tmp}/bootstrap-stage-$$
TGZ=$STAGE/bootstrap.tar.gz
SSHPASS=../tools/sshpass

DEV_TGZ=/mnt2/_bootstrap.tar.gz     # transferred archive, removed on success
DEV_STAGE=/mnt2/_bsstage            # unpack target, removed on success
DEV_JB=/mnt2/jb                     # final location == /var/jb on the device

COMMON=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=10)
SSH_OPTS=("${COMMON[@]}" -p 2222)
SCP_OPTS=("${COMMON[@]}" -P 2222)

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

# Keep this as host-side data. Sending it over ssh stdin avoids a remote shell
# here-document: SSHRD's root filesystem is read-only, so its shell cannot
# create the temporary file traditionally used to feed a here-document.
APT_TRUST_CONFIG='// Jailbreak repos are unsigned. Trust is declared here rather than per-repo
// because Sileo cannot parse [trusted=yes] or a Trusted: yes line, and drops
// or mangles any source that carries one.
Acquire::AllowInsecureRepositories "true";
Acquire::AllowDowngradeToInsecureRepositories "true";
APT::Get::AllowUnauthenticated "true";'

sshdev() { "$SSHPASS" -p alpine ssh "${SSH_OPTS[@]}" root@localhost "$@"; }

trust_state() {
    local got
    got=$(sshdev "/bin/cat '$DEV_JB/etc/apt/apt.conf.d/99-sileo-unsigned-repos'" 2>/dev/null)
    [[ "$got" == "$APT_TRUST_CONFIG" ]] && print "exact" || print "MISSING_OR_DIFFERENT"
}

# ---------------------------------------------------------------- preflight
[[ -f "$ZST" ]]     || { print -u2 "[!] missing $ZST"; exit 1; }
GOT_SHA=$(shasum -a 256 "$ZST" | awk '{print $1}')
[[ "$GOT_SHA" == "$ZST_SHA" ]] || {
    print -u2 "[!] bootstrap SHA-256 mismatch: got $GOT_SHA expected $ZST_SHA"
    exit 1
}
[[ -x "$SSHPASS" ]] || { print -u2 "[!] missing $SSHPASS"; exit 1; }
command -v zstd >/dev/null || { print -u2 "[!] zstd not installed on the Mac (brew install zstd)"; exit 1; }

if ! sshdev true 2>/dev/null; then
    command -v iproxy >/dev/null || { print -u2 "[!] iproxy not installed (brew install libimobiledevice)"; exit 1; }
    iproxy 2222 22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap 'kill $IPROXY_PID 2>/dev/null' EXIT
    sleep 2
fi

sshdev true 2>/dev/null || { print -u2 "[!] no SSH on port 2222. Is the device booted into SSHRD?"; exit 1; }

WHERE=$(sshdev "/sbin/mount | grep -q 'md0 on /' && echo SSHRD || echo NORMAL" 2>/dev/null)
[[ "$WHERE" == "SSHRD" ]] || {
    print -u2 "[!] device reports '${WHERE:-unknown}', not SSHRD. Refusing."
    exit 1
}
print "[*] device is in SSHRD"

sshdev "/sbin/mount | grep -q ' /mnt2 ' || /sbin/mount_apfs /dev/disk1s2 /mnt2" >/dev/null 2>&1
sshdev "/sbin/mount | grep -q ' /mnt2 '" || { print -u2 "[!] /mnt2 (Data volume) not mounted"; exit 1; }
print "[*] /mnt2 mounted (this is the device's /var)"

# ---------------------------------------------------------------- state report
jb_state() {
    if ! sshdev "[ -d '$DEV_JB' ]" 2>/dev/null; then print "ABSENT"; return; fi
    local n strapped
    n=$(sshdev "ls -1 '$DEV_JB' 2>/dev/null | wc -l" 2>/dev/null | tr -d ' ')
    strapped=$(sshdev "[ -f '$DEV_JB/.procursus_strapped' ] && echo yes || echo no" 2>/dev/null)
    print "PRESENT (${n} top-level entries, .procursus_strapped=${strapped})"
}

if (( CHECK_ONLY )); then
    print "\n[*] --check\n"
    printf "  %-24s %s\n" "$DEV_JB" "$(jb_state)"
    printf "  %-24s %s\n" ".installed_usbl8r" \
        "$(sshdev "[ -f '$DEV_JB/.installed_usbl8r' ] && echo present || echo ABSENT" 2>/dev/null)"
    printf "  %-24s %s\n" "repo trust config" "$(trust_state)"
    for p in "$DEV_TGZ" "$DEV_STAGE"; do
        sshdev "[ -e '$p' ]" 2>/dev/null && printf "  %-24s leftover from a previous run\n" "$p"
    done
    exit 0
fi

# Never clobber an unknown bootstrap. A Liter8-marked Procursus tree may resume
# the small post-install steps below; the archive itself is never unpacked over it.
RESUME=0
if sshdev "[ -e '$DEV_JB' ]" 2>/dev/null; then
    if sshdev "[ -f '$DEV_JB/.installed_usbl8r' ] && \
               [ -f '$DEV_JB/.procursus_strapped' ] && \
               [ -x '$DEV_JB/usr/bin/apt' ]" 2>/dev/null; then
        RESUME=1
        print "[*] existing Liter8 bootstrap detected; resuming post-install setup"
    else
        print -u2 "[!] $DEV_JB already exists but is not a verified Liter8 bootstrap."
        print -u2 "    Refusing to overwrite it. Inspect with --check and repair deliberately."
        exit 1
    fi
fi

if (( ! RESUME )); then
    # ------------------------------------------------------------- prepare
    mkdir -p "$STAGE" || exit 1
    print "[*] decompressing (zstd -> tar -> gz, ramdisk has no zstd)"
    zstd -d -q -f "$ZST" -o "$STAGE/bootstrap.tar" || { print -u2 "[!] zstd failed"; exit 1; }
    gzip -c -6 "$STAGE/bootstrap.tar" > "$TGZ" || { print -u2 "[!] gzip failed"; exit 1; }

    # Prove the repack did not lose ownership or setuid, since those are what
    # make the bootstrap work and they are silent if lost.
    ENTRIES=$(tar tzf "$TGZ" 2>/dev/null | wc -l | tr -d ' ')
    UIDS=$(tar tvzf "$TGZ" 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ' ')
    SETUID=$(tar tvzf "$TGZ" 2>/dev/null | grep -cE '^-rws')
    print "[*] repack: ${ENTRIES} entries, uid(s)='${UIDS% }', ${SETUID} setuid"
    [[ "$ENTRIES" == "6529" ]] || { print -u2 "[!] expected 6529 entries, got $ENTRIES"; exit 1; }
    [[ "${UIDS% }" == "0" ]]   || { print -u2 "[!] expected every entry uid 0, got '${UIDS% }'"; exit 1; }
    [[ "$SETUID" == "8" ]]     || { print -u2 "[!] expected 8 setuid binaries, got $SETUID"; exit 1; }

    # ------------------------------------------------------------ transfer
    print "[*] sending $(du -h "$TGZ" | awk '{print $1}') to $DEV_TGZ"
    "$SSHPASS" -p alpine scp "${SCP_OPTS[@]}" "$TGZ" "root@localhost:$DEV_TGZ" || {
        print -u2 "[!] transfer failed"; exit 1; }

    # ------------------------------------------------------------- extract
    # Unpack into staging first so an incomplete transfer can never become
    # /mnt2/jb. The archive keeps its leading ./var/jb hierarchy intact.
    print "[*] extracting on the device (GNU tar 1.17, as root: preserves symlinks/owner/setuid)"
    sshdev "/bin/mkdir -p '$DEV_STAGE' && cd '$DEV_STAGE' && /usr/bin/tar xzf '$DEV_TGZ'" \
        || { print -u2 "[!] extraction failed"; exit 1; }

    sshdev "[ -d '$DEV_STAGE/var/jb' ]" || {
        print -u2 "[!] expected $DEV_STAGE/var/jb after extraction; archive layout changed?"
        print -u2 "    staging left in place at $DEV_STAGE for inspection."
        exit 1
    }

    # The private marker selects this compatibility path without pretending to
    # be another jailbreak, which would change third-party package behaviour.
    print "[*] creating the private usbliter8 marker used by Sileo"
    sshdev ": > '$DEV_STAGE/var/jb/.installed_usbl8r' && \
            /usr/sbin/chown 0:0 '$DEV_STAGE/var/jb/.installed_usbl8r' && \
            /bin/chmod 0644 '$DEV_STAGE/var/jb/.installed_usbl8r'" \
        || { print -u2 "[!] failed to stage .installed_usbl8r"; exit 1; }

    print "[*] moving into place: $DEV_STAGE/var/jb -> $DEV_JB"
    sshdev "/bin/mv '$DEV_STAGE/var/jb' '$DEV_JB'" || { print -u2 "[!] move failed"; exit 1; }

    # rmdir refuses non-empty paths, so cleanup doubles as a staging check.
    sshdev "/bin/rmdir '$DEV_STAGE/var' '$DEV_STAGE' 2>/dev/null; /bin/rm -f '$DEV_TGZ'; sync" >/dev/null 2>&1
fi

# ---------------------------------------------------------------- apt cache owner
# Sileo downloads as mobile and only installs as root, so the apt archive directory
# has to be writable by mobile or every install dies with "Unable to fetch some
# archives", which reads like a network fault and is not one.
#
# The bootstrap ships these 0755 root, but the first root apt run tightens
# archives/partial to 0700 owned by APT::Sandbox::User, and etc/apt/apt.conf.d/
# 03sandbox.conf sets that to root. Nothing then loosens it again, so a fresh device
# always ends up with Sileo unable to write there.
#
# Numeric 501:501 rather than mobile:mobile: the ramdisk has no user database, so a
# name would not resolve. Root keeps write access regardless of owner, so CLI apt is
# unaffected, and this survives later root apt runs (verified on 24A5390f).
print "[*] making the apt archive dir writable by mobile (Sileo fetches as mobile)"
sshdev "/bin/mkdir -p '$DEV_JB/var/cache/apt/archives/partial' && \
        /usr/sbin/chown 501:501 '$DEV_JB/var/cache/apt/archives' \
                                '$DEV_JB/var/cache/apt/archives/partial'" \
    || print -u2 "[!] chown of the apt archive dir failed; Sileo installs will fail until it is fixed"

# ---------------------------------------------------------------- repo trust
# Jailbreak repos are unsigned, so apt needs to be told to trust them or it
# refuses with "There were unauthenticated packages". The usual way is
# [trusted=yes] in a .list or Trusted: yes in a .sources, but Sileo's parser
# breaks on both: with the bracket it treats "[trusted=yes]" as the URL, and a
# Trusted line makes it drop the repo from Sources entirely. Declaring it once
# here keeps apt happy and leaves the source files in a shape Sileo can read.
#
# Repos must then be written WITHOUT any trust directive, and flat ones as
# one-line .list rather than deb822, which Sileo only parses when the repo has
# real Suites and Components:
#     deb https://example.github.io/repo/ ./
print "[*] declaring repo trust globally (Sileo cannot parse per-repo trust)"
sshdev "/bin/mkdir -p '$DEV_JB/etc/apt/apt.conf.d'" \
    || { print -u2 "[!] could not create apt configuration directory"; exit 1; }
print -r -- "$APT_TRUST_CONFIG" | \
    "$SSHPASS" -p alpine ssh "${SSH_OPTS[@]}" root@localhost \
        "/bin/cat > '$DEV_JB/etc/apt/apt.conf.d/99-sileo-unsigned-repos'" \
    || { print -u2 "[!] could not write 99-sileo-unsigned-repos"; exit 1; }

# ---------------------------------------------------------------- verify
print "\n[*] verifying on the device\n"
fail=0
chk() {
    local desc="$1" cmd="$2" want="$3" got
    got=$(sshdev "$cmd" 2>/dev/null | tr -d ' \r')
    if [[ "$got" == "$want" ]]; then printf "  OK    %-42s %s\n" "$desc" "$got"
    else printf "  FAIL  %-42s got '%s', want '%s'\n" "$desc" "${got:-empty}" "$want"; fail=1; fi
}
chk ".procursus_strapped present" "[ -f '$DEV_JB/.procursus_strapped' ] && echo yes || echo no" "yes"
chk "Sileo private marker present" "[ -f '$DEV_JB/.installed_usbl8r' ] && echo yes || echo no"   "yes"
chk "prep_bootstrap.sh present"   "[ -f '$DEV_JB/prep_bootstrap.sh' ] && echo yes || echo no"   "yes"
chk "sudo is setuid root"         "ls -l '$DEV_JB/usr/bin/sudo' | cut -c1-10"                   "-rwsr-xr-x"
# -O is true when the file is owned by the effective uid, and we are root. Deliberately
# not `ls -l | awk '{print $3}'`: the ramdisk HAS NO awk, so that silently returns empty
# and reports a false failure on a perfectly good install. Every other awk in these
# scripts runs on the Mac against ssh output, not inside the remote command.
chk "sudo owned by root"          "[ -O '$DEV_JB/usr/bin/sudo' ] && echo root || echo notroot"  "root"
chk "symlinks preserved (sh)"     "[ -L '$DEV_JB/usr/bin/sh' ] && echo yes || echo no"          "yes"
chk "dpkg present"                "[ -x '$DEV_JB/usr/bin/dpkg' ] && echo yes || echo no"        "yes"
chk "apt present"                 "[ -x '$DEV_JB/usr/bin/apt' ] && echo yes || echo no"         "yes"
# stat -f %u, not ls: the ramdisk ships no passwd or group file, so ls would print the
# numeric id anyway, and -O only ever tests against the effective uid, which is root.
chk "apt archives uid 501 (mobile)" "stat -f %u '$DEV_JB/var/cache/apt/archives'"                "501"
chk "apt partial uid 501 (mobile)"  "stat -f %u '$DEV_JB/var/cache/apt/archives/partial'"        "501"
trust_got=$(trust_state)
if [[ "$trust_got" == "exact" ]]; then
    printf "  OK    %-42s %s\n" "repo trust config exact" "$trust_got"
else
    printf "  FAIL  %-42s %s\n" "repo trust config exact" "$trust_got"
    fail=1
fi
chk "staging cleaned up"          "[ -e '$DEV_STAGE' ] && echo left || echo clean"              "clean"
chk "archive cleaned up"          "[ -e '$DEV_TGZ' ] && echo left || echo clean"                "clean"

print ""
if (( fail )); then
    print -u2 "[!] verification failed. $DEV_JB may be incomplete; inspect before booting."
    exit 1
fi

print "[+] bootstrap installed at $DEV_JB  (== /var/jb on a booted device)"
print ""
print "    NOT finished. After the first normal boot, let Liter8 configure the"
print "    bootstrap, shell and one-time System application registration:"
print ""
print "        liter8 fw finalize --check"
print "        liter8 fw finalize"
print ""
print "    finalize invokes /var/jb/bin/sh explicitly because the kernel refuses direct"
print "    shebang execution here. It also sets NO_PASSWORD_PROMPT=1, skipping the uialert"
print "    password dialog while preserving the rest of Procursus configuration."
print ""
print "    It cannot be run from SSHRD: every path in it is an absolute /var/jb/..., and"
print "    /var on the ramdisk is a read-only symlink to private/var, so it cannot be"
print "    redirected at /mnt2/jb."
print ""
print "    Staging dir on the Mac: $STAGE"
