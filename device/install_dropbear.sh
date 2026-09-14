#!/bin/zsh
#
# Install dropbear onto the device's System volume. RUN FROM THE MAC, with the device
# booted into SSHRD.
#
#   ./install_dropbear.sh            install
#   ./install_dropbear.sh --check    verify only, change nothing
# Reuses `iproxy 2222 22` when running, or starts its own fallback.
#
# Source is ssh.tar.gz here, byte-identical to upstream's work-27.0b3/ssh.tar.gz.
# The server, key generator and the three minimal System utilities proven by the
# beta-4 research are installed. The archive also contains old host keys, but
# copying one private identity to every phone would be wrong. This installer
# therefore runs the device's own dropbearkey while Data is mounted writable in
# SSHRD. The launchd job later reads those unique keys from /private/var/dropbear.
# Generating them here is deliberate: this old Dropbear's -R mode only handles
# its default /etc/dropbear paths and does not populate arbitrary -r paths.
#
# Deliberately minimal. The restored System volume contains only df and ps in /bin.
# Dropbear reads root's /etc/passwd shell, which is /bin/sh, and com.jbboot names the
# same interpreter explicitly in its signed launchd-cache job. Omitting it therefore
# gives a listening SSH server that cannot open a login shell and a jbboot job that
# fails at launchd initialization. ls and cat are retained because the known-working
# beta-4 shell used them and they make recovery possible before /var/jb is prepared.
#
# The binary is NOT re-signed. It ships signed with `platform-application` and
# `com.apple.private.security.container-required=false`, and an ldid re-sign would strip
# the restricted entitlement. Loading it relies on the AMFIIsCDHashInTrustCache kernel
# patch, same as everything else we run.

set -u
cd "${0:A:h}"

PKG=ssh.tar.gz
STAGE=${TMPDIR:-/tmp}/dropbear-stage-$$
SSHPASS=../tools/sshpass

# ssh takes -p <port>, scp takes -P <port>. Keeping them as separate arrays avoids the
# obvious trap: `-p 2222` inside one array is TWO elements, so trying to rewrite it with a
# string substitution silently does nothing and scp ends up with -p (preserve times) and
# no port at all, connecting to localhost:22.
COMMON=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=8)
SSH_OPTS=("${COMMON[@]}" -p 2222)
SCP_OPTS=("${COMMON[@]}" -P 2222)

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

# Left = path inside the tarball, right = path on the device. /mnt1 is the System volume.
FILES=(
  "usr/local/bin/dropbear|/mnt1/usr/local/bin/dropbear"
  "usr/local/bin/dropbearkey|/mnt1/usr/local/bin/dropbearkey"
  "bin/sh|/mnt1/bin/sh"
  "bin/ls|/mnt1/bin/ls"
  "bin/cat|/mnt1/bin/cat"
)

# type | Data-volume path | key size. Dropbear 2016.74 advertises these three
# server key types, so create every identity named by the launchd job. The
# private keys never leave the phone and are not copied from ssh.tar.gz.
HOST_KEYS=(
  "rsa|/mnt2/dropbear/dropbear_rsa_host_key|2048"
  "ecdsa|/mnt2/dropbear/dropbear_ecdsa_host_key|521"
  "dss|/mnt2/dropbear/dropbear_dss_host_key|1024"
)

# ---------------------------------------------------------------- preflight
[[ -f "$PKG" ]]     || { print -u2 "[!] missing $PKG"; exit 1; }
[[ -x "$SSHPASS" ]] || { print -u2 "[!] missing $SSHPASS"; exit 1; }

sshdev() { "$SSHPASS" -p alpine ssh "${SSH_OPTS[@]}" root@localhost "$@"; }

# A following workflow phase may need the same local port immediately. Merely
# sending SIGTERM leaves a small window where the old forward still accepts a
# connection and then vanishes underneath it, so reap it before returning.
stop_owned_iproxy() {
    kill "$IPROXY_PID" 2>/dev/null || true
    wait "$IPROXY_PID" 2>/dev/null || true
}

if ! sshdev true 2>/dev/null; then
    command -v iproxy >/dev/null || { print -u2 "[!] iproxy not installed (brew install libimobiledevice)"; exit 1; }
    iproxy 2222 22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap stop_owned_iproxy EXIT
    sleep 2
fi

sshdev true 2>/dev/null || { print -u2 "[!] no SSH on port 2222. Is the device booted into SSHRD?"; exit 1; }

# Refuse to run against a normally-booted device. /mnt1 only exists under SSHRD, and this
# check is upstream's own (COMMANDS.md section 3).
WHERE=$(sshdev "/sbin/mount | grep -q 'md0 on /' && echo SSHRD || echo NORMAL" 2>/dev/null)
if [[ "$WHERE" != "SSHRD" ]]; then
    print -u2 "[!] device reports '${WHERE:-unknown}', not SSHRD."
    print -u2 "    Refusing: /mnt1 only exists on the ramdisk, so this would write nothing useful."
    exit 1
fi
print "[*] device is in SSHRD"

sshdev "/sbin/mount | grep -q ' /mnt1 ' || /sbin/mount_apfs /dev/disk1s1 /mnt1" >/dev/null 2>&1
sshdev "/sbin/mount | grep -q ' /mnt1 '" || { print -u2 "[!] /mnt1 not mounted"; exit 1; }
print "[*] /mnt1 mounted"
sshdev "/sbin/mount | grep -q ' /mnt2 ' || /sbin/mount_apfs /dev/disk1s2 /mnt2" >/dev/null 2>&1
sshdev "/sbin/mount | grep -q ' /mnt2 '" || { print -u2 "[!] /mnt2 not mounted"; exit 1; }
print "[*] /mnt2 mounted"

# ---------------------------------------------------------------- stage
mkdir -p "$STAGE" || exit 1
tar xzf "$PKG" -C "$STAGE" || { print -u2 "[!] extract failed"; exit 1; }
print "[*] extracted $PKG -> $STAGE"

for e in "${FILES[@]}"; do
    src="${e%%|*}"
    [[ -f "$STAGE/$src" ]] || { print -u2 "[!] not in the tarball: $src"; exit 1; }
done

# report <label> compares on-device size against the staged source
report() {
    local src="$1" dst="$2" want got line perm
    want=$(stat -f %z "$STAGE/$src")
    line=$(sshdev "ls -l '$dst' 2>/dev/null")
    got=$(print -r -- "$line" | awk '{print $5}')
    perm=$(print -r -- "$line" | awk '{print $1}')
    if [[ -z "$got" ]];           then printf "  ABSENT    %-56s want %s\n" "$dst" "$want"; return 1
    elif [[ "$got" == "$want" ]]; then printf "  OK        %-56s %s bytes  %s\n" "$dst" "$got" "$perm"; return 0
    else                               printf "  MISMATCH  %-56s have %s, want %s\n" "$dst" "$got" "$want"; return 1
    fi
}

# Report a host key without printing any key material. A non-empty file with
# mode 0600 is enough to prove that Dropbear can read a private identity while
# keeping it inaccessible to normal users.
report_key() {
    local key_file="$1" line size perm
    line=$(sshdev "ls -l '$key_file' 2>/dev/null")
    size=$(print -r -- "$line" | awk '{print $5}')
    perm=$(print -r -- "$line" | awk '{print $1}')
    if [[ -n "$size" && "$size" != "0" && "$perm" == "-rw-------" ]]; then
        printf "  OK        %-56s %s bytes  %s\n" "$key_file" "$size" "$perm"
        return 0
    fi
    printf "  MISMATCH  %-56s have %s bytes, %s\n" "$key_file" "${size:-0}" "${perm:-absent}"
    return 1
}

# A check must report the device exactly as it is. In particular, do not make
# an absent installation look partially present by creating its directories.
if (( CHECK_ONLY )); then
    print "\n[*] --check\n"
    check_failed=0
    for e in "${FILES[@]}"; do
        report "${e%%|*}" "${e#*|}" || check_failed=1
    done
    key_dir=$(sshdev "ls -ld /mnt2/dropbear 2>/dev/null" | awk '{print $1}')
    if [[ "$key_dir" == "drwx------" ]]; then
        printf "  OK        %-56s %s\n" "/mnt2/dropbear" "$key_dir"
    else
        printf "  MISMATCH  %-56s have %s, want drwx------\n" "/mnt2/dropbear" "${key_dir:-absent}"
        check_failed=1
    fi
    for e in "${HOST_KEYS[@]}"; do
        report_key "${${e#*|}%%|*}" || check_failed=1
    done
    rm -rf "$STAGE"
    (( check_failed == 0 )) || exit 1
    exit 0
fi

# A fresh restore may not have either target directory yet. Creation belongs
# to the install path, after the non-mutating --check exit above.
#
# Do not assume the System volume inherited a writable mount from an earlier
# command. A diagnostic collection deliberately mounts it read-only, and a
# later provisioning retry must repair that state instead of failing inside
# scp with no useful explanation.
sshdev "/sbin/mount -u -o rw /dev/disk1s1 2>/dev/null; \
        /usr/bin/touch /mnt1/.liter8-write-test && \
        /bin/rm -f /mnt1/.liter8-write-test" \
    || { print -u2 "[!] System volume is not writable"; exit 1; }
sshdev "/sbin/mount -u -o rw /dev/disk1s2 2>/dev/null; \
        /usr/bin/touch /mnt2/.liter8-write-test && \
        /bin/rm -f /mnt2/.liter8-write-test" \
    || { print -u2 "[!] Data volume is not writable"; exit 1; }
sshdev "/bin/mkdir -p /mnt1/usr/local/bin /mnt1/bin" \
    || { print -u2 "[!] could not create dropbear target directories"; exit 1; }
sshdev "/bin/mkdir -p /mnt2/dropbear && /bin/chmod 700 /mnt2/dropbear" \
    || { print -u2 "[!] could not create the private host-key directory"; exit 1; }
print "[*] target directories present"

# ---------------------------------------------------------------- install
print ""
for e in "${FILES[@]}"; do
    src="${e%%|*}"; dst="${e##*|}"
    printf "  %-56s " "$dst"
    if "$SSHPASS" -p alpine scp "${SCP_OPTS[@]}" "$STAGE/$src" "root@localhost:$dst" >/dev/null 2>&1; then
        print "sent"
    else
        print "FAILED"
        print -u2 "[!] stopping. Files sent before this point are already in place."
        exit 1
    fi
done

# scp does not reliably carry the executable bit here. Try chmod from whichever location
# actually has one: the ramdisk may not, and a System-volume binary may or may not run from
# the ramdisk's dyld cache. Not fatal if none work, so report instead of dying.
CHMOD=$(sshdev 'for c in /bin/chmod /usr/bin/chmod /mnt1/bin/chmod; do [ -x "$c" ] && { echo "$c"; break; }; done' 2>/dev/null)
if [[ -n "$CHMOD" ]]; then
    sshdev "$CHMOD 755 /mnt1/usr/local/bin/dropbear /mnt1/usr/local/bin/dropbearkey \
                        /mnt1/bin/sh /mnt1/bin/ls /mnt1/bin/cat 2>/dev/null" >/dev/null 2>&1
    print "\n[*] permissions set using $CHMOD"
else
    print "\n[!] no chmod found on the device; check the mode column below and fix by hand"
fi

# ---------------------------------------------------------------- host identity
# Generate keys after installing dropbearkey and before the normal boot. A
# zero-byte remnant is removed explicitly because dropbearkey refuses to
# overwrite an existing path. Existing non-empty keys are preserved so the
# device's SSH identity stays stable across repeated provisioning runs.
print "\n[*] preparing unique normal-boot Dropbear host keys"
for e in "${HOST_KEYS[@]}"; do
    type="${e%%|*}"
    rest="${e#*|}"
    key_file="${rest%%|*}"
    bits="${e##*|}"

    if sshdev "[ -s '$key_file' ]" 2>/dev/null; then
        printf "  %-56s preserved\n" "$key_file"
        continue
    fi

    # This is one exact, validated path under /mnt2/dropbear, never a glob.
    sshdev "/bin/rm -f '$key_file'; \
            /mnt1/usr/local/bin/dropbearkey -t '$type' -s '$bits' -f '$key_file' \
            >/dev/null 2>&1" \
        || { print -u2 "[!] could not generate the $type host key at $key_file"; exit 1; }
    printf "  %-56s generated (%s %s-bit)\n" "$key_file" "$type" "$bits"
done

if [[ -n "$CHMOD" ]]; then
    # HOST_KEYS contains structured records, so name the validated destinations
    # explicitly instead of attempting a brittle shell transformation.
    sshdev "$CHMOD 600 \
        /mnt2/dropbear/dropbear_rsa_host_key \
        /mnt2/dropbear/dropbear_ecdsa_host_key \
        /mnt2/dropbear/dropbear_dss_host_key" \
        || { print -u2 "[!] could not protect generated host keys"; exit 1; }
fi
sshdev sync >/dev/null 2>&1

# ---------------------------------------------------------------- verify
print "\n[*] verifying on-device\n"
fail=0
for e in "${FILES[@]}"; do report "${e%%|*}" "${e##*|}" || fail=1; done
key_dir=$(sshdev "ls -ld /mnt2/dropbear 2>/dev/null" | awk '{print $1}')
if [[ "$key_dir" == "drwx------" ]]; then
    printf "  OK        %-56s %s\n" "/mnt2/dropbear" "$key_dir"
else
    printf "  MISMATCH  %-56s have %s, want drwx------\n" "/mnt2/dropbear" "${key_dir:-absent}"
    fail=1
fi
for e in "${HOST_KEYS[@]}"; do
    report_key "${${e#*|}%%|*}" || fail=1
done

print ""
if (( fail )); then
    print -u2 "[!] one or more files did not land."
    exit 1
fi
print "[+] dropbear installed and verified."
print ""
print "    This only installs the binaries. Nothing in ssh.tar.gz is a LaunchDaemon, so"
print "    dropbear is started by the com.dropbear job that patch_launchd_cache.py adds"
print "    to the signed cache; fetch_payloads.sh builds it and sshrd_provision.sh"
print "    deploys it. See README.md steps 7 and 8."
print ""
print "    Staging dir left at: $STAGE"
