#!/bin/sh
# fetch_payloads.sh - build every device payload from scratch, on the host.
#
# Run this before sshrd_provision.sh. It downloads the upstream releases,
# extracts the bundles, re-signs everything ad-hoc, and builds the local helper
# binaries from source. Output lands in payload/ and is what the provisioning
# script deploys.
#
# This exists because the payloads are build artifacts and are not committed.
# Without it a fresh clone cannot reproduce anything, and Sileo in particular
# used to be sourced from the device itself (installed by dpkg, pulled back,
# re-signed), which made provisioning depend on the device already being
# half-configured. Everything now comes from upstream.
#
#   ./fetch_payloads.sh                # the default set
#   ./fetch_payloads.sh sileo          # just one
#   ./fetch_payloads.sh debugserver    # optional, not in the default set
#
# Why every binary is re-signed ad-hoc:
#   Sileo ships flags=0x0 "no signature" with ZERO entitlements, because a real
#   jailbreak grants them via trust cache plus an amfid patch. As shipped it
#   dies on '/var/jb/usr/lib/libzstd.1.dylib (blocked by sandbox)'.
#   get-task-allow is never granted: AMFI kills ad-hoc binaries carrying it, so
#   Sileo's replacement entitlement set is written from scratch rather than
#   filtered from what it shipped with.
#
# TrollStore is deliberately NOT built here any more. It used to download
# opa334's TrollStore.tar, re-sign it, and rename the bundle to
# TrollStoreLite.app, which meant the device got the FULL build wearing a Lite
# name, with a helper that cannot register apps on iOS 27:
#   - registerApplicationDictionary: is a stub that always returns NO
#   - its replacement is entitlement-gated and the stock helper lacks the keys
#   - ldid was looked up on the wrong prefix
# It now installs after first boot from a deb, which also means it can be
# updated without another DFU trip, unlike anything placed on the sealed
# System volume. See COMMANDS.md, "TrollStore Lite (after first boot)".

set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE"

# Host-side helper binaries. Where tools/ sits is the only thing that differs
# between the repo and research copies, so it is resolved once here.
TOOLS="$BASE/../tools"

# The bundled ldid links only system libraries, so a Homebrew upgrade
# cannot break it, and its output is byte-identical. It is arm64 only,
# so fall back to PATH where it cannot run, such as an Intel Mac.
# See https://github.com/Xplo8E/Liter8/issues/2.
LDID="$TOOLS/ldid_macosx_arm64"
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
IPSW_ROOT=${IPSW_ROOT:-/tmp/ios27-rootfs} # decrypted root filesystem, mounted
OUT="$BASE/payload"
WORK="$BASE/payload/.work"

# PID 1 and its service cache are never patched by shape alone. Swift exports
# their exact hashes and counts from the selected firmware profile, so a copied
# rootfs or stale work directory stops before producing boot-critical output.
#
# Required only by the components that consume them: LAUNCHD_SHA by injection,
# the two cache values by cache. The requirement is asserted beside the WANT
# set below rather than here, so a selective run such as `sileo` or
# `debugserver` does not need the whole firmware profile exported.
LAUNCHD_SHA=${LITER8_LAUNCHD_SHA:-}
LAUNCHD_CACHE_SHA=${LITER8_LAUNCHD_CACHE_SHA:-}
LAUNCHD_CACHE_DAEMONS=${LITER8_LAUNCHD_CACHE_DAEMONS:-}

SILEO_VER=2.5.1
SILEO_DEB="org.coolstar.sileo_${SILEO_VER}_iphoneos-arm64.deb"   # arm64 == rootless
SILEO_URL="https://github.com/Sileo/Sileo/releases/download/${SILEO_VER}/${SILEO_DEB}"
SILEO_SHA=8e3c90e5a7d32f4ca207a0ac30d3cfa8a13dca86a2b4e11cb3f9e5c68d7bc97a

UICACHE_VER=v1.0.0-ios27
UICACHE_URL="https://github.com/Xplo8E/uikittools-ng/releases/download/${UICACHE_VER}/uicache27"
UICACHE_SHA=2a59540d47cff7631470a98dd230bb233a3f081dc0ad37860970bf8a17f6f16a

# debugserver's own deb, pinned from the Procursus 1900 Packages index
# (Version/Size/SHA256/Filename). This is the SIGNING SOURCE only: the Mac needs
# the exact stock binary to re-sign, and pinning it means the thing we sign is
# byte-verified rather than whatever a device happened to have.
#
# Its dependencies are deliberately NOT pinned here. libllvm16 and
# libclang-cpp16 are installed by apt on the device at the matching version, so
# the dependency closure stays apt's problem. Hand-maintaining it means a
# Procursus bump that adds a dependency fails as an unmet-dependency error on
# someone else's phone.
PROCURSUS_LLVM="https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/llvm"
LLVM_VER="16.0.0~5.9.2~RELEASE-1"
DEBUGSERVER_DEB="debugserver-16_${LLVM_VER}_iphoneos-arm64.deb"
DEBUGSERVER_SHA=81f58c62f933a96912a7416aa4b73915bfd05ab4c1340f89a336337afe67e748

# The stock binary ships ad-hoc with exactly this many entitlements. Asserting
# it means a Procursus rebuild that changes the set stops here instead of
# silently shipping a debugger signed against different assumptions.
DEBUGSERVER_STOCK_ENTS=205

# TrollStore Lite helper, patched for iOS 27 registration. Pinned by SHA256
# because it is a GitHub release rather than an apt package, so nothing else
# verifies it. Its own dependencies (ldid, and libplist3 beneath that) come from
# apt on the device for the same reason as above.
#
# Nothing is re-signed here: the deb ships the patched helper and its postinst
# installs the bundled TrollStoreLite.ipa itself.
TROLLSTORE_VER="2.1.1-ios27+2"
TROLLSTORE_DEB="com.opa334.trollstorehelper27_${TROLLSTORE_VER}_iphoneos-arm64.deb"
TROLLSTORE_URL="https://github.com/Xplo8E/TrollStore27/releases/download/v2.1.1-ios27.2/${TROLLSTORE_DEB}"
TROLLSTORE_SHA=e8ea96c560268430fd437aa50cb9a97b774ee70c242a34fef12b38ef8b099c0d

# ElleKit, for its tweak injector only. lhook already dlopens
# /var/jb/usr/lib/TweakLoader.dylib, which is ElleKit's own symlink to
# libinjector.dylib, so its pspawn hook and launchd-side loader are neither
# needed nor deployed. ElleKit's postinst takes the same view: where a
# jailbreak's own hook already loads TweakLoader.dylib it installs the files
# and runs nothing.
#
# That is also why this is deployed from the host rather than apt-installed on
# the device. Our bootstrap marker is /var/jb/.installed_usbl8r, which that
# postinst does not recognise, so apt would fall through to its default branch
# and start ElleKit's own injection path alongside lhook.
#
# Pinned from ellekit.space, the only place built binaries exist: the GitHub
# repo publishes no releases, and its newest tag (v1.1.3) is six commits behind
# the main branch 1.2 was built from. Across those six commits
# injector/injector.c changes by one copyright line, so the loader is the same
# code either way; the one real change disables exception-handler hooking on
# iOS 17.4 and later, which is the correct behaviour here.
# Version and digest live in device/ellekit.pin so finalize.sh checks the same
# numbers this fetch verified, rather than a second copy that can drift.
. "$BASE/ellekit.pin"
ELLEKIT_DEB="ellekit_${ELLEKIT_VER}_iphoneos-arm64.deb"   # arm64 == rootless here
ELLEKIT_URL="https://ellekit.space/pool/${ELLEKIT_DEB}"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    [+] %s\n' "$1"; }
skip() { printf '    [=] %s\n' "$1"; }
die()  { printf '    [!] %s\n' "$1"; exit 1; }

# Download to a temporary name and rename only on success, so a cached file is
# only ever a complete one. `curl -o` writes in place, and a transfer that drops
# part way leaves the bytes it got: measured 49 KB of the 331 KB ElleKit deb
# against a 2s timeout. The next run reads that as a cache hit and dies on the
# digest instead, with nothing in the message saying to delete it.
# Deadlines, so a stall fails instead of hanging. The optional ElleKit download
# is allowed to fail into a skip, but a server that accepts the connection and
# then says nothing never reached that branch and held `fw provision` before
# Dropbear was installed. A stall detector rather than --max-time: these range
# from a 331 KB deb to a 53 MB one, so any total-time cap right for one is wrong
# for the other, while "no progress for 30s" is the condition being caught.
fetch_cached() {
    [ -f "$1" ] && return 0
    curl -sL --fail --connect-timeout 20 --speed-time 30 --speed-limit 1024 \
        -o "$1.part" "$2" && mv -f "$1.part" "$1" && return 0
    rm -f "$1.part"
    return 1
}

# -x passes for an arm64 binary on an Intel Mac, so check that it runs and
# identifies itself. ldid -v exits non-zero even when it works.
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || die "ldid at $LDID cannot run on this host; brew install ldid-procursus"
mkdir -p "$OUT" "$WORK"

WANT="${*:-sileo helpers cache injection tweaks pairing cellular}"
wants() { case " $WANT " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# A board without a modem has nothing for the cellular payload to fix; see
# LITER8_HAS_BASEBAND in sshrd_provision.sh. Required only when cellular is
# wanted, like the profile values below.
if wants cellular; then
    case "${LITER8_HAS_BASEBAND:-}" in
        1) ;;
        0)
            [ $# -eq 0 ] \
                || die "this firmware profile has no baseband; the cellular payload does not apply"
            no_cellular=
            for item in $WANT; do
                [ "$item" = cellular ] || no_cellular="$no_cellular $item"
            done
            WANT=${no_cellular# }
            ;;
        *) die "Liter8 did not provide the reviewed baseband policy" ;;
    esac
fi

# Assert the boot-critical profile values only for the components that use them.
if wants injection; then
    [ -n "$LAUNCHD_SHA" ] \
        || die "Liter8 did not provide the reviewed launchd hash"
fi
if wants cache; then
    [ -n "$LAUNCHD_CACHE_SHA" ] \
        || die "Liter8 did not provide the reviewed launchd cache hash"
    [ -n "$LAUNCHD_CACHE_DAEMONS" ] \
        || die "Liter8 did not provide the reviewed launchd daemon count"
fi


# ------------------------------------------------------------------- sileo
if wants sileo; then
    say "Sileo $SILEO_VER"
    deb="$WORK/$SILEO_DEB"
    fetch_cached "$deb" "$SILEO_URL" || die "download failed: $SILEO_URL"
    got=$(shasum -a 256 "$deb" | awk '{print $1}')
    [ "$got" = "$SILEO_SHA" ] || die "sha256 mismatch: got $got expected $SILEO_SHA"
    ok "downloaded and hash-verified"

    rm -rf "$WORK/sileo" && mkdir -p "$WORK/sileo"
    ( cd "$WORK/sileo" && ar x "$deb" && xz -dc data.tar.xz | tar xf - )
    APP="$WORK/sileo/var/jb/Applications/Sileo.app"
    [ -d "$APP" ] || die "Sileo.app not found in the deb"
    # Verify setuid in the ARCHIVE, not the extracted copy: macOS tar drops
    # setuid bits when extracting as a non-root user, so the extracted file
    # never has it and checking there would always fail. It is restored with an
    # explicit chmod below, and the device-side tar (running as root) preserves
    # what we set.
    xz -dc "$WORK/sileo/data.tar.xz" | tar tvf - 2>/dev/null \
        | grep -q '^-rws.*giveMeRoot$' \
        || die "giveMeRoot is not setuid in the deb; refusing"
    ok "extracted, giveMeRoot setuid confirmed in the archive"

    # Sileo chooses /var/jb/usr/bin helpers only after recognizing a named
    # jailbreak. This CFW is intentionally not Dopamine/Xina, so patch the
    # Xina marker literal to a private, same-length usbliter8 marker. Sileo
    # still classifies its bootstrap as Procursus, while ElleKit and other
    # software do not mistake the device for a jailbreak it is not running.
    python3 - "$APP/Sileo" <<'PY'
import pathlib, sys

path = pathlib.Path(sys.argv[1])
old = b"/var/jb/.installed_xina15"
new = b"/var/jb/.installed_usbl8r"
assert len(old) == len(new)
blob = path.read_bytes()
count = blob.count(old)
if count != 1:
    raise SystemExit(f"expected exactly one Sileo marker pre-image, found {count}")
group_old = b"mobile:mobile"
# DependencyResolverAccelerator.init chowns sileolists via CommandPath.group; 000501 is decimal 501 padded to match mobile:mobile.
group_new = b"000501:000501"
if len(group_old) != len(group_new) or blob.count(group_old) != 1:
    raise SystemExit("expected exactly one Sileo ownership pre-image")
path.write_bytes(blob.replace(old, new).replace(group_old, group_new))
print("        Sileo marker: .installed_xina15 -> .installed_usbl8r")
print("        Sileo chown: mobile:mobile -> 000501:000501")
PY

    # Sileo needs sandbox exemption to load dylibs out of /var/jb. Its own
    # 34-entitlement set cannot be granted wholesale: AMFI SIGKILLs an ad-hoc
    # binary claiming all of them (one of the 30 we do not need is restricted).
    cat > "$WORK/sileo.ent" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>platform-application</key><true/>
	<key>com.apple.private.security.no-sandbox</key><true/>
	<key>com.apple.private.security.no-container</key><true/>
	<key>com.apple.private.security.container-required</key><false/>
	<key>com.apple.private.skip-library-validation</key><true/>
	<key>com.apple.private.security.storage-exempt.heritable</key><true/>
	<key>com.apple.private.persona-mgmt</key><true/>
	<key>com.apple.private.spawn-subsystem-root</key><true/>
</dict></plist>
EOF
    "$LDID" -Iorg.coolstar.SileoStore -S"$WORK/sileo.ent" -Cadhoc "$APP/Sileo"
    "$LDID" -IgiveMeRoot -S"$WORK/sileo.ent" -Cadhoc "$APP/giveMeRoot"
    chmod 4755 "$APP/giveMeRoot"
    [ -u "$APP/giveMeRoot" ] || die "giveMeRoot lost setuid after signing"

    # CodeResources seals giveMeRoot (the main binary is excluded, its signature
    # is embedded). Re-signing giveMeRoot changes its bytes, which leaves that
    # seal entry pointing at a file that no longer exists. Rewrite just that
    # entry rather than leaving the bundle internally inconsistent.
    python3 - "$APP" <<'PY'
import plistlib, hashlib, sys, os
app = sys.argv[1]
cr = os.path.join(app, "_CodeSignature", "CodeResources")
if not os.path.isfile(cr):
    print("        no CodeResources, nothing to reseal"); raise SystemExit
d = plistlib.load(open(cr, "rb"))
fixed = 0
for section in ("files", "files2"):
    files = d.get(section)
    if not isinstance(files, dict):
        continue
    for name, ent in files.items():
        target = os.path.join(app, name)
        if os.path.basename(name) != "giveMeRoot" or not os.path.isfile(target):
            continue
        blob = open(target, "rb").read()
        if isinstance(ent, dict):
            if "hash2" in ent: ent["hash2"] = hashlib.sha256(blob).digest()
            if "hash"  in ent: ent["hash"]  = hashlib.sha1(blob).digest()
        else:
            files[name] = hashlib.sha1(blob).digest()
        fixed += 1
plistlib.dump(d, open(cr, "wb"))
print(f"        resealed {fixed} CodeResources entr{'y' if fixed==1 else 'ies'} for giveMeRoot")
PY

    codesign --force --sign - --entitlements "$WORK/sileo.ent" "$APP"
    codesign -v "$APP" || die "Sileo bundle signature verification failed"
    python3 - "$LDID" "$APP/Sileo" "$WORK/sileo.ent" <<'PY'
import pathlib, plistlib, subprocess, sys

ldid, binary, source = sys.argv[1:]
signed = plistlib.loads(subprocess.check_output([ldid, "-e", binary]))
expected = plistlib.loads(pathlib.Path(source).read_bytes())
if signed != expected:
    raise SystemExit("Sileo entitlements changed while signing the bundle")
PY

    rm -rf "$OUT/Sileo.app" && cp -R "$APP" "$OUT/Sileo.app"
    chmod 4755 "$OUT/Sileo.app/giveMeRoot"
    codesign -v "$OUT/Sileo.app" || die "copied Sileo bundle signature verification failed"
    ok "payload/Sileo.app ready ($(codesign -dv "$OUT/Sileo.app/Sileo" 2>&1 | grep -o 'flags=0x[0-9a-f]*([a-z]*)'))"
fi

# --------------------------------------------------------------- injection
if wants injection; then
    say "launchd injection payload"
    STOCK="$IPSW_ROOT/sbin/launchd"
    [ -f "$STOCK" ] || die "stock launchd missing at $STOCK; mount the selected profile's rootfs"
    got=$(shasum -a 256 "$STOCK" | awk '{print $1}')
    [ "$got" = "$LAUNCHD_SHA" ] \
        || die "stock launchd sha256 mismatch: got $got expected $LAUNCHD_SHA"
    ok "stock launchd hash verified"

    ( cd launchdhook && ./build.sh ) || die "launchd payload build failed"
    cp launchdhook/lhook.dylib "$OUT/lhook.dylib"
    cp launchdhook/systemhook.dylib "$OUT/systemhook.dylib"
    cp launchdhook/sbextissue "$OUT/sbextissue"
    cp launchdhook/lhookctl "$OUT/lhookctl"

    cp "$STOCK" "$WORK/launchd.orig"
    python3 launchdhook/patch_launchd.py "$WORK/launchd.orig" \
        -o "$WORK/launchd.hooked" --apply >/dev/null \
        || die "could not append the weak lhook load command"
    python3 launchdhook/resign_pagehashes.py "$WORK/launchd.hooked" --apply >/dev/null \
        || die "could not repair launchd page hashes"
    python3 launchdhook/verify_diff.py "$WORK/launchd.orig" "$WORK/launchd.hooked" >/dev/null \
        || die "launchd byte-diff verification failed"
    codesign -v "$WORK/launchd.hooked" \
        || die "launchd code-slot verification failed"

    # The same patch against the path this repo used before the hook moved to
    # /usr/lib/lhook. Nothing installs this image; it exists so provisioning can
    # recognise a device already hooked by the old build as a known state rather
    # than refusing to touch an unrecognised launchd. Built from the same
    # reviewed stock by the same patcher, and byte-diff verified like the real
    # one, so recognising it is not the same as trusting whatever is on a phone.
    # Only where the old command could ever have fitted. /usr/lib/lhook.dylib
    # needs 48 bytes of load-command slack where /usr/lib/lhook needs 40, and a
    # launchd with only 40 (iPadOS 23H30, the build that shortening the path was
    # for) can never have carried the old command, so there is no such state to
    # recognise. Building it unconditionally made patch_launchd.py refuse and
    # took the whole injection step down with it, publishing no payloads at all
    # on a board where provisioning would otherwise work.
    rm -f "$WORK/launchd.hooked-legacy"
    LEGACY_SLACK=$(python3 launchdhook/patch_launchd.py "$WORK/launchd.orig" \
        | sed -n 's/^slack  *\([0-9][0-9]*\) bytes$/\1/p')
    [ -n "$LEGACY_SLACK" ] || die "could not read the launchd load-command slack"
    if [ "$LEGACY_SLACK" -lt 48 ]; then
        skip "launchd has $LEGACY_SLACK bytes of slack; the 48-byte previous path never fitted"
        skip "no legacy recognition image is built, and provisioning does not expect one"
    else
    python3 launchdhook/patch_launchd.py "$WORK/launchd.orig" \
        -o "$WORK/launchd.hooked-legacy" --path /usr/lib/lhook.dylib --apply >/dev/null \
        || die "could not build the previous-path launchd for recognition"
    python3 launchdhook/resign_pagehashes.py "$WORK/launchd.hooked-legacy" --apply >/dev/null \
        || die "could not repair the previous-path launchd page hashes"
    python3 launchdhook/verify_diff.py "$WORK/launchd.orig" "$WORK/launchd.hooked-legacy" \
        /usr/lib/lhook.dylib >/dev/null \
        || die "previous-path launchd byte-diff verification failed"
    codesign -v "$WORK/launchd.hooked-legacy" \
        || die "previous-path launchd code-slot verification failed"
    cmp -s "$WORK/launchd.hooked" "$WORK/launchd.hooked-legacy" \
        && die "the two hook paths produced identical images; the path change is not in effect"
    fi

    cp "$WORK/launchd.orig" "$OUT/launchd.orig"
    cp "$WORK/launchd.hooked" "$OUT/launchd.hooked"
    rm -f "$OUT/launchd.hooked-legacy"
    [ -f "$WORK/launchd.hooked-legacy" ] \
        && cp "$WORK/launchd.hooked-legacy" "$OUT/launchd.hooked-legacy"
    ok "launchd, lhook, icon sandbox payload and token issuer ready"
fi

# ------------------------------------------------------------------- tweaks
# The loader lhook dlopens, plus the tweaks that go in TweakInject. Without
# this step /var/jb/usr/lib/TweakLoader.dylib is absent, lhook's own gate sees
# no loader, and a built tweak has nowhere to be loaded from.
#
# Unreachable upstream skips the step instead of ending the run. This is the
# only member of the default set whose download is not boot-critical: the tweak
# stack is Data-volume content and nothing in the boot path loads it. Dying here
# would abort `fw provision` before install_dropbear.sh, so an ellekit.space
# outage would cost the device its SSH channel over an optional feature.
# sshrd_provision.sh skips its tweaks step to match and reports the set as not
# built. The deb is cached in payload/.work, so only a first run needs network.
EK_FETCHED=0
if wants tweaks; then
    say "ElleKit $ELLEKIT_VER tweak injector"
    deb="$WORK/$ELLEKIT_DEB"
    if fetch_cached "$deb" "$ELLEKIT_URL"; then
        EK_FETCHED=1
    else
        skip "could not reach $ELLEKIT_URL"
        skip "tweak loader not built; re-run ./fetch_payloads.sh tweaks with network"
    fi
fi
if [ "$EK_FETCHED" = 1 ]; then
    got=$(shasum -a 256 "$deb" | awk '{print $1}')
    [ "$got" = "$ELLEKIT_SHA" ] \
        || die "$ELLEKIT_DEB sha256 mismatch: got $got expected $ELLEKIT_SHA"

    rm -rf "$WORK/ellekit" && mkdir -p "$WORK/ellekit"
    # Only the two regular files provisioning installs, named explicitly.
    # Extracting the whole payload would also unpack the deb's symlinks, every
    # one of which points at an absolute /var/jb path that does not exist on a
    # Mac, and a dangling symlink under device/ breaks the copytree in
    # scripts/device_provision.py's prepare_runtime. Naming the members also
    # makes "we take only what provisioning needs" a property of the extraction
    # rather than of a later copy step.
    #
    # libellekit.dylib is deliberately not among them. Neither tweak here links
    # it, and finalize.sh installs the whole deb on a booted device, which is
    # what brings the hooking library, the substrate compatibility symlinks and
    # the dpkg record that lets a tweak depending on mobilesubstrate install.
    # The licence comes out with them: provisioning installs these two dylibs on
    # their own, without dpkg, so the notice ElleKit's BSD terms ask binary
    # redistributions to carry has to travel with them. The deb path gets it for
    # free, since the package contains this same file.
    ( cd "$WORK/ellekit" && ar x "$deb" \
        && xz -dc control.tar.xz | tar xf - \
        && xz -dc data.tar.xz | tar xf - \
            ./var/jb/usr/lib/ellekit/libinjector.dylib \
            ./var/jb/usr/lib/ellekit/MobileSafety.dylib \
            ./var/jb/usr/share/doc/ellekit/LICENSE ) \
        || die "could not extract $ELLEKIT_DEB"
    # Nothing under the extraction may be a symlink, dangling or otherwise.
    [ -z "$(find "$WORK/ellekit" -type l)" ] \
        || die "extraction left a symlink under $WORK/ellekit"
    grep -q '^Package: ellekit$' "$WORK/ellekit/control" \
        || die "unexpected package name in $ELLEKIT_DEB"
    grep -q "^Version: ${ELLEKIT_VER}\$" "$WORK/ellekit/control" \
        || die "unexpected version in $ELLEKIT_DEB"

    EK="$WORK/ellekit/var/jb/usr/lib"
    [ -f "$EK/ellekit/libinjector.dylib" ] \
        || die "$ELLEKIT_DEB has no ellekit/libinjector.dylib; layout changed?"
    # The loader is dlopened into arm64e processes, so an arm64-only build would
    # fail exactly there and nowhere a host check would notice.
    for lib in ellekit/libinjector.dylib ellekit/MobileSafety.dylib; do
        archs=$(lipo -archs "$EK/$lib")
        case " $archs " in *" arm64 "*)  ;; *) die "$lib is missing arm64"  ;; esac
        case " $archs " in *" arm64e "*) ;; *) die "$lib is missing arm64e" ;; esac
        [ -z "$("$LDID" -e "$EK/$lib")" ] \
            || die "$lib unexpectedly carries entitlements"
    done
    # lhook only dlopens the loader and never calls into it, so everything the
    # injector does has to happen from a module initialiser. __init_offsets is
    # the chained-fixups form of __mod_init_func; accept either.
    otool -l "$EK/ellekit/libinjector.dylib" \
        | grep -qE '__init_offsets|__mod_init_func' \
        || die "libinjector.dylib has no module initialiser; a bare dlopen would do nothing"
    ok "$ELLEKIT_DEB hash-verified, both slices, no entitlements, initialiser present"

    # Built in a sibling and renamed into place only once every check below has
    # passed. Writing into payload/tweaks directly meant a rebuild that failed
    # anywhere after the first rm -rf left no tweak set at all, so a transient
    # build failure took away the last working one as well as the new one.
    STAGE="$OUT/.tweaks-building"
    ROLLBACK="$OUT/.tweaks-previous"
    # An interrupted publish leaves the old set under the rollback name and
    # nothing at payload/tweaks. Put it back before building, so the rollback
    # this run creates cannot bury a usable set from the last one.
    if [ ! -d "$OUT/tweaks" ] && [ -d "$ROLLBACK" ]; then
        mv "$ROLLBACK" "$OUT/tweaks" \
            && skip "restored the previous tweak set from an interrupted publish"
    fi
    rm -rf "$STAGE" && mkdir -p "$STAGE/TweakInject"
    cp "$EK/ellekit/libinjector.dylib" "$STAGE/libinjector.dylib"
    # Named by libinjector itself, so it is staged rather than left to resolve
    # to a path that does not exist.
    cp "$EK/ellekit/MobileSafety.dylib" "$STAGE/MobileSafety.dylib"

    # Staged beside them, for the same reason it was extracted. Checked against
    # the copy kept in the repo so the two cannot say different things.
    EK_DOC="$WORK/ellekit/var/jb/usr/share/doc/ellekit/LICENSE"
    [ -f "$EK_DOC" ] || die "$ELLEKIT_DEB has no share/doc/ellekit/LICENSE; layout changed?"
    cmp -s "$EK_DOC" "$BASE/$ELLEKIT_LICENSE" \
        || die "$ELLEKIT_LICENSE differs from the licence in $ELLEKIT_DEB; review it and update the pin"
    cp "$EK_DOC" "$STAGE/LICENSE"

    # The deb itself, for finalize.sh to install on a booted device. It is the
    # upstream package, unmodified and hash-pinned above, so ElleKit stays
    # ElleKit's: its own control, its own maintainer, its own version in dpkg.
    cp "$deb" "$STAGE/ellekit.deb"

    # ElleKit ships its dylibs at flags=0x0. Measured on device: they load and
    # run perfectly well that way, so this is not a requirement and an earlier
    # comment here claiming otherwise was wrong. They are re-signed anyway, for
    # consistency with every other payload and because a payload whose signature
    # state we chose is one less variable when something fails to load. Their
    # identifiers are already their file names, so ldid's default preserves them.
    for lib in libinjector.dylib MobileSafety.dylib; do
        "$LDID" -S -Cadhoc "$STAGE/$lib" || die "could not re-sign $lib"
        codesign -dv "$STAGE/$lib" 2>&1 | grep -q 'flags=0x2(adhoc)' \
            || die "$lib is still not ad-hoc signed"
        [ -z "$("$LDID" -e "$STAGE/$lib")" ] \
            || die "$lib gained entitlements while being re-signed"
        codesign -v "$STAGE/$lib" || die "$lib code-slot verification failed"
    done
    ok "loader and safe-mode payload staged and re-signed; ellekit.deb staged for finalize"

    # Nothing built either tweak before this: the commits that added them and
    # made them ElleKit tweaks never gave them a build or deployment path.
    ( cd localauthfix && ./build.sh ) || die "l8localauth build failed"
    ( cd personafix && ./build.sh ) || die "l8persona build failed"
    for tweak in localauthfix/l8localauth personafix/l8persona; do
        name=$(basename "$tweak")
        cp "$tweak.dylib" "$STAGE/TweakInject/$name.dylib"
        cp "$tweak.plist" "$STAGE/TweakInject/$name.plist"
        plutil -lint "$STAGE/TweakInject/$name.plist" >/dev/null \
            || die "$name.plist does not lint"
        # Both are ElleKit tweaks loaded by filter, so the install name has to
        # be the TweakInject path and not wherever the build ran.
        otool -D "$STAGE/TweakInject/$name.dylib" \
            | grep -qx "/var/jb/usr/lib/TweakInject/$name.dylib" \
            || die "$name.dylib install name is not its TweakInject path"
        ok "$name.dylib and its filter plist staged"
    done

    # Everything above passed, so the previous set can be replaced. It is moved
    # aside rather than deleted: `rm -rf` then `mv` still had a window where a
    # failed or interrupted publication left no set at all, which is the same
    # loss the staging directory was added to prevent, one step later. The old
    # set is restored if the publish fails, and a rollback left behind by an
    # interrupted run is put back by the check where $ROLLBACK is defined.
    if [ -d "$OUT/tweaks" ]; then
        rm -rf "$ROLLBACK"
        mv "$OUT/tweaks" "$ROLLBACK" || die "could not move the previous tweak set aside"
    fi
    if ! mv "$STAGE" "$OUT/tweaks"; then
        [ -d "$ROLLBACK" ] && mv "$ROLLBACK" "$OUT/tweaks"
        die "could not publish the tweak set; the previous one has been put back"
    fi
    rm -rf "$ROLLBACK"
    ok "tweak set published"
fi

# ------------------------------------------------------------------ pairing
if wants pairing; then
    say "pairing, RemoteXPC and coreauthd fallbacks"
    ( cd pairingfix && ./build.sh ) || die "pairing fallback build failed"
    ( cd remotexpcfix && ./build.sh ) || die "RemoteXPC fallback build failed"
    ( cd coreauthfix && ./build.sh ) || die "coreauthd fallback build failed"
    cp pairingfix/l8pair.dylib "$OUT/l8pair.dylib"
    cp remotexpcfix/l8remotepairing.dylib "$OUT/l8remotepairing.dylib"
    cp coreauthfix/l8coreauth.dylib "$OUT/l8coreauth.dylib"
    codesign -v "$OUT/l8pair.dylib" \
        || die "pairing fallback signature verification failed"
    codesign -v "$OUT/l8remotepairing.dylib" \
        || die "RemoteXPC fallback signature verification failed"
    codesign -v "$OUT/l8coreauth.dylib" \
        || die "coreauthd fallback signature verification failed"
    ok "marker-gated l8pair.dylib ready"
    ok "remotepairingdeviced-only l8remotepairing.dylib ready"
    ok "coreauthd-only l8coreauth.dylib ready"
fi

# ----------------------------------------------------------------- cellular
if wants cellular; then
    say "baseband calibration FDR bypass"
    ( cd fdrfix && ./build.sh ) || die "FDR bypass build failed"
    cp fdrfix/l8fdr.dylib "$OUT/l8fdr.dylib"
    codesign -v "$OUT/l8fdr.dylib" \
        || die "FDR bypass signature verification failed"
    ok "CommCenter-only l8fdr.dylib ready"
fi

# ------------------------------------------------------------------- cache
# Build the launchd service cache from the IPSW, not from the device. It used
# to be pulled off a live phone, which meant you needed an already-provisioned
# device to provision a device.
if wants cache; then
    say "launchd service cache"
    STOCK="$IPSW_ROOT/System/Library/xpc/launchd.plist"
    if [ ! -f "$STOCK" ]; then
        skip "IPSW not mounted at $IPSW_ROOT; cannot build the cache"
    else
        mkdir -p boot/work
        got=$(shasum -a 256 "$STOCK" | awk '{print $1}')
        [ "$got" = "$LAUNCHD_CACHE_SHA" ] \
            || die "stock launchd cache sha256 mismatch: got $got expected $LAUNCHD_CACHE_SHA"
        pristine_n=$(python3 -c "import plistlib;print(len(plistlib.load(open('$STOCK','rb'))['LaunchDaemons']))")
        [ "$pristine_n" = "$LAUNCHD_CACHE_DAEMONS" ] \
            || die "stock launchd cache has $pristine_n daemons, expected $LAUNCHD_CACHE_DAEMONS"
        cp "$STOCK" boot/work/launchd.plist
        ok "stock cache hash and $pristine_n-daemon profile verified"
        ./patch_launchd_cache.py boot/work/launchd.plist --apply \
            --expected-pristine-daemons "$LAUNCHD_CACHE_DAEMONS" >/dev/null \
            || die "failed to add com.dropbear"
        ok "com.dropbear added"
        ./add_jbboot.py boot/work/launchd.plist --apply \
            --expected-pristine-daemons "$LAUNCHD_CACHE_DAEMONS" >/dev/null \
            || die "failed to add com.jbboot"
        ok "com.jbboot added"
        ./add_ddi_services.py boot/work/launchd.plist --apply \
            --expected-pristine-daemons "$LAUNCHD_CACHE_DAEMONS" >/dev/null \
            || die "failed to add automatic DeveloperDiskImage service registration"
        ok "DeveloperDiskImage service registration job added"
        ./patch_watchdogd_job.py boot/work/launchd.plist --apply \
            --expected-pristine-daemons "$LAUNCHD_CACHE_DAEMONS" >/dev/null \
            || die "failed to mitigate the watchdogd launch loop"
        ok "watchdogd automatic launch, restart and panic escalation disabled"
        n=$(python3 -c "import plistlib;print(len(plistlib.load(open('boot/work/launchd.plist','rb'))['LaunchDaemons']))")
        [ "$n" = "$((LAUNCHD_CACHE_DAEMONS + 3))" ] \
            || die "patched cache has $n daemons, expected $((LAUNCHD_CACHE_DAEMONS + 3))"
        ok "boot/work/launchd.plist ready, $n daemons"
        echo "        the detached .sig on the device is left untouched; the loader"
        echo "        accepts a modified cache because of launchd_unsecure_cache=1"
    fi
fi

# ------------------------------------------------------------------ helpers
if wants helpers; then
    say "local helper binaries"
    for d in photodiag appreg spawnprobe; do
        [ -d "$d" ] || continue
        if [ -x "$d/build.sh" ]; then
            # if-then-else, not A && B || C: with the latter, a failing ok()
            # would run the skip() branch even on a successful build
            if ( cd "$d" && ./build.sh >/dev/null 2>&1 ); then
                ok "$d built"
            else
                skip "$d build failed"
            fi
        else
            skip "$d has no build.sh"
        fi
    done
    if ( cd photoforce && ./build.sh >/dev/null 2>&1 ); then
        ok "PosterBoard wallpaper repair tools built"
    else
        die "PosterBoard wallpaper repair tools build failed"
    fi
    if ( cd ddiwatch && ./build.sh >/dev/null 2>&1 ); then
        ok "DeveloperDiskImage service watcher built"
    else
        die "DeveloperDiskImage service watcher build failed"
    fi
    if ( cd boothelper && ./build.sh >/dev/null 2>&1 ); then
        ok "per-boot helper built (SSH PATH links, lhook auto-enable)"
    else
        die "per-boot helper build failed"
    fi

    uicache_asset="$WORK/uicache27-$UICACHE_VER"
    fetch_cached "$uicache_asset" "$UICACHE_URL" \
        || die "uicache download failed: $UICACHE_URL"
    got=$(shasum -a 256 "$uicache_asset" | awk '{print $1}')
    [ "$got" = "$UICACHE_SHA" ] \
        || die "uicache sha256 mismatch: got $got expected $UICACHE_SHA"
    cp "$uicache_asset" "$OUT/uicache"
    chmod 0755 "$OUT/uicache"
    ok "uicache $UICACHE_VER downloaded and hash-verified"
fi


# -------------------------------------------------------------- debugserver
# Not in the default WANT set: it is a 53 MB download for an optional debugger,
# and nothing in the boot or bootstrap path needs it.
#
#   ./fetch_payloads.sh debugserver
#
# Only `debugserver` itself is re-signed. The stock binary is ad-hoc with 205
# entitlements and none of the three below, which is enough to attach to a
# platform daemon but NOT enough to set a hardware breakpoint: lldb reports the
# breakpoint as set and it then never fires. Verified by an A/B on one boot
# against one target, stock versus re-signed.
#
# Software breakpoints do not work on this platform at all, regardless of
# entitlements: the write to a shared-cache code page is silently discarded, so
# `breakpoint set -H` is mandatory. See docs/design/DEBUGGING_PLATFORM_DAEMONS.md.
if wants debugserver; then
    say "debugserver $LLVM_VER"
    rm -rf "$WORK/debugserver" && mkdir -p "$WORK/debugserver"

    deb="$WORK/$DEBUGSERVER_DEB"
    fetch_cached "$deb" "$PROCURSUS_LLVM/$DEBUGSERVER_DEB" \
        || die "download failed: $PROCURSUS_LLVM/$DEBUGSERVER_DEB"
    got=$(shasum -a 256 "$deb" | awk '{print $1}')
    [ "$got" = "$DEBUGSERVER_SHA" ] \
        || die "$DEBUGSERVER_DEB sha256 mismatch: got $got expected $DEBUGSERVER_SHA"
    ok "$DEBUGSERVER_DEB hash-verified"

    # Procursus ships this zstd-compressed, unlike Sileo's xz.
    ( cd "$WORK/debugserver" && ar x "$deb" && zstd -dc data.tar.zst | tar xf - )
    ds="$WORK/debugserver/var/jb/usr/lib/llvm-16/bin/debugserver"
    [ -f "$ds" ] || die "debugserver not found in $DEBUGSERVER_DEB"

    # Kept inside the per-run directory wiped above. codesign will not overwrite
    # an existing output file, so a path that survives between runs silently
    # feeds the previous run's merged plist back into the assertions below.
    ent="$WORK/debugserver/entitlements.plist"
    codesign -d --entitlements "$ent" --xml "$ds" 2>/dev/null \
        || die "cannot read debugserver entitlements"
    plutil -convert xml1 "$ent"
    stock=$(grep -c '<key>' "$ent")
    [ "$stock" = "$DEBUGSERVER_STOCK_ENTS" ] \
        || die "debugserver ships $stock entitlements, expected $DEBUGSERVER_STOCK_ENTS"

    # set-exception-port: without it debugserver is SIGKILLed with EXC_GUARD on
    #   task_set_exception_ports(mach_task_self()), which iOS 27 guards.
    # thread-set-state: programs the ARM64 debug registers, so hardware
    #   breakpoints fire. This is the one the stock binary most visibly lacks.
    # cs.debugger: satisfies TXM's debug-mapping entitlement check.
    for k in com.apple.private.set-exception-port \
             com.apple.private.thread-set-state \
             com.apple.private.cs.debugger; do
        /usr/libexec/PlistBuddy -c "Add :$k bool true" "$ent" >/dev/null \
            || die "could not add $k"
    done
    merged=$(grep -c '<key>' "$ent")
    [ "$merged" = "$((DEBUGSERVER_STOCK_ENTS + 3))" ] \
        || die "merged entitlements are $merged, expected $((DEBUGSERVER_STOCK_ENTS + 3))"

    # Keep the stock name and identifier: this replaces the packaged binary at
    # its own path, so the debugserver-16 symlink keeps working and there is no
    # second copy to keep in sync.
    "$LDID" -Idebugserver -S"$ent" -Cadhoc "$ds"
    for k in set-exception-port thread-set-state cs.debugger; do
        "$LDID" -e "$ds" 2>/dev/null | grep -q "com.apple.private.$k" \
            || die "com.apple.private.$k missing after signing"
    done
    cp "$ds" "$OUT/debugserver"
    chmod 0755 "$OUT/debugserver"
    # The deb goes along too: apt installs it on the device so the dependency
    # closure is resolved there, then the re-signed binary replaces the one it
    # unpacked.
    cp "$deb" "$OUT/$DEBUGSERVER_DEB"
    ok "debugserver re-signed, $merged entitlements, all three present"
fi


# --------------------------------------------------------------- trollstore
# Not in the default WANT set. Nothing is re-signed: the deb ships the iOS 27
# patched helper, and its postinst installs the bundled TrollStoreLite.ipa.
#
#   ./fetch_payloads.sh trollstore
if wants trollstore; then
    say "TrollStore helper $TROLLSTORE_VER"
    deb="$WORK/$TROLLSTORE_DEB"
    fetch_cached "$deb" "$TROLLSTORE_URL" \
        || die "download failed: $TROLLSTORE_URL"
    got=$(shasum -a 256 "$deb" | awk '{print $1}')
    [ "$got" = "$TROLLSTORE_SHA" ] \
        || die "$TROLLSTORE_DEB sha256 mismatch: got $got expected $TROLLSTORE_SHA"

    # Confirm it is the package we think it is before shipping it to a device.
    rm -rf "$WORK/trollstore" && mkdir -p "$WORK/trollstore"
    ( cd "$WORK/trollstore" && ar x "$deb" && xz -dc control.tar.xz | tar xf - )
    grep -q '^Package: com.opa334.trollstorehelper27$' "$WORK/trollstore/control" \
        || die "unexpected package name in $TROLLSTORE_DEB"
    grep -q "^Version: ${TROLLSTORE_VER}\$" "$WORK/trollstore/control" \
        || die "unexpected version in $TROLLSTORE_DEB"

    cp "$deb" "$OUT/$TROLLSTORE_DEB"
    ok "$TROLLSTORE_DEB hash-verified, package and version confirmed"
fi

say "summary"
for p in "$OUT/Sileo.app/Sileo" "$OUT/Sileo.app/giveMeRoot" \
         "$OUT/launchd.orig" "$OUT/launchd.hooked" "$OUT/lhook.dylib" \
         "$OUT/systemhook.dylib" "$OUT/sbextissue" "$OUT/l8pair.dylib" \
         "$OUT/l8remotepairing.dylib" "$OUT/l8coreauth.dylib" \
         "$OUT/l8fdr.dylib" "$OUT/uicache" \
         "$OUT/tweaks/libinjector.dylib" "$OUT/tweaks/ellekit.deb" \
         "$OUT/tweaks/TweakInject/l8localauth.dylib" \
         "$OUT/tweaks/TweakInject/l8persona.dylib" \
         photodiag/photodiag spawnprobe/personaalloc appreg/appreg \
         photoforce/pfruntimeprobe photoforce/pfwatch ddiwatch/ddiwatch boothelper/l8boot \
         "$OUT/debugserver"; do
    if [ -f "$p" ]; then
        # "$BASE" quoted separately inside ${..}: unquoted it is treated as a
        # glob pattern, so a path containing [ or * would strip the wrong prefix
        printf '    %-46s %8s bytes  %s\n' "${p#"$BASE"/}" "$(wc -c < "$p" | tr -d ' ')" \
            "$(codesign -dv "$p" 2>&1 | grep -o 'flags=0x[0-9a-f]*([a-z]*)' || echo '')"
    else
        printf '    %-46s MISSING\n' "${p#"$BASE"/}"
    fi
done
echo
echo "    next: boot the device into SSHRD, then ./sshrd_provision.sh"
