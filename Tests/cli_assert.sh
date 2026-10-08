#!/bin/zsh
#
# Assert the CLI's observable contract. Written after a custom entry point broke
# every --help while the exit-code diff still looked plausible, so help is
# asserted on content, not just on exit status.
#
#   ./cli_assert.sh <path-to-liter8>

set -u
BIN=${1:?usage: cli_assert.sh <liter8>}
# Firmware binaries are not committed, so the checks that need one are skipped
# when it is absent. Pass them to exercise those too:
#
#   MACHO=<a Mach-O payload> KERNEL=<a kernelcache> IM4P=<an .im4p> ./cli_assert.sh <liter8>
#
# Everything about help, option scoping and error wording runs without them.
KC=${MACHO:-}
KERNEL=${KERNEL:-}
IM4P=${IM4P:-}

pass=0; fail=0; skipped=0
ok()   { print -r -- "  [+] $1"; ((pass++)) }
bad()  { print -r -- "  [!] $1"; ((fail++)) }
skip() { print -r -- "  [=] $1 (no fixture)"; ((skipped++)) }

# Skip rather than fail when the fixture a check needs is not present.
have() { [[ -n "$1" && -f "$1" ]] }

# expect_ok <desc> <args...>
expect_ok() {
    local desc=$1; shift
    "$BIN" "$@" >/tmp/.a_out 2>/tmp/.a_err
    local rc=$?
    (( rc == 0 )) && ok "$desc" || bad "$desc (exit $rc: $(head -1 /tmp/.a_err))"
}

# expect_fail <desc> <args...>   any non-zero
expect_fail() {
    local desc=$1; shift
    "$BIN" "$@" >/tmp/.a_out 2>/tmp/.a_err
    local rc=$?
    (( rc != 0 )) && ok "$desc" || bad "$desc (expected failure, got 0)"
}

# expect_help <desc> <must-contain> <args...>
# Help must exit 0, reach stdout, and name the scope it is describing.
expect_help() {
    local desc=$1 needle=$2; shift 2
    "$BIN" "$@" >/tmp/.a_out 2>/tmp/.a_err
    local rc=$?
    if (( rc != 0 )); then
        bad "$desc (exit $rc)"; return
    fi
    if [[ ! -s /tmp/.a_out ]]; then
        bad "$desc (nothing on stdout; stderr: $(head -1 /tmp/.a_err))"; return
    fi
    if ! grep -qF -- "$needle" /tmp/.a_out; then
        bad "$desc (stdout missing '$needle')"; return
    fi
    # A leaked internal error is the specific failure this script exists to catch.
    if grep -qiE "CommandError|ParserError|helpRequested" /tmp/.a_out /tmp/.a_err; then
        bad "$desc (leaked an internal ArgumentParser error)"; return
    fi
    ok "$desc"
}

# expect_no_match <desc> <needle> <args...>
# For checks where the command is expected to fail later anyway, and all that
# matters is that it did NOT fail at the parsing layer.
expect_no_match() {
    local desc=$1 needle=$2; shift 2
    "$BIN" "$@" >/tmp/.a_out 2>/tmp/.a_err
    if grep -qF -- "$needle" /tmp/.a_out /tmp/.a_err; then
        bad "$desc (parser rejected it)"
    else ok "$desc"; fi
}

# expect_contains <desc> <needle> <args...>  (stdout or stderr)
expect_contains() {
    local desc=$1 needle=$2; shift 2
    "$BIN" "$@" >/tmp/.a_out 2>/tmp/.a_err
    if grep -qF -- "$needle" /tmp/.a_out /tmp/.a_err; then ok "$desc"
    else bad "$desc (missing '$needle')"; fi
}

print -r -- "== help is scoped and clean =="
expect_help "liter8 --help lists subcommands"        "SUBCOMMANDS:" --help
expect_help "liter8 -h works"                        "SUBCOMMANDS:" -h
expect_help "fw --help lists fw actions"             "setup-debugger" fw --help
expect_help "fw -h works"                            "setup-debugger" fw -h
expect_help "fw boot --help names --irecovery"       "--irecovery" fw boot --help
expect_help "fw get-rd --help names --ticket"        "--ticket" fw get-rd --help
expect_help "fw get-rd --help names --serial"        "--serial" fw get-rd --help
expect_help "fw provision --help names --rootfs"     "--rootfs" fw provision --help
expect_help "fw prepare --help names --file"         "--file" fw prepare --help
expect_help "fw setup-debugger --help names --check" "--check" fw setup-debugger --help
expect_help "resolve --help names <component>"       "component" resolve --help
expect_help "apply --help names --records-out"       "--records-out" apply --help
expect_help "inspect --help lists the modes"         "pattern-at" inspect --help
expect_help "im4p --help lists subcommands"          "repack" im4p --help
expect_help "img4 --help lists subcommands"          "extract-manifest" img4 --help
expect_help "fixture --help names --component-name"  "--component-name" fixture --help
expect_help "survey --help names --guards"           "--guards" survey --help
expect_help "verify --help names manifest"           "manifest" verify --help
expect_help "setup --help names --resource-dir"      "--resource-dir" setup --help
expect_help "preflight --help works"                 "OVERVIEW" preflight --help
expect_help "profiles --help works"                  "OVERVIEW" profiles --help
expect_help "acm-probe --help works"                 "signature-variant" acm-probe --help
expect_help "fw actions --help works"                "OVERVIEW" fw actions --help
expect_help "fw make-cfw --help names --serial"      "--serial" fw make-cfw --help
expect_help "fw restore-cfw --help names the option" "--idevicerestore" fw restore-cfw --help

print -r -- ""; print -r -- "== help does NOT offer options that do not apply =="
# A false positive here means the old global-usage behaviour is back.
expect_fail "fw boot rejects --rootfs"           fw boot --rootfs /tmp
expect_fail "fw boot rejects --check"            fw boot --check
expect_fail "fw make-cfw rejects --check"        fw make-cfw --check
expect_fail "fw boot rejects --idevicerestore"   fw boot --idevicerestore /bin/true
expect_fail "fw prepare rejects --serial"        fw prepare --serial
expect_fail "fw prepare rejects --check"         fw prepare --check
expect_fail "fw boot rejects --ticket"           fw boot --ticket /tmp/t
expect_fail "fw boot rejects --sshrd-payload"    fw boot --sshrd-payload /tmp/s

print -r -- ""; print -r -- "== read-only commands still work =="
expect_ok "profiles"                      profiles
expect_ok "fw actions"                    fw actions
if have "$KC"; then
expect_ok "inspect segments"              inspect "$KC" segments
expect_ok "inspect strings"               inspect "$KC" strings vm_fault_enter_prepare
expect_ok "inspect func"                  inspect "$KC" func 0x2f3a4
expect_ok "inspect dis"                   inspect "$KC" dis 0x2f408 4
expect_ok "inspect xrefs"                 inspect "$KC" xrefs 0xeba
expect_ok "inspect calls"                 inspect "$KC" calls 0x2f3a4
expect_ok "inspect pattern"               inspect "$KC" pattern 0x370001c8
expect_ok "inspect pattern-at"            inspect "$KC" pattern-at 0x2f408 0x370001c8
expect_ok "inspect page-tail-runs"        inspect "$KC" page-tail-runs 2
have "$KERNEL" && expect_ok "profile (kernelcache)" profile "$KERNEL" || skip "profile"
have "$IM4P" && expect_ok "im4p info (real IM4P)" im4p info "$IM4P" || skip "im4p info"
expect_ok "resolve txm boot"              resolve txm boot "$KC"
expect_ok "resolve txm boot --json"       resolve txm boot "$KC" --json
else
  skip "inspect/resolve/profile/im4p checks"
fi

print -r -- ""; print -r -- "== argument order preserved: binary before mode =="
if have "$KC"; then
    expect_ok   "inspect <bin> segments works"  inspect "$KC" segments
    expect_fail "inspect segments <bin> fails"  inspect segments "$KC"
else
    skip "inspect argument order"
fi

print -r -- ""
print -r -- "== help survives after the inspect mode =="
# .captureForPassthrough swallows built-in flags, so these regress silently:
# before the explicit check, `segments --help` reported "takes no parameters"
# and `dis <off> --help` ignored the flag and disassembled.
# No fixture needed: validate() throws the help request before run() opens the
# path, so these must hold on a bare checkout. Gating them behind a firmware
# binary would skip the exact regression they exist to catch.
expect_help "inspect <bin> --help"                  "MODES:" inspect /dev/null --help
expect_help "inspect <bin> segments --help"         "MODES:" inspect /dev/null segments --help
expect_help "inspect <bin> dis <off> --help"        "MODES:" inspect /dev/null dis 0x2f408 --help
expect_help "inspect <bin> pattern <word> -h"       "MODES:" inspect /dev/null pattern 0x370001c8 -h
expect_help "inspect <bin> objc-methods sel --help" "MODES:" inspect /dev/null objc-methods someSel --help
expect_help "help resolves before the file is read" "MODES:" inspect /nonexistent segments --help

print -r -- ""; print -r -- "== option values that begin with a dash =="
# This device boots `-v debug=0x2014e launchd_unsecure_cache=1 wdt=-1 serial=3`,
# so a boot-args literal normally starts with a dash. Without
# `parsing: .unconditional` ArgumentParser reports "Missing value for
# '--boot-args'" and the option is unusable for its main purpose.
expect_no_match "--boot-args accepts a leading dash" "Missing value" \
    resolve iboot ibss-bootargs /dev/null --boot-args "-v debug=0x2014e"
expect_no_match "--boot-args accepts a bare -v" "Missing value" \
    resolve iboot ibss-bootargs /dev/null --boot-args "-v"
expect_no_match "apply --boot-args leading dash" "Missing value" \
    apply iboot ibss-bootargs /dev/null /tmp/liter8-assert-out.bin --boot-args "-v x"

print -r -- ""; print -r -- "== errors name the valid values =="
# Validation happens before any file is read, so a placeholder path is fine here.
expect_contains "unknown plan lists plans"          "Plans:"      resolve txm nope /dev/null
expect_contains "unknown component lists them"      "Components:" resolve nope boot /dev/null
expect_contains "unknown inspect mode lists modes"  "Modes:"      inspect /dev/null nope
expect_contains "unknown plan scoped to resolve"    "liter8 resolve" resolve txm nope /dev/null
expect_contains "unknown mode scoped to inspect"    "liter8 inspect" inspect /dev/null nope

print -r -- ""; print -r -- "== runtime errors still report =="
expect_contains "missing file names it" "nonexistent" im4p info /nonexistent
expect_fail     "missing file exits non-zero"        im4p info /nonexistent

print -r -- ""; print -r -- "$pass passed, $fail failed, $skipped skipped"
(( fail == 0 ))
