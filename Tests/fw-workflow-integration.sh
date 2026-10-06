#!/bin/bash
set -euo pipefail

# A tiny IPSW exercises native Swift extraction and the remaining Python build
# handoff without storing or unpacking real firmware.
PATCHER="${1:-.build/debug/liter8}"
PATCHER="$(cd "$(dirname "$PATCHER")" && pwd)/$(basename "$PATCHER")"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

WORK_DIR="$TEST_ROOT/work"
IPSW_FILE="$TEST_ROOT/renamed.ipsw"
RC_IPSW_FILE="$TEST_ROOT/release-candidate.ipsw"
RC_WORK_DIR="$TEST_ROOT/rc-work"
D431_IPSW_FILE="$TEST_ROOT/d431.ipsw"
D431_WORK_DIR="$TEST_ROOT/d431-work"
DUAL_IPSW_FILE="$TEST_ROOT/dual-board.ipsw"
DUAL_WORK_DIR="$TEST_ROOT/dual-board-work"
BAD_WORK_DIR="$TEST_ROOT/bad-work"
BAD_IPSW_FILE="$TEST_ROOT/traversal.ipsw"
RESOURCE_DIR="$TEST_ROOT/resources"
RUN_DIR="$TEST_ROOT/unrelated-current-directory"
mkdir -p "$WORK_DIR" "$RC_WORK_DIR" "$D431_WORK_DIR" "$DUAL_WORK_DIR" "$BAD_WORK_DIR" "$RESOURCE_DIR/scripts" "$RUN_DIR"

/usr/bin/python3 - "$IPSW_FILE" "$RC_IPSW_FILE" "$D431_IPSW_FILE" "$DUAL_IPSW_FILE" "$BAD_IPSW_FILE" "$WORK_DIR" <<'PY'
import copy
import plistlib
import sys
import zipfile
from pathlib import Path

ipsw = Path(sys.argv[1])
rc_ipsw = Path(sys.argv[2])
d431_ipsw = Path(sys.argv[3])
dual_ipsw = Path(sys.argv[4])
bad_ipsw = Path(sys.argv[5])
work = Path(sys.argv[6])
manifest = {
    "ProductVersion": "27.0",
    "ProductBuildVersion": "24A5390f",
    "SupportedProductTypes": ["iPhone12,1"],
    "BuildIdentities": [{
        "ApBoardID": "0x04",
        "ApChipID": "0x8030",
        "Info": {
            "DeviceClass": "n104ap",
            "Variant": "Developer Erase Install (IPSW)",
        },
        "Manifest": {
            "iBSS": {"Info": {"Path": "Firmware/dfu/iBSS.test.im4p"}},
            "iBEC": {"Info": {"Path": "Firmware/dfu/iBEC.test.im4p"}},
            "RestoreDeviceTree": {"Info": {"Path": "Firmware/all_flash/DeviceTree.test.im4p"}},
            "RestoreKernelCache": {"Info": {"Path": "kernelcache.test"}},
            "RestoreRamDisk": {"Info": {"Path": "restore.dmg"}},
        },
    }],
}
with zipfile.ZipFile(ipsw, "w") as archive:
    archive.writestr("BuildManifest.plist", plistlib.dumps(manifest))

# The same tiny archive with the RC build ID proves the reviewed profile is
# selected from plist identity without relying on the IPSW filename.
rc_manifest = dict(manifest)
rc_manifest["ProductBuildVersion"] = "24A435"
with zipfile.ZipFile(rc_ipsw, "w") as archive:
    archive.writestr("BuildManifest.plist", plistlib.dumps(rc_manifest))

d431_manifest = copy.deepcopy(manifest)
d431_manifest["ProductVersion"] = "27.0.1"
d431_manifest["ProductBuildVersion"] = "24A446"
d431_manifest["SupportedProductTypes"] = ["iPhone12,3", "iPhone12,5"]
d431_manifest["BuildIdentities"][0]["ApBoardID"] = "0x02"
d431_manifest["BuildIdentities"][0]["Info"]["DeviceClass"] = "d431ap"
with zipfile.ZipFile(d431_ipsw, "w") as archive:
    archive.writestr("BuildManifest.plist", plistlib.dumps(d431_manifest))

# 24A437 ships one IPSW for both Pro boards, so its manifest carries two build
# identities and two profiles match it. Liter8 cannot tell which phone is
# attached from the archive, so it has to ask rather than pick.
dual_manifest = copy.deepcopy(manifest)
dual_manifest["ProductVersion"] = "27.0"
dual_manifest["ProductBuildVersion"] = "24A437"
dual_manifest["SupportedProductTypes"] = ["iPhone12,3", "iPhone12,5"]
d421_identity = copy.deepcopy(dual_manifest["BuildIdentities"][0])
d421_identity["ApBoardID"] = "0x06"
d421_identity["Info"]["DeviceClass"] = "d421ap"
d431_identity = copy.deepcopy(dual_manifest["BuildIdentities"][0])
d431_identity["ApBoardID"] = "0x02"
d431_identity["Info"]["DeviceClass"] = "d431ap"
dual_manifest["BuildIdentities"] = [d421_identity, d431_identity]
with zipfile.ZipFile(dual_ipsw, "w") as archive:
    archive.writestr("BuildManifest.plist", plistlib.dumps(dual_manifest))

# The manifest is valid, but extraction must reject the parent traversal before
# it can write outside Liter8's staging directory.
with zipfile.ZipFile(bad_ipsw, "w") as archive:
    archive.writestr("BuildManifest.plist", plistlib.dumps(manifest))
    archive.writestr("../escaped", b"must not be written")

(work.parent / "resources" / "requirements.txt").write_text("# explicit test Python needs no packages\n")
(work.parent / "resources" / "scripts" / "verify_cfw.py").write_text('''
import os
from pathlib import Path
expected = Path.cwd() / "iPhone12,1_27.0_24A5390f_Restore"
assert Path(os.environ["IPSW_SRC"]).resolve() == expected.resolve()
assert Path(os.environ["LITER8_RESOURCE_DIR"]).resolve() == Path(__file__).resolve().parent.parent
context = Path(os.environ["LITER8_CONTEXT"])
assert context.resolve() == (Path.cwd() / "context.json").resolve()
document = __import__("json").loads(context.read_text())
assert document["schema"] == 3
assert document["components"]["iBSS"] == "Firmware/dfu/iBSS.test.im4p"
assert document["bootPlan"] == {
    "normalIBSSAdditionalPlans": ["ibss-skip-display-init"],
    "restoreIBSSAdditionalPlans": ["ibss-skip-display-init"],
    "firmwareComponents": [
        "RestoreLogo", "ANE", "AOP", "AVE", "Ap,SecurePageTableMonitor",
        "GFX", "ISP", "PMP", "SIO", "WCHFirmwareUpdater", "SEP",
    ],
    "normalTrustCache": "RestoreTrustCache",
}
''')
PY

# Resource discovery and firmware outputs must not depend on the directory from
# which the operator happened to launch Liter8.
cd "$RUN_DIR"

# --file must beat the deliberately wrong IPSW_FILE inherited by the CLI.
IPSW_FILE=/deliberately/wrong.ipsw WORK_DIR="$WORK_DIR" \
    "$PATCHER" fw prepare --file "$IPSW_FILE"

test -f "$WORK_DIR/iPhone12,1_27.0_24A5390f_Restore/.extract-complete"

WORK_DIR="$RC_WORK_DIR" "$PATCHER" fw prepare --file "$RC_IPSW_FILE"
test -f "$RC_WORK_DIR/iPhone12,1_27.0_24A435_Restore/.extract-complete"

if "$PATCHER" fw prepare --file "$D431_IPSW_FILE" --work-dir "$D431_WORK_DIR" > "$TEST_ROOT/d431-refusal.log" 2>&1; then
    echo "D431 unexpectedly accepted without --experimental" >&2
    exit 1
fi
grep -q 'is experimental; rerun with --experimental' "$TEST_ROOT/d431-refusal.log"
"$PATCHER" fw prepare --file "$D431_IPSW_FILE" --work-dir "$D431_WORK_DIR" --experimental > "$TEST_ROOT/d431-opt-in.log"
grep -q 'firmware profile: iphone12,5-d431ap-24A446' "$TEST_ROOT/d431-opt-in.log"

# A dual-board IPSW matches two profiles. Picking one silently would hand a
# phone the other board's boot plan and iBSS, so this must refuse and say how.
if "$PATCHER" fw prepare --file "$DUAL_IPSW_FILE" --work-dir "$DUAL_WORK_DIR" --experimental \
    > "$TEST_ROOT/dual-refusal.log" 2>&1; then
    echo "dual-board IPSW unexpectedly accepted without --board" >&2
    exit 1
fi
grep -q 'several boards' "$TEST_ROOT/dual-refusal.log"
grep -q 'd421ap, d431ap' "$TEST_ROOT/dual-refusal.log"
grep -q -- '--board' "$TEST_ROOT/dual-refusal.log"

# Each board selects its own profile, never the other's.
for board_case in "d421ap:iphone12,3-d421ap-24A437" "d431ap:iphone12,5-d431ap-24A437"; do
    board="${board_case%%:*}"
    expected="${board_case##*:}"
    rm -rf "$DUAL_WORK_DIR" && mkdir -p "$DUAL_WORK_DIR"
    "$PATCHER" fw prepare --file "$DUAL_IPSW_FILE" --work-dir "$DUAL_WORK_DIR" \
        --experimental --board "$board" > "$TEST_ROOT/dual-$board.log"
    grep -q "firmware profile: $expected" "$TEST_ROOT/dual-$board.log"
done

# A board this IPSW does not carry is a typo, so name the ones it does.
if "$PATCHER" fw prepare --file "$DUAL_IPSW_FILE" --work-dir "$DUAL_WORK_DIR" \
    --experimental --board n104ap > "$TEST_ROOT/dual-wrong-board.log" 2>&1; then
    echo "unknown --board unexpectedly accepted" >&2
    exit 1
fi

# A single-board IPSW must still work with no --board at all.
grep -q 'firmware profile: iphone12,5-d431ap-24A446' "$TEST_ROOT/d431-opt-in.log"

if WORK_DIR="$BAD_WORK_DIR" "$PATCHER" fw prepare --file "$BAD_IPSW_FILE"; then
    echo "unsafe IPSW member unexpectedly extracted" >&2
    exit 1
fi
test ! -e "$BAD_WORK_DIR/escaped"

# The validated work tree must beat a stale legacy IPSW_SRC value.
IPSW_SRC=/deliberately/wrong-tree WORK_DIR="$WORK_DIR" \
    "$PATCHER" fw verify-cfw --python /usr/bin/python3 --resource-dir "$RESOURCE_DIR"

echo "fw workflow integration: passed"
