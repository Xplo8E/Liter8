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
BAD_WORK_DIR="$TEST_ROOT/bad-work"
BAD_IPSW_FILE="$TEST_ROOT/traversal.ipsw"
RESOURCE_DIR="$TEST_ROOT/resources"
RUN_DIR="$TEST_ROOT/unrelated-current-directory"
mkdir -p "$WORK_DIR" "$RC_WORK_DIR" "$BAD_WORK_DIR" "$RESOURCE_DIR/scripts" "$RUN_DIR"

/usr/bin/python3 - "$IPSW_FILE" "$RC_IPSW_FILE" "$BAD_IPSW_FILE" "$WORK_DIR" <<'PY'
import plistlib
import sys
import zipfile
from pathlib import Path

ipsw = Path(sys.argv[1])
rc_ipsw = Path(sys.argv[2])
bad_ipsw = Path(sys.argv[3])
work = Path(sys.argv[4])
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
assert document["schema"] == 2
assert document["components"]["iBSS"] == "Firmware/dfu/iBSS.test.im4p"
assert document["bootPlan"] == {
    "normalIBSSAdditionalPlans": ["ibss-skip-display-init"],
    "restoreIBSSAdditionalPlans": ["ibss-skip-display-init"],
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

if WORK_DIR="$BAD_WORK_DIR" "$PATCHER" fw prepare --file "$BAD_IPSW_FILE"; then
    echo "unsafe IPSW member unexpectedly extracted" >&2
    exit 1
fi
test ! -e "$BAD_WORK_DIR/escaped"

# The validated work tree must beat a stale legacy IPSW_SRC value.
IPSW_SRC=/deliberately/wrong-tree WORK_DIR="$WORK_DIR" \
    "$PATCHER" fw verify-cfw --python /usr/bin/python3 --resource-dir "$RESOURCE_DIR"

echo "fw workflow integration: passed"
