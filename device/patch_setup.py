#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_setup.py — patch every class-owned -[* controllerNeedsToRun] in the iOS
Setup (purplebuddy) binary to `mov w0,#0 ; ret` (return NO).

Why: each Setup pane (Apple ID, Siri, iCloud, Terms, Payment, CloudConfig,
Messages/FaceTime, Proximity, ...) has its own controllerNeedsToRun. On a
research VM most of them do async Apple-server work that never completes ->
infinite spinner. Skipping ONE just moves the hang to the previous pane
(whack-a-mole). The device-validated beta-4 workflow patched the 65
implementations reachable from __objc_classlist. A raw sweep of
__objc_methlist finds additional structurally valid but unowned lists, so this
tool deliberately does not patch that broader set.

Re-derives the IMPs from class_ro_t and relative method_list_t metadata (no
hardcoded offsets), validates chained selector references, method types and
__text destinations, and can pin the expected count from the firmware profile.

Usage:
    python3 patch_setup.py Setup.app/Setup            # dry-run: list targets
    python3 patch_setup.py Setup.app/Setup --apply    # patch in place (.bak)
    python3 patch_setup.py Setup.app/Setup --verify   # verify every target
    python3 patch_setup.py Setup.app/Setup --apply \
            --keep ActivationController,BuddyLocaleController   # don't skip these

After patching: it must be the binary that is actually LOADED (bake into the
restore / snapshot, or a non-sealed volume), code-signing must pass (TXM
getTrustLevel patch), and relaunch Setup:  killall -9 Setup
"""

import argparse
import json
import shutil
import struct
import sys
from pathlib import Path

BASE = 0x100000000
MOV_W0_0 = 0x52800000   # mov w0, #0
RET      = 0xD65F03C0   # ret
RELATIVE_METHODS = 0x80000000
RELATIVE_METHOD_SIZE = 12


def parse_segs(d):
    magic, cput, cpus, ftype, ncmds = struct.unpack_from("<IiiII", d, 0)
    assert magic == 0xFEEDFACF
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            so = off + 72
            ns = struct.unpack_from("<I", d, off + 64)[0]
            for _ in range(ns):
                nm = d[so:so + 16].split(b"\x00")[0].decode()
                addr, size = struct.unpack_from("<QQ", d, so + 32)
                offv = struct.unpack_from("<I", d, so + 48)[0]
                segs.append({
                    "segment": d[off + 8:off + 24].split(b"\x00")[0].decode(),
                    "name": nm,
                    "addr": addr,
                    "size": size,
                    "off": offv,
                })
                so += 80
        off += cs
    return segs


def discover_targets(data):
    """Return class-owned `controllerNeedsToRun` implementations.

    The broader `__objc_methlist` section also contains valid lists that are
    not installed as base methods of any class in this image. Patching those
    entries would change more behaviour than the device-validated beta-4 flow.
    Start from every `__objc_classlist` entry, require its class and class_ro_t
    to resolve, and then walk only the referenced method_list_t.
    """
    d = data
    segs = parse_segs(d)

    def section(segment, name):
        matches = [s for s in segs if s["segment"] == segment and s["name"] == name]
        if len(matches) != 1:
            raise ValueError(f"expected one {segment},{name} section, found {len(matches)}")
        return matches[0]

    def contains(s, offset, size=1):
        return s["off"] <= offset and offset + size <= s["off"] + s["size"]

    def va2off(va):
        for s in segs:
            if s["off"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s["off"] + (va - s["addr"])
        return None

    def off2va(offset):
        for s in segs:
            if s["off"] and s["off"] <= offset < s["off"] + s["size"]:
                return s["addr"] + (offset - s["off"])
        return None

    def chained_pointer_at(offset):
        if offset is None or offset + 8 > len(d):
            return None
        raw = struct.unpack_from("<Q", d, offset)[0]
        if raw & (1 << 62):  # bind, not a local rebase
            return None
        target = raw & (0xFFFFFFFF if raw & (1 << 63) else 0x7FFFFFFFFFF)
        address = BASE + target
        return address if va2off(address) is not None else None

    def pointer_at_va(va):
        return chained_pointer_at(va2off(va))

    def cstring(va, expected):
        offset = va2off(va)
        if offset is None or not contains(expected, offset):
            return None
        end = d.find(b"\x00", offset, expected["off"] + expected["size"])
        if end < 0:
            return None
        try:
            return bytes(d[offset:end]).decode()
        except UnicodeDecodeError:
            return None

    classlist = section("__DATA_CONST", "__objc_classlist")
    method_lists = section("__TEXT", "__objc_methlist")
    method_names = section("__TEXT", "__objc_methname")
    method_types = section("__TEXT", "__objc_methtype")
    text = section("__TEXT", "__text")

    def methods_of(list_va):
        list_offset = va2off(list_va)
        if list_offset is None or not contains(method_lists, list_offset, 8):
            raise ValueError(f"method list {list_va:#x} is outside __objc_methlist")
        flags, count = struct.unpack_from("<II", d, list_offset)
        entry_size = flags & 0xFFFF
        if not flags & RELATIVE_METHODS or entry_size != RELATIVE_METHOD_SIZE or count == 0:
            raise ValueError(
                f"unsupported method_list_t at {list_va:#x}: flags={flags:#x}, count={count}"
            )
        byte_count = 8 + count * entry_size
        if not contains(method_lists, list_offset, byte_count):
            raise ValueError(f"method_list_t at {list_va:#x} overruns __objc_methlist")

        methods = []
        for index in range(count):
            entry = list_offset + 8 + index * entry_size
            name_delta, types_delta, imp_delta = struct.unpack_from("<iii", d, entry)
            entry_va = off2va(entry)
            if entry_va is None:
                raise ValueError(f"method entry {entry:#x} is not mapped")

            # Relative method names point to a selector-reference slot. That
            # slot is itself a dyld chained rebase to __objc_methname.
            selector_slot = entry_va + name_delta
            selector_va = pointer_at_va(selector_slot)
            selector = cstring(selector_va, method_names) if selector_va else None

            types_va = entry_va + 4 + types_delta
            types = cstring(types_va, method_types)
            implementation_va = entry_va + 8 + imp_delta
            implementation_offset = va2off(implementation_va)
            if implementation_offset is None or not contains(text, implementation_offset, 8):
                raise ValueError(f"method implementation {implementation_va:#x} is outside __text")
            if selector:
                methods.append((selector, types, implementation_va, implementation_offset))
        return methods

    targets = []
    class_count = classlist["size"] // 8
    if classlist["size"] % 8:
        raise ValueError("__objc_classlist size is not pointer-aligned")
    for index in range(class_count):
        class_offset = classlist["off"] + index * 8
        class_va = chained_pointer_at(class_offset)
        class_file_offset = va2off(class_va) if class_va else None
        if class_file_offset is None or class_file_offset + 0x28 > len(d):
            raise ValueError(f"classlist entry {index} does not resolve")

        raw_data = struct.unpack_from("<Q", d, class_file_offset + 0x20)[0]
        if raw_data & (1 << 62):
            raise ValueError(f"classlist entry {index} has a bound class data pointer")
        ro_target = raw_data & (0xFFFFFFFF if raw_data & (1 << 63) else 0x7FFFFFFFFFF)
        ro_va = (BASE + ro_target) & ~0x7
        ro_offset = va2off(ro_va)
        if ro_offset is None or ro_offset + 0x28 > len(d):
            raise ValueError(f"classlist entry {index} has an invalid class_ro_t")

        name_va = chained_pointer_at(ro_offset + 0x18)
        class_name = cstring(name_va, method_names) if name_va else None
        # Swift class names live outside __objc_methname, so accept any mapped
        # NUL-terminated name after first trying the strict ObjC string section.
        if not class_name and name_va:
            name_offset = va2off(name_va)
            end = d.find(b"\x00", name_offset) if name_offset is not None else -1
            if name_offset is not None and end >= 0:
                class_name = bytes(d[name_offset:end]).decode(errors="replace")
        if not class_name:
            raise ValueError(f"classlist entry {index} has no readable name")

        method_list_va = chained_pointer_at(ro_offset + 0x20)
        if method_list_va is None:
            continue
        for selector, types, implementation_va, implementation_offset in methods_of(method_list_va):
            if selector == "controllerNeedsToRun":
                if types != "B16@0:8":
                    raise ValueError(
                        f"{class_name} controllerNeedsToRun has unexpected types {types!r}"
                    )
                targets.append({
                    "class": class_name,
                    "implementation": implementation_va,
                    "offset": implementation_offset,
                    "types": types,
                })

    unique = {target["implementation"]: target for target in targets}
    return sorted(unique.values(), key=lambda target: target["implementation"])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("setup", help="path to the Setup Mach-O (Setup.app/Setup)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="write patches (creates .bak)")
    mode.add_argument("--verify", action="store_true", help="require every selected method to be patched")
    ap.add_argument("--expect-count", type=int,
                    help="refuse if the exact firmware profile's method count differs")
    ap.add_argument("--records", type=Path,
                    help="write the selected class, IMP, pre-image and replacement records")
    ap.add_argument("--keep", default="",
                    help="comma-separated class names to NOT skip "
                         "(e.g. ActivationController,BuddyLocaleController)")
    args = ap.parse_args(argv)
    keep = set(x.strip() for x in args.keep.split(",") if x.strip())

    d = bytearray(open(args.setup, "rb").read())
    try:
        targets = discover_targets(d)
    except (AssertionError, KeyError, struct.error, ValueError) as error:
        print(f"[!] malformed or unsupported Setup metadata: {error}", file=sys.stderr)
        return 1
    uniq = [(target["class"], target["implementation"], target["offset"])
            for target in targets]
    if not uniq:
        print("[!] no controllerNeedsToRun implementations found", file=sys.stderr)
        return 1

    if args.expect_count is not None and len(uniq) != args.expect_count:
        print(
            f"[!] found {len(uniq)} class-owned controllerNeedsToRun methods, "
            f"expected {args.expect_count}",
            file=sys.stderr,
        )
        return 1
    print(f"[*] {len(uniq)} classes implement controllerNeedsToRun")
    patched = 0
    records = []
    for nm, imp, o in uniq:
        if nm in keep:
            print(f"    KEEP  {nm:44s} @ {imp:#x}")
            continue
        print(f"    skip  {nm:44s} IMP={imp:#x} fileoff={o:#x} -> mov w0,#0; ret")
        original = bytes(d[o:o + 8])
        records.append({
            "class": nm,
            "implementation": f"0x{imp:x}",
            "offset": o,
            "originalBytes": original.hex(),
            "replacementBytes": struct.pack("<II", MOV_W0_0, RET).hex(),
        })
        if args.apply:
            struct.pack_into("<I", d, o, MOV_W0_0)
            struct.pack_into("<I", d, o + 4, RET)
        patched += 1

    selected = [(nm, imp, o) for nm, imp, o in uniq if nm not in keep]
    if args.records:
        args.records.parent.mkdir(parents=True, exist_ok=True)
        args.records.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    if args.verify:
        ok = all(struct.unpack_from("<II", d, o) == (MOV_W0_0, RET)
                 for _, _, o in selected)
        print(f"\n[{'+' if ok else '!'}] verify={ok} ({len(selected)} methods)")
        return 0 if ok else 1
    if args.apply:
        shutil.copyfile(args.setup, args.setup + ".bak")
        open(args.setup, "wb").write(d)
        # verify
        d2 = open(args.setup, "rb").read()
        ok = all(struct.unpack_from("<II", d2, o) == (MOV_W0_0, RET)
                 for _, _, o in selected)
        print(f"\n[+] patched {patched} methods (backup: {args.setup}.bak)  verify={ok}")
        print("[!] now: re-sign / snapshot as needed, then  killall -9 Setup")
        if not ok:
            return 1
    else:
        print(f"\n[dry-run] would patch {patched} methods. re-run with --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
