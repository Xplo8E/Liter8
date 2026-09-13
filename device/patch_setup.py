#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_setup.py — patch EVERY -[* controllerNeedsToRun] in the iOS
Setup (purplebuddy) binary to `mov w0,#0 ; ret` (return NO), so the flow
controller skips all panes and Setup completes immediately.

Why: each Setup pane (Apple ID, Siri, iCloud, Terms, Payment, CloudConfig,
Messages/FaceTime, Proximity, ...) has its own controllerNeedsToRun. On a
research VM most of them do async Apple-server work that never completes ->
infinite spinner. Skipping ONE just moves the hang to the previous pane
(whack-a-mole). Making them ALL return NO removes every optional pane at once.

Re-derives the IMPs from ObjC metadata (no hardcoded offsets), so it survives
minor binary differences. arm64e, small (relative) method lists.

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

import sys, struct, argparse, shutil

BASE = 0x100000000
MOV_W0_0 = 0x52800000   # mov w0, #0
RET      = 0xD65F03C0   # ret


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
                segs.append({"name": nm, "addr": addr, "size": size, "off": offv})
                so += 80
        off += cs
    return segs


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("setup", help="path to the Setup Mach-O (Setup.app/Setup)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="write patches (creates .bak)")
    mode.add_argument("--verify", action="store_true", help="require every selected method to be patched")
    ap.add_argument("--keep", default="",
                    help="comma-separated class names to NOT skip "
                         "(e.g. ActivationController,BuddyLocaleController)")
    args = ap.parse_args(argv)
    keep = set(x.strip() for x in args.keep.split(",") if x.strip())

    d = bytearray(open(args.setup, "rb").read())
    segs = parse_segs(d)

    def va2off(v):
        for s in segs:
            if s["off"] and s["addr"] <= v < s["addr"] + s["size"]:
                return s["off"] + (v - s["addr"])
        return None

    def off2va(o):
        for s in segs:
            if s["off"] and s["off"] <= o < s["off"] + s["size"]:
                return s["addr"] + (o - s["off"])
        return None

    def rd(va):
        o = va2off(va)
        if o is None:
            return None
        e = d.find(b"\x00", o)
        try:
            return bytes(d[o:e]).decode()
        except Exception:
            return None

    def ptr_t(va):
        o = va2off(va)
        return None if o is None else BASE + (struct.unpack_from("<Q", d, o)[0] & 0xFFFFFFFF)

    def methods_of(ro):
        ml = ptr_t(ro + 0x20)
        if ml is None:
            return {}
        mo = va2off(ml)
        if mo is None:
            return {}
        ent, cnt = struct.unpack_from("<II", d, mo)
        small = bool(ent & 0x80000000)
        esz = ent & 0xFFFF
        out = {}
        for k in range(cnt):
            eo = mo + 8 + k * esz
            if small:
                noff, toff, ioff = struct.unpack_from("<iii", d, eo)
                sel = rd(ptr_t(off2va(eo) + noff))
                imp = (off2va(eo) + 8) + ioff
            else:
                npv, tpv, ipv = struct.unpack_from("<QQQ", d, eo)
                sel = rd(BASE + (npv & 0xFFFFFFFF))
                imp = BASE + (ipv & 0xFFFFFFFF)
            if sel:
                out[sel] = imp
        return out

    classlist = next(s for s in segs if s["name"] == "__objc_classlist")
    targets = []
    for i in range(0, classlist["size"], 8):
        clsptr = ptr_t(classlist["addr"] + i)
        if clsptr is None:
            continue
        cof = va2off(clsptr)
        if cof is None:
            continue
        data = struct.unpack_from("<Q", d, cof + 0x20)[0]
        ro = BASE + ((data & 0xFFFFFFFF) & ~0x7)
        ms = methods_of(ro)
        if "controllerNeedsToRun" in ms:
            nm = rd(ptr_t(ro + 0x18)) or "?"
            targets.append((nm, ms["controllerNeedsToRun"]))
    # dedupe
    seen = set(); uniq = []
    for nm, imp in targets:
        if imp in seen:
            continue
        seen.add(imp); uniq.append((nm, imp))
    uniq.sort(key=lambda x: x[1])
    if not uniq:
        print("[!] no controllerNeedsToRun implementations found", file=sys.stderr)
        return 1

    print(f"[*] {len(uniq)} classes implement controllerNeedsToRun")
    patched = 0
    for nm, imp in uniq:
        o = va2off(imp)
        if nm in keep:
            print(f"    KEEP  {nm:44s} @ {imp:#x}")
            continue
        print(f"    skip  {nm:44s} IMP={imp:#x} fileoff={o:#x} -> mov w0,#0; ret")
        if args.apply:
            struct.pack_into("<I", d, o, MOV_W0_0)
            struct.pack_into("<I", d, o + 4, RET)
        patched += 1

    selected = [(nm, imp) for nm, imp in uniq if nm not in keep]
    if args.verify:
        ok = all(struct.unpack_from("<II", d, va2off(imp)) == (MOV_W0_0, RET)
                 for _, imp in selected)
        print(f"\n[{'+' if ok else '!'}] verify={ok} ({len(selected)} methods)")
        return 0 if ok else 1
    if args.apply:
        shutil.copyfile(args.setup, args.setup + ".bak")
        open(args.setup, "wb").write(d)
        # verify
        d2 = open(args.setup, "rb").read()
        ok = all(struct.unpack_from("<II", d2, va2off(imp)) == (MOV_W0_0, RET)
                 for _, imp in selected)
        print(f"\n[+] patched {patched} methods (backup: {args.setup}.bak)  verify={ok}")
        print("[!] now: re-sign / snapshot as needed, then  killall -9 Setup")
        if not ok:
            return 1
    else:
        print(f"\n[dry-run] would patch {patched} methods. re-run with --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
