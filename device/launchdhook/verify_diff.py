#!/usr/bin/env python3
"""Prove a patched launchd differs from stock in exactly the intended places.

`codesign -v` passing says the signature is self-consistent. It does not say we
changed only what we meant to change. A stray write elsewhere in the file would
still validate, because the fixup recomputes whatever is there.

So this compares byte ranges instead. Four regions are expected to differ:

  offset 16          ncmds, one higher
  offset 20          sizeofcmds, larger by the command size
  end of commands    the appended LC_LOAD_WEAK_DYLIB itself
  two code slots     SHA-256 of the header page and the command page

Anything else that differs is a bug, and this exits non-zero if it finds one.

    ./verify_diff.py launchd.orig .dev_launchd
"""

import hashlib
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import resign_pagehashes
import patch_launchd

HOOK_PATH = "/usr/lib/lhook.dylib"


def changed_ranges(a, b):
    """Yield (start, end) for every maximal run of differing bytes."""
    if len(a) != len(b):
        raise SystemExit(f"size differs: {len(a)} vs {len(b)}")
    start = None
    for i in range(len(a)):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            yield (start, i)
            start = None
    if start is not None:
        yield (start, len(a))


def expected_regions(stock, patched):
    """Build the set of byte ranges we intended to change, from the files themselves."""
    ncmds_old, size_old = struct.unpack_from("<II", stock, 16)
    ncmds_new, size_new = struct.unpack_from("<II", patched, 16)

    command = patch_launchd.build_command(HOOK_PATH)
    if ncmds_new != ncmds_old + 1:
        raise SystemExit(f"ncmds is {ncmds_old} -> {ncmds_new}, expected exactly +1")
    if size_new != size_old + len(command):
        raise SystemExit(f"sizeofcmds is {size_old} -> {size_new}, expected +{len(command)}")

    command_start = 32 + size_old
    command_end = command_start + len(command)
    if stock[command_start:command_end] != bytes(len(command)):
        raise SystemExit("stock load-command pre-image is not zero padding")
    if patched[command_start:command_end] != command:
        raise SystemExit(f"appended command is not the exact weak load for {HOOK_PATH}")

    regions = {
        (16, 20): f"ncmds {ncmds_old} -> {ncmds_new}",
        (20, 24): f"sizeofcmds {size_old} -> {size_new}",
    }

    regions[(command_start, command_end)] = \
        f"appended load command ({command_end - command_start} bytes)"

    # Code slots for every page whose contents moved.
    sig_offset, _ = resign_pagehashes.find_code_signature(patched)
    for cd in resign_pagehashes.find_code_directories(patched, sig_offset):
        (_, _, _, _, hash_offset, _, _, n_code,
         code_limit, hash_size, _, _, page_shift, _) = \
            struct.unpack_from(">IIIIIIIIIBBBBI", patched, cd)
        page_size = 1 << page_shift
        slots_base = cd + hash_offset
        for page in {16 // page_size, command_start // page_size,
                     (command_end - 1) // page_size}:
            if page >= n_code:
                continue
            at = slots_base + page * hash_size
            regions[(at, at + hash_size)] = f"code slot {page} (page hash)"
    return regions


def main():
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <stock> <patched>")

    stock = pathlib.Path(sys.argv[1]).read_bytes()
    patched = pathlib.Path(sys.argv[2]).read_bytes()

    expected = expected_regions(stock, patched)
    actual = list(changed_ranges(stock, patched))

    print(f"file size        {len(stock)} both\n")
    print("permitted regions:")
    for (start, end), text in sorted(expected.items()):
        print(f"      0x{start:06x}..0x{end:06x}  {end - start:>4} bytes  {text}")

    # Membership is tested per byte against the union of permitted regions.
    # Testing containment per run is wrong: two adjacent code slots form one
    # contiguous permitted area, and a changed run that crosses the boundary
    # between them belongs to neither run individually while still being fine.
    permitted = set()
    for start, end in expected:
        permitted.update(range(start, end))

    print("\nchanged regions:")
    unexpected = []
    for start, end in actual:
        labels = {text for (e_start, e_end), text in expected.items()
                  if start < e_end and end > e_start}
        stray = [i for i in range(start, end) if i not in permitted]
        mark = "!!!" if stray else "OK "
        note = ", ".join(sorted(labels)) if labels else "UNEXPECTED"
        if stray:
            note = f"{len(stray)} byte(s) outside every permitted region"
        print(f"  {mark} 0x{start:06x}..0x{end:06x}  {end - start:>4} bytes  {note}")
        if stray:
            unexpected.append((start, end))

    print()
    total = sum(e - s for s, e in actual)
    print(f"total bytes differing: {total} across {len(actual)} region(s)")

    # The page hashes must actually be correct, not merely present.
    sig_offset, _ = resign_pagehashes.find_code_signature(bytearray(patched))
    check = bytearray(patched)
    stale = 0
    for cd in resign_pagehashes.find_code_directories(check, sig_offset):
        stale += resign_pagehashes.rehash_directory(check, cd, verbose=False)
    print(f"stale page hashes:     {stale} (must be 0)")

    if unexpected:
        raise SystemExit(f"\nFAIL: {len(unexpected)} unexpected changed region(s)")
    if stale:
        raise SystemExit("\nFAIL: page hashes do not match the file contents")
    print("\nPASS: only the intended bytes differ, and the hashes are correct")


if __name__ == "__main__":
    main()
