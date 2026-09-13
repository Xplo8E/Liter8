#!/usr/bin/env python3
"""Recompute a Mach-O's code-slot page hashes in place, preserving every other blob.

Re-signing launchd with ldid works but throws away 18KB of stock signing data:
the parent and responsible launch-constraint blobs (special slots 8 and 9) are
dropped and the requirements blob is rebuilt. None of that is needed for the
device to boot, since proc_check_launch_constraints is patched to return 0, but
discarding blobs changes more than the one thing we meant to change.

This does the minimum instead. Appending a load command dirties exactly two
pages, the header page and the page holding the new command, so only their
SHA-256 code slots are stale. Recomputing every code slot fixes those and is
a no-op for the rest, which also makes the tool correct for any edit below
codeLimit rather than only this one.

The CDHash changes as a result, and that is fine: AMFIIsCDHashInTrustCache is
patched to return 1, so any hash is trusted. Nothing re-signs the CMS blob
because the binary is ad-hoc signed and has no CMS signature to invalidate.

Verification is `codesign -v`, which walks these same slots. If it passes, the
hashes are right.

    ./resign_pagehashes.py launchd.patched --apply
"""

import argparse
import hashlib
import pathlib
import struct
import sys

LC_CODE_SIGNATURE = 0x1D
MH_MAGIC_64 = 0xFEEDFACF
HEADER_SIZE = 32
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0

HASHERS = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256}


def find_code_signature(blob):
    """Return (offset, size) of the LC_CODE_SIGNATURE payload in __LINKEDIT."""
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<8I", blob, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f"not a 64-bit Mach-O: magic 0x{magic:08x}")

    offset = HEADER_SIZE
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, offset)
        if cmd == LC_CODE_SIGNATURE:
            return struct.unpack_from("<II", blob, offset + 8)
        offset += cmdsize
    raise ValueError("no LC_CODE_SIGNATURE")


def find_code_directories(blob, sig_offset):
    """Return the absolute file offset of every CodeDirectory in the SuperBlob.

    A binary can carry more than one (sha1 and sha256 for older targets), and
    every one of them hashes the same pages, so all must be updated together.
    """
    magic, _, count = struct.unpack_from(">III", blob, sig_offset)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError(f"not an embedded signature SuperBlob: 0x{magic:08x}")

    directories = []
    for i in range(count):
        _, blob_offset = struct.unpack_from(">II", blob, sig_offset + 12 + i * 8)
        absolute = sig_offset + blob_offset
        if struct.unpack_from(">I", blob, absolute)[0] == CSMAGIC_CODEDIRECTORY:
            directories.append(absolute)
    if not directories:
        raise ValueError("SuperBlob contains no CodeDirectory")
    return directories


def rehash_directory(blob, cd_offset, verbose):
    """Rewrite every code-slot hash in one CodeDirectory. Returns slots changed."""
    (_, _, version, _, hash_offset, _, n_special, n_code,
     code_limit, hash_size, hash_type, _, page_shift, _) = \
        struct.unpack_from(">IIIIIIIIIBBBBI", blob, cd_offset)

    hasher = HASHERS.get(hash_type)
    if hasher is None:
        raise ValueError(f"unsupported hash type {hash_type}")

    page_size = 1 << page_shift if page_shift else code_limit
    slots_base = cd_offset + hash_offset

    if verbose:
        print(f"    version 0x{version:x} hashType {hash_type} hashSize {hash_size} "
              f"pageSize {page_size}")
        print(f"    codeLimit {code_limit} nCodeSlots {n_code} nSpecialSlots {n_special}")

    changed = 0
    for slot in range(n_code):
        start = slot * page_size
        end = min(start + page_size, code_limit)
        digest = hasher(blob[start:end]).digest()[:hash_size]
        at = slots_base + slot * hash_size
        if blob[at:at + hash_size] != digest:
            blob[at:at + hash_size] = digest
            changed += 1
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="Mach-O to fix up, modified in place with --apply")
    parser.add_argument("--apply", action="store_true",
                        help="write the result; without it this only reports")
    args = parser.parse_args()

    path = pathlib.Path(args.binary)
    blob = bytearray(path.read_bytes())

    sig_offset, sig_size = find_code_signature(blob)
    print(f"LC_CODE_SIGNATURE  offset 0x{sig_offset:x} size {sig_size}")

    directories = find_code_directories(blob, sig_offset)
    print(f"CodeDirectories    {len(directories)}")

    total = 0
    for cd_offset in directories:
        print(f"  CodeDirectory at 0x{cd_offset:x}")
        total += rehash_directory(blob, cd_offset, verbose=True)

    print(f"\nstale code slots   {total}")
    if total == 0:
        print("nothing to do, hashes already match")
        return

    if not args.apply:
        print("\ndry run, nothing written. Re-run with --apply")
        return

    path.write_bytes(bytes(blob))
    print(f"\n[+] rewrote {total} code slot(s) in {path} ({len(blob)} bytes, size unchanged)")
    print( "    verify with: codesign -v <file>")


if __name__ == "__main__":
    main()
