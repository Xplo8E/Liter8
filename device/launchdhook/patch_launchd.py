#!/usr/bin/env python3
"""Append a weak LC_LOAD_DYLIB to a Mach-O so dyld loads a hook at process start.

This is the vphone route to system-wide injection. Instead of fighting the
DYLD_INSERT_LIBRARIES restriction (which launchd strips from job environments
anyway), the hook becomes an ordinary linked dependency of /sbin/launchd. dyld
loads it before main() at PID 1 start, with no environment variable involved.

LC_LOAD_WEAK_DYLIB rather than LC_LOAD_DYLIB is what makes this survivable on a
tethered device: if the dylib is missing or unloadable, dyld continues instead of
failing the process, and PID 1 failing to launch is an unbootable device.

The command has to fit in the zero padding between the end of the existing load
commands and the start of the first __TEXT section. launchd on 24A5390f has 48
bytes there, which caps the path at 23 characters. That is why the reference
implementation uses a two-character path; it is not a stylistic choice.

The hook must live on the System volume. At the moment dyld resolves launchd's
dependencies the Data volume is not mounted yet, so /var/jb is not reachable.

    ./patch_launchd.py launchd.orig -o launchd.patched --apply
"""

import argparse
import pathlib
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
HEADER_SIZE = 32
LC_REQ_DYLD = 0x80000000
LC_SEGMENT_64 = 0x19
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
DYLIB_COMMAND_SIZE = 24
SECTION_64_SIZE = 80
SEGMENT_64_HEADER_SIZE = 72


def parse_header(blob):
    """Return (ncmds, sizeofcmds) after validating this is a 64-bit Mach-O."""
    if len(blob) < HEADER_SIZE:
        raise ValueError("file is too small to hold a Mach-O header")
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from("<8I", blob, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f"not a 64-bit Mach-O: magic 0x{magic:08x}")
    return ncmds, sizeofcmds


def first_text_section_offset(blob, ncmds):
    """Return the lowest file offset of any section in __TEXT.

    That offset is the ceiling for the load commands: everything between the end
    of the commands and it is padding we can claim.
    """
    offset = HEADER_SIZE
    lowest = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, offset)
        if cmd == LC_SEGMENT_64:
            segname = blob[offset + 8:offset + 24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", blob, offset + 64)[0]
            if segname == "__TEXT":
                section = offset + SEGMENT_64_HEADER_SIZE
                for _ in range(nsects):
                    sect_offset = struct.unpack_from("<I", blob, section + 48)[0]
                    if lowest is None or sect_offset < lowest:
                        lowest = sect_offset
                    section += SECTION_64_SIZE
        offset += cmdsize
    if lowest is None:
        raise ValueError("no __TEXT sections found")
    return lowest


def already_loads(blob, ncmds, path):
    """True if the binary already carries a load command naming this path."""
    offset = HEADER_SIZE
    encoded = path.encode()
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, offset)
        if cmd in (0x0C, LC_LOAD_WEAK_DYLIB):
            name_offset = struct.unpack_from("<I", blob, offset + 8)[0]
            name = blob[offset + name_offset:offset + cmdsize].rstrip(b"\0")
            if name == encoded:
                return True
        offset += cmdsize
    return False


def build_command(path):
    """Build an 8-byte-aligned LC_LOAD_WEAK_DYLIB naming path."""
    encoded = path.encode() + b"\0"
    cmdsize = (DYLIB_COMMAND_SIZE + len(encoded) + 7) & ~7
    command = struct.pack(
        "<IIIIII",
        LC_LOAD_WEAK_DYLIB,
        cmdsize,
        DYLIB_COMMAND_SIZE,   # name offset, immediately after the struct
        0,                    # timestamp
        0x00010000,           # current_version 1.0.0
        0x00010000,           # compatibility_version 1.0.0
    )
    return command + encoded.ljust(cmdsize - DYLIB_COMMAND_SIZE, b"\0")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="input Mach-O, never modified in place")
    parser.add_argument("-o", "--output", help="where to write the patched copy")
    parser.add_argument("--path", default="/usr/lib/lhook.dylib",
                        help="dylib path to load (default: %(default)s)")
    parser.add_argument("--apply", action="store_true",
                        help="write the output; without it this only reports")
    args = parser.parse_args()

    blob = bytearray(pathlib.Path(args.binary).read_bytes())
    ncmds, sizeofcmds = parse_header(blob)

    end_of_commands = HEADER_SIZE + sizeofcmds
    ceiling = first_text_section_offset(blob, ncmds)
    slack = ceiling - end_of_commands

    command = build_command(args.path)

    print(f"input            {args.binary} ({len(blob)} bytes)")
    print(f"ncmds            {ncmds}")
    print(f"sizeofcmds       {sizeofcmds} (0x{sizeofcmds:x})")
    print(f"end of commands  0x{end_of_commands:x}")
    print(f"first __TEXT sec 0x{ceiling:x}")
    print(f"slack            {slack} bytes")
    print(f"new command      LC_LOAD_WEAK_DYLIB '{args.path}' ({len(command)} bytes)")

    if already_loads(blob, ncmds, args.path):
        sys.exit(f"[!] {args.path} is already a load command; refusing to add it twice")

    if len(command) > slack:
        sys.exit(f"[!] needs {len(command)} bytes, only {slack} available. "
                 f"Path must be at most {slack - DYLIB_COMMAND_SIZE - 1} characters.")

    padding = blob[end_of_commands:ceiling]
    if padding != bytes(slack):
        sys.exit("[!] the region after the load commands is not zero padding; refusing")

    print(f"[+] fits, {slack - len(command)} bytes of padding left over")

    if not args.apply:
        print("\ndry run, nothing written. Re-run with --apply")
        return

    if not args.output:
        sys.exit("[!] --apply needs -o/--output")

    blob[end_of_commands:end_of_commands + len(command)] = command
    struct.pack_into("<II", blob, 16, ncmds + 1, sizeofcmds + len(command))

    out = pathlib.Path(args.output)
    out.write_bytes(bytes(blob))
    print(f"\n[+] wrote {out} ({len(blob)} bytes, size unchanged)")
    print(f"    ncmds {ncmds} -> {ncmds + 1}, sizeofcmds {sizeofcmds} -> {sizeofcmds + len(command)}")
    print( "    next: re-sign it, the signature no longer covers page 0")


if __name__ == "__main__":
    main()
