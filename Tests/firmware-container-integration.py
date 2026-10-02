#!/usr/bin/env python3
"""Exercise IM4P repacking with the restricted decoder used by iBoot.

No Apple firmware or XCTest is needed. The repeated 128 KiB block exposes the
0x801/0x891 incompatibility that a macOS-only round-trip fails to detect.
"""

import ctypes
import random
import subprocess
import sys
import tempfile
from pathlib import Path


CLI = Path(sys.argv[1] if len(sys.argv) > 1 else ".build/debug/liter8").resolve()
LIB = ctypes.CDLL("/usr/lib/libcompression.dylib")
for name in ("compression_encode_buffer", "compression_decode_buffer"):
    function = getattr(LIB, name)
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                         ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_size_t


def compress(data: bytes, algorithm: int) -> bytes:
    source = ctypes.create_string_buffer(data)
    destination = ctypes.create_string_buffer(len(data) * 2 + 4096)
    size = LIB.compression_encode_buffer(
        destination, len(destination), source, len(data), None, algorithm
    )
    assert size > 0, "test input compression failed"
    return destination.raw[:size]


def decode_iboot(data: bytes, expected_size: int) -> bytes:
    source = ctypes.create_string_buffer(data)
    destination = ctypes.create_string_buffer(expected_size + 1)
    size = LIB.compression_decode_buffer(
        destination, len(destination), source, len(data), None, 0x891
    )
    return destination.raw[:size]


def tlv(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def integer(value: int) -> bytes:
    return tlv(2, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big"))


def children(data: bytes) -> list[tuple[int, bytes, bytes]]:
    def field(offset: int):
        tag, size = data[offset:offset + 2]
        start = offset + 2
        if size & 0x80:
            count = size & 0x7f
            size = int.from_bytes(data[start:start + count], "big")
            start += count
        end = start + size
        assert end <= len(data)
        return tag, data[start:end], data[offset:end], start, end

    tag, _, _, cursor, end = field(0)
    assert tag == 0x30 and end == len(data)
    result = []
    while cursor < end:
        tag, value, raw, _, cursor = field(cursor)
        assert cursor <= end
        result.append((tag, value, raw))
    return result


def main() -> None:
    original = random.Random(8020).randbytes(128 * 1024) * 4
    # Establish that this input catches the historical bug on this host.
    assert decode_iboot(compress(original, 0x801), len(original)) != original
    packed = compress(original, 0x891)
    assert decode_iboot(packed, len(original)) == original
    payp = tlv(0xa0, tlv(0x30, tlv(0x16, b"PAYP") + tlv(0x31, b"")))
    container = tlv(0x30, b"".join([
        tlv(0x16, b"IM4P"), tlv(0x16, b"krnl"), tlv(0x16, b"test"),
        tlv(4, packed), tlv(0x30, integer(1) + integer(len(original))), payp,
    ]))
    with tempfile.TemporaryDirectory(prefix="liter8-im4p-tests-") as temporary:
        root = Path(temporary)
        source, payload, output = (root / name for name in ("source.im4p", "raw", "out.im4p"))
        source.write_bytes(container)
        # Exercise changed bytes and a changed uncompressed size.
        replacement = b"PATCHED" + original[7:] + b"extra payload"
        payload.write_bytes(replacement)
        subprocess.run([str(CLI), "im4p", "repack", str(source), str(payload), str(output)],
                       check=True, capture_output=True)
        fields = children(output.read_bytes())
        assert [tag for tag, _, _ in fields] == [0x16, 0x16, 0x16, 4, 0x30, 0xa0]
        assert fields[:3] == children(container)[:3]
        assert fields[-1][2] == payp, "PAYP DER child changed"
        descriptor = children(fields[4][2])
        assert [int.from_bytes(value, "big") for _, value, _ in descriptor] == [1, len(replacement)]
        assert decode_iboot(fields[3][1], len(replacement)) == replacement
        print("[pass] modified IM4P decodes with iBoot LZFSE and preserves PAYP")

        payload.write_bytes(b"")
        sentinel = b"previous complete artifact"
        output.write_bytes(sentinel)
        result = subprocess.run([str(CLI), "im4p", "repack", str(source), str(payload), str(output)],
                                capture_output=True)
        assert result.returncode != 0 and output.read_bytes() == sentinel
        print("[pass] failed repack does not replace previous output")


if __name__ == "__main__":
    main()
