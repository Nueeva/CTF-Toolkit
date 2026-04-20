from __future__ import annotations

import struct


def p32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def u32(data: bytes) -> int:
    if len(data) != 4:
        raise ValueError("u32 requires 4 bytes")
    return struct.unpack("<I", data)[0]


def u64(data: bytes) -> int:
    if len(data) != 8:
        raise ValueError("u64 requires 8 bytes")
    return struct.unpack("<Q", data)[0]
