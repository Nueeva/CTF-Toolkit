from __future__ import annotations

import re
import struct


def assemble_memory_frag_headers(data: bytes, header: bytes = b"FRAGHDR\x00") -> bytes:
    """
    Parse a memory fragment container with header [8 bytes header][off1, off2, len1, len2: <IIII]
    and reconstruct the payload from the two memory regions.
    """
    if not data.startswith(header):
        idx = data.find(header)
        if idx != -1:
            data = data[idx:]
        else:
            raise ValueError("Header not found")

    hdr_len = len(header)
    off1, off2, len1, len2 = struct.unpack("<IIII", data[hdr_len : hdr_len + 16])
    part1 = data[off1 : off1 + len1]
    part2 = data[off2 : off2 + len2]
    return part1 + part2


def extract_memory_dump_xor(data: bytes, key: int = 0x3C, pattern: bytes = rb"(?:GETSFLAG|FLAG)\{[^}]+\}") -> list[str]:
    """
    Decrypt single-byte XOR obfuscated memory heap dump and extract matching flags.
    """
    decrypted = bytes(b ^ key for b in data)
    matches = re.findall(pattern, decrypted)
    return [m.decode("utf-8", errors="ignore") for m in matches]
