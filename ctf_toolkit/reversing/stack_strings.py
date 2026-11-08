from __future__ import annotations

import re
import struct


def extract_mov_stack_strings(asm_or_bytes: str | bytes) -> list[str]:
    """
    Reconstruct stack strings built via x86/x64 immediate MOV / MOVABS instructions
    (e.g. `mov DWORD PTR [rbp-0x20], 0x53544547` or `movabs rax, 0x...`) in disassembly text
    or raw binary sequences.
    """
    if isinstance(asm_or_bytes, bytes):
        text = asm_or_bytes.decode("latin-1", errors="ignore")
    else:
        text = asm_or_bytes

    hex_literals = re.findall(r"0x([0-9a-fA-F]{2,16})", text)
    chunks: list[bytes] = []
    for h in hex_literals:
        if len(h) % 2 != 0:
            h = "0" + h
        raw_be = bytes.fromhex(h)
        raw_le = raw_be[::-1]
        if all(32 <= b <= 126 or b == 0 for b in raw_le):
            chunks.append(raw_le.rstrip(b"\x00"))
        elif all(32 <= b <= 126 or b == 0 for b in raw_be):
            chunks.append(raw_be.rstrip(b"\x00"))

    combined = b"".join(chunks).decode("latin-1", errors="ignore")
    results = [c.decode("latin-1") for c in chunks if c]
    if combined and combined not in results:
        results.insert(0, combined)
    return results
