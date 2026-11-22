from __future__ import annotations

import re
import struct


def extract_mov_stack_strings(asm_or_bytes: str | bytes) -> list[str]:
    """
    Reconstruct stack strings built via x86/x64 immediate MOV / MOVABS instructions
    (e.g. `mov DWORD PTR [rbp-0x20], 0x53544547` or `movabs rax, 0x...`) in disassembly text
    or raw binary sequences. Supports out-of-order stack-offset assignments.
    """
    if isinstance(asm_or_bytes, bytes):
        text = asm_or_bytes.decode("latin-1", errors="ignore")
    else:
        text = asm_or_bytes

    # 1. Offset-aware reconstruction for `[rbp-0x20], 0x...` or `[rsp+0x10], 0x...`
    offset_pattern = re.compile(
        r"\[(?P<base>rbp|ebp|rsp|esp)\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-fA-F]+|\d+)\]\s*,\s*0x(?P<imm>[0-9a-fA-F]{2,16})",
        re.IGNORECASE,
    )
    offset_entries: list[tuple[int, int, bytes]] = []
    for idx, m in enumerate(offset_pattern.finditer(text)):
        sign = -1 if m.group("sign") == "-" else 1
        disp = int(m.group("disp"), 0) * sign
        imm = m.group("imm")
        if len(imm) % 2 != 0:
            imm = "0" + imm
        raw_be = bytes.fromhex(imm)
        raw_le = raw_be[::-1]
        if all(32 <= b <= 126 or b == 0 for b in raw_le):
            offset_entries.append((disp, idx, raw_le.rstrip(b"\x00")))
        elif all(32 <= b <= 126 or b == 0 for b in raw_be):
            offset_entries.append((disp, idx, raw_be.rstrip(b"\x00")))

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

    results = [c.decode("latin-1") for c in chunks if c]
    combined = b"".join(chunks).decode("latin-1", errors="ignore")
    if combined and combined not in results:
        results.insert(0, combined)

    if len(offset_entries) >= 2:
        offset_entries.sort(key=lambda item: (item[0], item[1]))
        sorted_str = b"".join(item[2] for item in offset_entries).decode("latin-1", errors="ignore")
        if sorted_str and sorted_str not in results:
            results.insert(0, sorted_str)
        elif sorted_str in results and results[0] != sorted_str:
            results.remove(sorted_str)
            results.insert(0, sorted_str)

    return results
