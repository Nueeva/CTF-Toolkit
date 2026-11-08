"""Permutation and lightweight x86/ASM emulation helpers for CTF reverse engineering."""
from __future__ import annotations

import re
from typing import Sequence, TypeVar

T = TypeVar("T")


def invert_permutation(p: Sequence[int]) -> list[int]:
    """
    Compute the inverse permutation of p where result[p[i]] = i.
    Handles both 0-indexed and 1-indexed permutations.
    """
    if not p:
        return []
    is_1_indexed = min(p) == 1 and max(p) == len(p)
    n = len(p)
    inv = [0] * n
    for i, val in enumerate(p):
        idx = val - 1 if is_1_indexed else val
        if 0 <= idx < n:
            inv[idx] = i + 1 if is_1_indexed else i
    return inv


def apply_permutation(data: bytes | Sequence[T], p: Sequence[int]) -> bytes | list[T]:
    """
    Rearrange elements of data according to permutation p: output[i] = data[p[i]].
    Supports 0-indexed or 1-indexed permutations.
    """
    is_bytes = isinstance(data, (bytes, bytearray))
    elems = list(data)
    is_1_indexed = bool(p) and min(p) == 1 and max(p) == len(elems)
    res = []
    for idx in p:
        actual_idx = idx - 1 if is_1_indexed else idx
        if 0 <= actual_idx < len(elems):
            res.append(elems[actual_idx])
    return bytes(res) if is_bytes else res


def permute_bits_in_byte(b: int, bit_perm: Sequence[int]) -> int:
    """
    Permute the 8 bits of a byte according to bit_perm (indices 0..7 or 1..8).
    bit_perm[i] specifies which source bit position goes to output bit i.
    """
    is_1_indexed = bool(bit_perm) and min(bit_perm) == 1 and max(bit_perm) == 8
    res = 0
    for out_bit, in_bit in enumerate(bit_perm):
        src = in_bit - 1 if is_1_indexed else in_bit
        bit_val = (b >> src) & 1
        res |= bit_val << out_bit
    return res


def emulate_x86_snippet(
    code: bytes | str,
    initial_regs: dict[str, int] | None = None,
    max_steps: int = 1000,
) -> dict[str, int]:
    """
    Lightweight emulator for straight-line x86/x64 assembly snippets
    (mov, add, sub, xor, rol, ror, inc, dec, shl, shr).
    Supports either machine bytecode (bytes) or mnemonic assembly text (str).
    """
    regs = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0, "ebp": 0, "esp": 0}
    if initial_regs:
        for k, v in initial_regs.items():
            regs[k.lower()] = v & 0xFFFFFFFF

    MASK = 0xFFFFFFFF

    # Text disassembly parsing mode
    if isinstance(code, str):
        steps = 0
        lines = code.splitlines()
        for raw_line in lines:
            if steps >= max_steps:
                break
            line = raw_line.split(";")[0].split("#")[0].strip()
            if not line:
                continue
            steps += 1
            parts = re.split(r"[,\s]+", line)
            op = parts[0].lower()
            if op == "nop":
                continue
            if op in ("inc", "dec") and len(parts) >= 2:
                r = parts[1].lower()
                if r in regs:
                    diff = 1 if op == "inc" else -1
                    regs[r] = (regs[r] + diff) & MASK
                continue
            if len(parts) >= 3:
                r = parts[1].lower()
                val_str = parts[2].lower()
                val = regs[val_str] if val_str in regs else int(val_str, 0) if (val_str.startswith("0x") or val_str.lstrip("-").isdigit()) else 0
                if r not in regs:
                    continue
                if op == "mov":
                    regs[r] = val & MASK
                elif op == "add":
                    regs[r] = (regs[r] + val) & MASK
                elif op == "sub":
                    regs[r] = (regs[r] - val) & MASK
                elif op == "xor":
                    regs[r] = (regs[r] ^ val) & MASK
                elif op == "shl":
                    regs[r] = (regs[r] << (val & 31)) & MASK
                elif op == "shr":
                    regs[r] = (regs[r] >> (val & 31)) & MASK
        return regs

    # Binary machine code emulation mode
    bytecode = bytes(code)
    i = 0
    steps = 0

    while i < len(bytecode) and steps < max_steps:
        steps += 1
        b = bytecode[i]
        if b == 0x90:  # NOP
            i += 1
            continue
        if 0x40 <= b <= 0x47:  # INC
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = reg_names[b - 0x40]
            if r in regs:
                regs[r] = (regs[r] + 1) & MASK
            i += 1
            continue
        if 0x48 <= b <= 0x4F:  # DEC
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = reg_names[b - 0x48]
            if r in regs:
                regs[r] = (regs[r] - 1) & MASK
            i += 1
            continue
        if 0xB8 <= b <= 0xBF and i + 5 <= len(bytecode):  # MOV reg, imm32
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            r = reg_names[b - 0xB8]
            val = int.from_bytes(bytecode[i + 1 : i + 5], "little")
            if r in regs:
                regs[r] = val & MASK
            i += 5
            continue
        if b == 0x81 and i + 6 <= len(bytecode):
            modrm = bytecode[i + 1]
            val = int.from_bytes(bytecode[i + 2 : i + 6], "little")
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if 0xC0 <= modrm <= 0xC7:  # ADD
                r = reg_names[modrm - 0xC0]
                if r in regs:
                    regs[r] = (regs[r] + val) & MASK
                i += 6
                continue
            elif 0xE8 <= modrm <= 0xEF:  # SUB
                r = reg_names[modrm - 0xE8]
                if r in regs:
                    regs[r] = (regs[r] - val) & MASK
                i += 6
                continue
            elif 0xF0 <= modrm <= 0xF7:  # XOR
                r = reg_names[modrm - 0xF0]
                if r in regs:
                    regs[r] = (regs[r] ^ val) & MASK
                i += 6
                continue

        i += 1

    return regs
