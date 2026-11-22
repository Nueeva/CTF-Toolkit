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
    (mov, add, sub, xor, and, or, rol, ror, inc, dec, shl, shr, not, neg, imul, bswap).
    Supports either machine bytecode (bytes) or mnemonic assembly text (str).
    """
    regs = {
        "eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0, "ebp": 0, "esp": 0,
        "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0, "rsi": 0, "rdi": 0, "rbp": 0, "rsp": 0,
        "r8": 0, "r9": 0, "r10": 0, "r11": 0, "r12": 0, "r13": 0, "r14": 0, "r15": 0,
    }
    if initial_regs:
        for k, v in initial_regs.items():
            kl = k.lower()
            mask_k = 0xFFFFFFFFFFFFFFFF if kl.startswith("r") else 0xFFFFFFFF
            regs[kl] = v & mask_k

    MASK32 = 0xFFFFFFFF
    MASK64 = 0xFFFFFFFFFFFFFFFF

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
            if op in ("inc", "dec", "not", "neg", "bswap") and len(parts) >= 2:
                r = parts[1].lower()
                if r in regs:
                    width = 64 if r.startswith("r") else 32
                    rmask = MASK64 if width == 64 else MASK32
                    if op == "inc":
                        regs[r] = (regs[r] + 1) & rmask
                    elif op == "dec":
                        regs[r] = (regs[r] - 1) & rmask
                    elif op == "not":
                        regs[r] = (~regs[r]) & rmask
                    elif op == "neg":
                        regs[r] = (-regs[r]) & rmask
                    elif op == "bswap":
                        b_len = width // 8
                        regs[r] = int.from_bytes(regs[r].to_bytes(b_len, "little"), "big")
                continue
            if len(parts) >= 3:
                r = parts[1].lower()
                val_str = parts[2].lower()
                val = regs[val_str] if val_str in regs else int(val_str, 0) if (val_str.startswith("0x") or val_str.lstrip("-").isdigit()) else 0
                if r not in regs:
                    continue
                width = 64 if r.startswith("r") else 32
                rmask = MASK64 if width == 64 else MASK32
                if op in ("mov", "movabs"):
                    regs[r] = val & rmask
                elif op == "add":
                    regs[r] = (regs[r] + val) & rmask
                elif op == "sub":
                    regs[r] = (regs[r] - val) & rmask
                elif op == "xor":
                    regs[r] = (regs[r] ^ val) & rmask
                elif op == "and":
                    regs[r] = (regs[r] & val) & rmask
                elif op == "or":
                    regs[r] = (regs[r] | val) & rmask
                elif op == "imul":
                    src_val = regs[val_str] if val_str in regs else val
                    if len(parts) >= 4:
                        imm_str = parts[3].lower()
                        imm_v = int(imm_str, 0) if (imm_str.startswith("0x") or imm_str.lstrip("-").isdigit()) else 0
                        regs[r] = (src_val * imm_v) & rmask
                    else:
                        regs[r] = (regs[r] * src_val) & rmask
                elif op == "shl":
                    regs[r] = (regs[r] << (val & (width - 1))) & rmask
                elif op == "shr":
                    regs[r] = (regs[r] >> (val & (width - 1))) & rmask
                elif op == "rol":
                    s = val % width
                    v = regs[r] & rmask
                    regs[r] = ((v << s) | (v >> (width - s))) & rmask if s else v
                elif op == "ror":
                    s = val % width
                    v = regs[r] & rmask
                    regs[r] = ((v >> s) | (v << (width - s))) & rmask if s else v
        return regs

    MASK = MASK32

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
