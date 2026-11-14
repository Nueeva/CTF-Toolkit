"""CRC32 forgery: patch four bytes so any message carries a chosen checksum.

CRC is affine over GF(2) in the message bits, so the 32 bits of a 4-byte window
span a linear subspace of the 32-bit checksum space. Solving the resulting 32x32
system over GF(2) gives the exact patch, with no brute force and no dependence on
a specific polynomial beyond zlib's own crc32.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

__all__ = ["CRCForgeResult", "crc32_value", "forge_crc32", "forge_crc32_hex"]


@dataclass
class CRCForgeResult:
    data: bytes
    target: int
    offset: int
    original_window: bytes
    patched_window: bytes
    solution_bits: int

    @property
    def patch(self) -> bytes:
        return self.patched_window


def crc32_value(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _solve_gf2(rows: list[int], ncols: int = 32) -> int:
    """Solve A x = b over GF(2). Row layout: bits 0..ncols-1 = coefficients, bit ncols = rhs."""
    rows = list(rows)
    pivot_row: dict[int, int] = {}
    r = 0
    for col in range(ncols):
        piv = None
        for k in range(r, len(rows)):
            if (rows[k] >> col) & 1:
                piv = k
                break
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for k in range(len(rows)):
            if k != r and ((rows[k] >> col) & 1):
                rows[k] ^= rows[r]
        pivot_row[col] = r
        r += 1

    for k in range(r, len(rows)):
        if ((rows[k] >> ncols) & 1) and (rows[k] & ((1 << ncols) - 1)) == 0:
            raise ValueError("CRC32 system is inconsistent (target unreachable)")

    x = 0
    for col, ri in pivot_row.items():
        if (rows[ri] >> ncols) & 1:
            x |= 1 << col
    return x


def forge_crc32(data: bytes, target: int, offset: int | None = None) -> CRCForgeResult:
    """Return `data` with a four-byte window patched so crc32(data) == target.

    `offset` defaults to the last four bytes. The window must lie inside `data`,
    and the patch is the minimal-xor solution of the linear system.
    """
    target &= 0xFFFFFFFF
    payload = bytearray(data)
    if len(payload) < 4:
        raise ValueError("need at least 4 bytes to carry the CRC patch")
    if offset is None:
        offset = len(payload) - 4
    if offset < 0 or offset + 4 > len(payload):
        raise ValueError(f"offset {offset} does not leave a 4-byte window")

    base_crc = crc32_value(bytes(payload))
    delta = base_crc ^ target
    if delta == 0:
        window = bytes(payload[offset:offset + 4])
        return CRCForgeResult(bytes(payload), target, offset, window, window, 0)

    # column i: checksum delta produced by flipping bit i inside the window
    vectors: list[int] = []
    for i in range(32):
        probe = bytearray(payload)
        probe[offset + (i >> 3)] ^= 1 << (i & 7)
        vectors.append(crc32_value(bytes(probe)) ^ base_crc)

    rows: list[int] = []
    for b in range(32):
        coeff = 0
        for i in range(32):
            if (vectors[i] >> b) & 1:
                coeff |= 1 << i
        rows.append(coeff | (((delta >> b) & 1) << 32))

    x = _solve_gf2(rows, 32)
    for i in range(32):
        if (x >> i) & 1:
            payload[offset + (i >> 3)] ^= 1 << (i & 7)

    forged = bytes(payload)
    actual = crc32_value(forged)
    if actual != target:
        raise ValueError(f"patch failed: crc {actual:#010x} != target {target:#010x}")

    return CRCForgeResult(
        data=forged,
        target=target,
        offset=offset,
        original_window=bytes(data[offset:offset + 4]),
        patched_window=forged[offset:offset + 4],
        solution_bits=x,
    )


def forge_crc32_hex(data: bytes, target_hex: str, offset: int | None = None) -> CRCForgeResult:
    return forge_crc32(data, int(target_hex.strip().removeprefix("0x"), 16), offset)
