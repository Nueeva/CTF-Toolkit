"""LFSR recovery via Berlekamp-Massey over GF(2), pure stdlib.

A maximal-length LFSR emits a bit stream whose shortest linear recurrence has
degree equal to the register size, so 2n observed bits are enough to recover the
taps and predict every following bit. That covers the common CTF shapes:
`output.txt` of raw bits, bits packed into ints, or a keystream generator.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "LFSRModel",
    "berlekamp_massey",
    "lfsr_predict",
    "lfsr_generate",
    "bits_from_bytes",
    "bits_from_int",
    "bits_to_bytes",
    "recover_from_bytes",
]


@dataclass
class LFSRModel:
    taps: list[int]          # C[0..L], C[0] == 1, taps[i] taps s[n-i]
    complexity: int          # L
    warmup: list[int]        # observed bits, needed to seed the recurrence

    def predict(self, count: int) -> list[int]:
        return lfsr_predict(self.warmup, count, self.taps)

    @property
    def polynomial(self) -> str:
        """Tap mask as a binary string, MSB = x^L coefficient."""
        return "".join(str(b) for b in self.taps[1:][::-1]) or "0"


def _as_bits(seq) -> list[int]:
    """Accept a bit list, a '0101' string, or a '1,0,1,1' string.

    The TUI and the JSON API both hand over whatever the operator typed, so the
    normalisation lives here rather than at every call site.
    """
    if isinstance(seq, str):
        cleaned = seq.replace(",", " ").replace(";", " ").split()
        if len(cleaned) > 1:
            return [int(tok) & 1 for tok in cleaned]
        return [int(ch) & 1 for ch in seq if ch in "01"]
    return [int(b) & 1 for b in seq]


def berlekamp_massey(bits) -> tuple[list[int], int]:
    """Return (connection polynomial C, linear complexity L) over GF(2).

    C[0] is always 1; the recurrence is
        s[n] = XOR over j in 1..L of C[j] & s[n-j]

    Accepts a bit list or a string of bits (see `_as_bits`).
    """
    s = _as_bits(bits)
    n = len(s)
    if n == 0:
        return [1], 0

    c = [1] + [0] * n
    b = [1] + [0] * n
    l = 0
    m = 1

    for i in range(n):
        d = s[i]
        for j in range(1, l + 1):
            d ^= c[j] & s[i - j]
        if d == 0:
            m += 1
            continue
        prev = c[:]
        for j in range(n + 1 - m):
            c[j + m] ^= b[j]
        if 2 * l <= i:
            l = i + 1 - l
            b = prev
            m = 1
        else:
            m += 1

    return c[: l + 1], l


def lfsr_predict(bits, count: int, taps: list[int] | None = None) -> list[int]:
    """Continue a bit stream by `count` steps using recovered (or supplied) taps."""
    seq = _as_bits(bits)
    if taps is None:
        taps, _ = berlekamp_massey(seq)
    l = len(taps) - 1
    if l == 0:
        raise ValueError("degenerate polynomial: stream has zero complexity")
    if len(seq) < l:
        raise ValueError(f"need at least {l} warmup bits, got {len(seq)}")

    out: list[int] = []
    for _ in range(count):
        nxt = 0
        for j in range(1, l + 1):
            nxt ^= taps[j] & seq[-j]
        seq.append(nxt)
        out.append(nxt)
    return out


def lfsr_generate(seed_bits, taps: list[int], count: int) -> list[int]:
    """Generate a stream from an explicit initial state (no observation needed)."""
    l = len(taps) - 1
    seq = [int(b) & 1 for b in seed_bits]
    if len(seq) != l:
        raise ValueError(f"seed must hold exactly {l} bits, got {len(seq)}")
    out: list[int] = []
    for _ in range(count):
        nxt = 0
        for j in range(1, l + 1):
            nxt ^= taps[j] & seq[-j]
        seq.append(nxt)
        out.append(nxt)
    return out


def bits_from_bytes(data: bytes, msb_first: bool = True) -> list[int]:
    out: list[int] = []
    for byte in data:
        order = range(7, -1, -1) if msb_first else range(8)
        out.extend((byte >> i) & 1 for i in order)
    return out


def bits_from_int(value: int, width: int | None = None) -> list[int]:
    if value < 0:
        raise ValueError("value must be non-negative")
    if width is None:
        width = max(1, value.bit_length())
    return [(value >> i) & 1 for i in range(width - 1, -1, -1)]


def bits_to_bytes(bits, msb_first: bool = True) -> bytes:
    seq = [int(b) & 1 for b in bits]
    pad = (-len(seq)) % 8
    seq += [0] * pad
    out = bytearray()
    for i in range(0, len(seq), 8):
        chunk = seq[i:i + 8]
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        if not msb_first:
            value = int(f"{value:08b}"[::-1], 2)
        out.append(value)
    return bytes(out)


def recover_from_bytes(observed: bytes, predict: int = 32, msb_first: bool = True) -> LFSRModel:
    """Convenience: bytes in, model + `predict` extra bits available."""
    bits = bits_from_bytes(observed, msb_first)
    taps, l = berlekamp_massey(bits)
    if l == 0:
        raise ValueError("stream has zero linear complexity")
    model = LFSRModel(taps=taps, complexity=l, warmup=bits[:2 * l] if len(bits) >= 2 * l else bits)
    _ = predict  # kept for API symmetry; caller asks model.predict(n)
    return model
