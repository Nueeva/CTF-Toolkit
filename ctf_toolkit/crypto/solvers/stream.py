"""Stream-cipher and PRNG solvers: known key, keystream reuse, LCG and MT19937."""

from __future__ import annotations

import binascii
import re
import struct

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext


def _payload(ctx: SolveContext) -> bytes:
    """Ciphertext bytes: prefer decoding a text digest, fall back to the raw file."""
    text = ctx.output_text.strip()
    if text:
        compact = re.sub(r"\s+", "", text)
        if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
            try:
                return bytes.fromhex(compact)
            except ValueError:
                pass
    return ctx.output_bytes or ctx.output_text.encode("latin-1", "replace")


def _looks_like_int_dump(text: str) -> bool:
    """True when the payload surface is a whitespace-separated integer list."""
    stripped = text.strip()
    if not stripped:
        return False
    lines = [ln for ln in stripped.splitlines() if ln.strip()]
    if not lines:
        return False
    numeric = sum(1 for ln in lines if re.fullmatch(r"\d{1,10}", ln.strip()))
    return numeric >= len(lines) * 0.8 and len(lines) > 50


def _literal_keys(ctx: SolveContext) -> list[bytes]:
    keys = [b for name, b in extract_bytes_constants(ctx.source_text)
            if name is None or "key" in name.lower() or name.lower() in ("k", "kunci", "ik", "sk")]
    for name, value in ctx.params.items():
        if ("key" in name.lower() or name.lower() in ("k", "kunci")) and isinstance(value, int):
            keys.append(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))
    return [k for k in keys if k]


def solve_stream_known_key(ctx: SolveContext) -> list[Candidate]:
    """RC4 / ChaCha20 / Salsa20 with the key embedded in the generator."""
    ct = _payload(ctx)
    if not ct:
        return []
    out: list[Candidate] = []
    keys = _literal_keys(ctx)
    if not keys:
        return []

    lowered = ctx.source_text.lower()
    for key in keys:
        if "rc4" in lowered or "arc4" in lowered:
            for drop in (0, 256, 768, 3072):
                pt = _rc4(ct, key, drop)
                out.append(Candidate(pt, f"rc4[key={key!r}, drop={drop}]"))
        if "chacha" in lowered:
            pt = _chacha20(ct, key, _nonce(ctx))
            if pt:
                out.append(Candidate(pt, f"chacha20[key={key.hex()}]"))
        if "salsa" in lowered:
            pt = _salsa20(ct, key, _nonce(ctx))
            if pt:
                out.append(Candidate(pt, f"salsa20[key={key.hex()}]"))
    return out


def solve_keystream_reuse(ctx: SolveContext) -> list[Candidate]:
    """Two ciphertexts under the same pad: c1 ^ c2 ^ known plaintext."""
    text = ctx.output_text
    blobs = re.findall(r"\b[0-9a-fA-F]{32,}\b", text)
    if len(blobs) < 2:
        return []
    c1, c2 = (bytes.fromhex(blobs[0]), bytes.fromhex(blobs[1]))
    out: list[Candidate] = []
    # Try every literal string in the source as the known plaintext of message 2
    known = [b for _, b in extract_bytes_constants(ctx.source_text) if len(b) >= 8]
    for kp in known:
        if len(kp) >= len(c1):
            out.append(Candidate(bytes(a ^ b ^ c for a, b, c in zip(c1, c2, kp)),
                                 "keystream-reuse: crib from source constant"))
    return out


def solve_lcg(ctx: SolveContext) -> list[Candidate]:
    """LCG keystream: state = (a*state + c) mod m, byte taken from state>>24."""
    a = c_const = m = seed = None
    # Script role names first, then any literal int in the source
    traced = (ctx.report.get("trace") or {}).get("params", {})
    merged = dict(traced)
    merged.update(ctx.params)
    for name, value in merged.items():
        low = name.lower()
        if low in ("a", "mult", "multiplier"):
            a = value
        elif low in ("c", "inc", "increment"):
            c_const = value
        elif low in ("m", "mod", "modulus"):
            m = value
        elif low in ("seed", "s", "state"):
            seed = value
    if None in (a, c_const, m, seed):
        from ..ast_tracer import extract_int_list
        ints = extract_int_list(ctx.source_text)
        if len(ints) >= 4:
            a, c_const, m, seed = ints[0], ints[1], ints[2], ints[3]
    if None in (a, c_const, m, seed):
        return []
    aa, cc, mm, st = int(a), int(c_const), int(m), int(seed)  # type: ignore[arg-type]
    if mm <= 1:
        return []
    ct = _payload(ctx)
    if not ct:
        return []
    out: list[Candidate] = []
    for shift in (0, 8, 16, 24):
        state = st
        pt = bytearray()
        for byte in ct:
            state = (aa * state + cc) % mm
            pt.append(byte ^ ((state >> shift) & 0xFF))
        out.append(Candidate(bytes(pt), f"lcg-keystream[shift={shift}]"))
    return out


def solve_mt_clone(ctx: SolveContext) -> list[Candidate]:
    """Recover MT19937 state from 624 consecutive 32-bit outputs."""
    numbers = [int(x) for x in re.findall(r"\b\d{6,10}\b", ctx.output_text)]
    numbers = [n for n in numbers if n < 2 ** 32]
    if len(numbers) < 624:
        return []
    state = [_untemper(v) for v in numbers[:624]]
    text = ctx.output_text
    ct: bytes
    # The dump may be followed by the ciphertext on the same file: take the hex
    # tail after the integer block, else the last non-numeric blob.
    tail = text.split(str(numbers[623]))[-1] if str(numbers[623]) in text else ""
    hex_tail = re.search(r"[0-9a-fA-F]{32,}", tail)
    if hex_tail:
        try:
            ct = bytes.fromhex(hex_tail.group(0))
        except ValueError:
            ct = b""
    else:
        ct = _payload(ctx) if not _looks_like_int_dump(ctx.output_text) else b""
    if not ct:
        return []
    out: list[Candidate] = []
    for skip in (0, 1):
        clone = _MT(list(state))
        for _ in range(skip):
            clone.next_u32()
        ks = b"".join(struct.pack("<I", clone.next_u32()) for _ in range(len(ct) // 4 + 1))
        plain = bytes(c ^ k for c, k in zip(ct, ks))
        out.append(Candidate(plain, f"mt19937-clone[xor ct, skip={skip}]"))
        out.append(Candidate(ks, f"mt19937-clone[keystream only, skip={skip}]"))
    return out


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------

def _rc4(data: bytes, key: bytes, drop: int = 0) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def _nonce(ctx: SolveContext) -> bytes:
    for name, blob in extract_bytes_constants(ctx.source_text):
        if name and ("nonce" in name.lower() or "iv" in name.lower()) and len(blob) in (8, 12):
            return blob
    return b"\x00" * 8


def _chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes | None:
    try:
        from Crypto.Cipher import ChaCha20
    except ImportError:
        return None
    if len(key) not in (16, 32):
        return None
    try:
        return ChaCha20.new(key=key, nonce=nonce).decrypt(data)
    except Exception:
        return None


def _salsa20(data: bytes, key: bytes, nonce: bytes) -> bytes | None:
    try:
        from Crypto.Cipher import Salsa20
    except ImportError:
        return None
    if len(key) != 32 or len(nonce) != 8:
        return None
    try:
        return Salsa20.new(key=key, nonce=nonce).decrypt(data)
    except Exception:
        return None


def _untemper(y: int) -> int:
    y = _undo_right_shift(y, 18)
    y = _undo_left_shift_mask(y, 15, 0xEFC60000)
    y = _undo_left_shift_mask(y, 7, 0x9D2C5680)
    y = _undo_right_shift(y, 11)
    return y


def _undo_right_shift(y: int, shift: int) -> int:
    x = 0
    for i in range(31, -1, -1):
        bit = (y >> i) & 1
        if i + shift < 32:
            bit ^= (x >> (i + shift)) & 1
        x = (x & ~(1 << i)) | (bit << i)
    return x


def _undo_left_shift_mask(y: int, shift: int, mask: int) -> int:
    x = 0
    for i in range(32):
        bit = (y >> i) & 1
        if i - shift >= 0:
            bit ^= ((x >> (i - shift)) & 1) & ((mask >> i) & 1)
        x = (x & ~(1 << i)) | (bit << i)
    return x


class _MT:
    def __init__(self, state: list[int]) -> None:
        self.mt = list(state)
        self.index = 624

    def next_u32(self) -> int:
        if self.index >= 624:
            self._twist()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.index += 1
        return y & 0xFFFFFFFF

    def _twist(self) -> None:
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y % 2:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0


def solve_lfsr(ctx: SolveContext) -> list[Candidate]:
    """Recover LFSR recurrence from observed bitstream via Berlekamp-Massey."""
    from ..lfsr import berlekamp_massey, lfsr_predict, bits_to_bytes
    # Look for bit sequences in output or source
    raw_candidates = re.findall(r"\b[01]{16,}\b", ctx.output_text + " " + ctx.source_text)
    if not raw_candidates:
        return []
    ct = _payload(ctx)
    out: list[Candidate] = []
    for bit_str in raw_candidates[:3]:
        try:
            taps, L = berlekamp_massey(bit_str)
            if L == 0 or 2 * L > len(bit_str) + 4:
                continue
            # If ciphertext exists, predict enough bits and XOR
            if ct:
                needed = len(ct) * 8 - len(bit_str)
                pred = lfsr_predict(bit_str, max(0, needed), taps) if needed > 0 else []
                full_bits = [int(b) for b in bit_str] + pred
                ks = bits_to_bytes(full_bits)
                plain = bytes(c ^ k for c, k in zip(ct, ks[:len(ct)]))
                out.append(Candidate(plain, f"lfsr-berlekamp-massey[L={L}]"))
            # Also emit keystream as bytes
            ks_only = bits_to_bytes([int(b) for b in bit_str])
            if ks_only:
                out.append(Candidate(ks_only, f"lfsr-keystream[L={L}]"))
        except Exception:
            continue
    return out


SOLVERS = {
    "stream_known_key": solve_stream_known_key,
    "stream_keystream_reuse": solve_keystream_reuse,
    "stream_lfsr": solve_lfsr,
    "prng_lcg_solve": solve_lcg,
    "prng_mt_clone": solve_mt_clone,
}