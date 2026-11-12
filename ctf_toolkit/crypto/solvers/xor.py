"""XOR solvers: single-byte brute with frequency scoring and repeating-key cracking."""

from __future__ import annotations

import re

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext

_COMMON_WORDS = {b"the", b"and", b"flag", b"key", b"with", b"that", b"from"}


def _score_english(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(data)
    if ratio < 0.8:
        return 0.0
    low = data.lower()
    word_hits = sum(1 for w in _COMMON_WORDS if w in low)
    return ratio + word_hits * 0.5


def _raw_payload(ctx: SolveContext) -> bytes:
    """Same precedence as stream: a hex text digest beats the raw file bytes."""
    text = ctx.output_text.strip()
    if text:
        compact = re.sub(r"\s+", "", text)
        if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
            try:
                return bytes.fromhex(compact)
            except ValueError:
                pass
    return ctx.output_bytes or ctx.output_text.encode("latin-1", "replace")


def solve_single_byte(ctx: SolveContext) -> list[Candidate]:
    payload = _raw_payload(ctx)
    if not payload:
        return []
    # If the source defines a literal byte key, try that first
    constants = extract_bytes_constants(ctx.source_text)
    literal_keys = [b[0] for _, b in constants if len(b) == 1]
    # Check int literals assigned to k/key
    for k, v in ctx.params.items():
        if ("key" in k.lower() or k == "k") and isinstance(v, int) and 0 <= v < 256:
            literal_keys.append(v)

    out: list[Candidate] = []
    for k in set(literal_keys):
        dec = bytes(b ^ k for b in payload)
        out.append(Candidate(dec, f"xor_single_byte[explicit key=0x{k:02x}]"))

    # Exhaustive 256-key sweep
    ranked: list[tuple[float, int, bytes]] = []
    for k in range(256):
        dec = bytes(b ^ k for b in payload)
        score = _score_english(dec)
        if score > 0.0:
            ranked.append((score, k, dec))
    ranked.sort(key=lambda r: -r[0])
    for score, k, dec in ranked[:10]:
        out.append(Candidate(dec, f"xor_single_byte[key=0x{k:02x}, score={score:.2f}]"))
    return out


def solve_repeating_key(ctx: SolveContext) -> list[Candidate]:
    payload = _raw_payload(ctx)
    if not payload or len(payload) < 8:
        return []
    # If the source defines a repeating key literal, try it directly
    constants = extract_bytes_constants(ctx.source_text)
    out: list[Candidate] = []
    for name, k in constants:
        if 2 <= len(k) <= 64:
            dec = bytes(payload[i] ^ k[i % len(k)] for i in range(len(payload)))
            out.append(Candidate(dec, f"xor_repeating_key[literal key={k[:16]!r}]"))

    # Crib drag against known flag prefixes if pattern is available
    m = re.search(r"\b([A-Za-z0-9_]{2,8})\{", ctx.flag_pattern)
    prefix = (m.group(0).encode() if m else b"FLAG{")
    if len(payload) >= len(prefix):
        key_frag = bytes(payload[i] ^ prefix[i] for i in range(len(prefix)))
        # Check if key_frag looks like a repeating word
        for klen in range(2, len(prefix)):
            cand_key = key_frag[:klen]
            dec = bytes(payload[i] ^ cand_key[i % klen] for i in range(len(payload)))
            out.append(Candidate(dec, f"xor_repeating_crib[guessed_key={cand_key!r}]"))
    return out


SOLVERS = {
    "xor_single_byte": solve_single_byte,
    "xor_repeating_key": solve_repeating_key,
}
