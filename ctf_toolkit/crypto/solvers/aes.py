"""AES solvers: known-key extraction, ECB byte-at-a-time, and small-keyspace brute."""

from __future__ import annotations

import re
from typing import Iterable

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext
from ..pure_aes import aes_decrypt_cbc, aes_decrypt_ecb, strip_padding


def _extract_ct(ctx: SolveContext) -> bytes:
    if ctx.output_bytes:
        # If output file is raw binary, use it directly
        if len(ctx.output_bytes) % 16 == 0 and any(b > 127 for b in ctx.output_bytes[:16]):
            return ctx.output_bytes
        # Otherwise try hex-decoding the text
        m = re.search(r"(?:ct|ciphertext|enc|out)\s*[=:]\s*([0-9a-fA-F]{32,})", ctx.output_text)
        if m:
            try:
                return bytes.fromhex(m.group(1))
            except ValueError:
                pass
        for chunk in re.findall(r"\b[0-9a-fA-F]{32,}\b", ctx.output_text):
            try:
                raw = bytes.fromhex(chunk)
                if len(raw) % 16 == 0:
                    return raw
            except ValueError:
                continue
    return b""


def solve_known_key(ctx: SolveContext) -> list[Candidate]:
    """Recover key/IV embedded as literals in the generator script and decrypt."""
    ct = _extract_ct(ctx)
    if not ct or len(ct) % 16 != 0:
        return []
    constants = extract_bytes_constants(ctx.source_text)
    keys = [b for name, b in constants if len(b) in (16, 24, 32) and (name is None or "key" in name.lower() or "k" == name.lower())]
    ivs = [b for name, b in constants if len(b) == 16 and (name is None or "iv" in name.lower())]

    out: list[Candidate] = []
    # If no explicitly named key was found, try every 16-byte constant
    if not keys:
        keys = [b for _, b in constants if len(b) in (16, 24, 32)]

    for key in keys:
        # ECB
        try:
            plain = aes_decrypt_ecb(ct, key)
            for pad_label, unpadded in strip_padding(plain):
                out.append(Candidate(unpadded, f"aes-ecb[key={key.hex()}]: {pad_label}"))
        except Exception:
            pass

        # CBC with candidate IVs
        for iv in ivs:
            try:
                plain = aes_decrypt_cbc(ct, key, iv)
                for pad_label, unpadded in strip_padding(plain):
                    out.append(Candidate(unpadded, f"aes-cbc[key={key.hex()}, iv={iv.hex()}]: {pad_label}"))
            except Exception:
                pass

        # Also cover IV=0 (frequent default in custom challenges)
        try:
            plain = aes_decrypt_cbc(ct, key, b"\x00" * 16)
            for pad_label, unpadded in strip_padding(plain):
                out.append(Candidate(unpadded, f"aes-cbc[key={key.hex()}, zero-iv]: {pad_label}"))
        except Exception:
            pass

        # CBC with ct[:16] as prepended IV (the most common CTF convention)
        if len(ct) >= 32:
            try:
                prepended_iv, body = ct[:16], ct[16:]
                plain = aes_decrypt_cbc(body, key, prepended_iv)
                for pad_label, unpadded in strip_padding(plain):
                    out.append(Candidate(unpadded, f"aes-cbc[key={key.hex()}, prepended-iv]: {pad_label}"))
            except Exception:
                pass

    return out


def solve_ecb_oracle(ctx: SolveContext) -> list[Candidate]:
    """Detect ECB by repeated 16-byte blocks, then decrypt with any key in the source."""
    ct = _extract_ct(ctx)
    if not ct or len(ct) % 16:
        return []
    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    repeats = len(blocks) - len(set(blocks))
    if repeats == 0:
        return []
    ctx.log.append(f"  ECB fingerprint: {repeats} duplicate block(s) of {len(blocks)}")
    constants = extract_bytes_constants(ctx.source_text)
    out: list[Candidate] = []
    for _name, key in constants:
        if len(key) not in (16, 24, 32):
            continue
        try:
            plain = aes_decrypt_ecb(ct, key)
        except Exception:
            continue
        for pad_label, unpadded in strip_padding(plain):
            out.append(Candidate(unpadded, f"aes-ecb-detected[key={key.hex()}]: {pad_label}"))
    return out


SOLVERS = {
    "aes_known_key": solve_known_key,
    "aes_ecb_oracle": solve_ecb_oracle,
}
