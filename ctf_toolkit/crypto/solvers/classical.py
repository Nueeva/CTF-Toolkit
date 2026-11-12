"""Classical cipher solvers: Caesar, Vigenère, and Rail Fence sweeps."""

from __future__ import annotations

import re

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext
from ..signal import english_score

ETAOIN = b"etaoinshrdlcumwfgypbvkjxqz"


def _clean_alpha(text: str) -> str:
    return "".join(c for c in text if c.isalpha())


def solve_caesar(ctx: SolveContext) -> list[Candidate]:
    text = ctx.output_text
    if not text:
        return []
    out: list[Candidate] = []
    for shift in range(1, 26):
        shifted = []
        for c in text:
            if "a" <= c <= "z":
                shifted.append(chr((ord(c) - 97 - shift) % 26 + 97))
            elif "A" <= c <= "Z":
                shifted.append(chr((ord(c) - 65 - shift) % 26 + 65))
            else:
                shifted.append(c)
        out.append(Candidate("".join(shifted).encode("utf-8"), f"caesar[shift={shift}]"))
    return out


def solve_vigenere(ctx: SolveContext) -> list[Candidate]:
    """IoC-driven key-length search, then per-column chi-square key recovery."""
    text = _clean_alpha(ctx.output_text)
    if len(text) < 24:
        return []
    lowered = text.lower()

    # Author-supplied key in the script beats any statistical recovery
    out: list[Candidate] = []
    for name, blob in extract_bytes_constants(ctx.source_text):
        key = blob.decode("latin-1")
        if name and ("key" in name.lower() or name.lower() in ("k", "kunci")) and 1 <= len(key) <= 24 and key.isalpha():
            out.extend(ctx.wrap(_vigenere_decrypt(ctx.output_text, key), f"vigenere[literal key='{key}']"))

    best_lengths: list[tuple[float, int]] = []
    for length in range(2, min(20, len(lowered) // 4)):
        groups = [lowered[i::length] for i in range(length)]
        iocs = [_ioc(g) for g in groups if len(g) > 3]
        if not iocs:
            continue
        best_lengths.append((sum(iocs) / len(iocs), length))
    best_lengths.sort(reverse=True)

    for avg_ioc, length in best_lengths[:3]:
        key = []
        for column in range(length):
            group = lowered[column::length]
            if not group:
                key.append("a")
                continue
            scores = [(sum(abs(group.count(chr(c + 97)) - _ENGLISH_FREQ[c] * len(group) / 100) for c in range(26)), c)
                      for c in range(26)]
            scores.sort()
            key.append(chr(scores[0][1] + 97))
        key_str = "".join(key)
        if set(key_str) == {"a"}:
            continue  # identity substitution: another solver owns this case
        dec = _vigenere_decrypt(ctx.output_text, key_str)
        out.extend(ctx.wrap(dec, f"vigenere[ioc={avg_ioc:.4f}, len={length}, key='{key_str}']"))
    return out


def solve_affine(ctx: SolveContext) -> list[Candidate]:
    text = ctx.output_text.strip()
    if not text:
        return []
    out: list[Candidate] = []
    for a in range(1, 26):
        if a % 2 == 0 or a == 13:
            continue
        if a == 1:
            continue  # a=1 is Caesar shift; caesar_bruteforce solver owns it
        a_inv = pow(a, -1, 26)
        for b in range(26):
            res = []
            for ch in text:
                if "a" <= ch <= "z":
                    res.append(chr((a_inv * (ord(ch) - 97 - b)) % 26 + 97))
                elif "A" <= ch <= "Z":
                    res.append(chr((a_inv * (ord(ch) - 65 - b)) % 26 + 65))
                else:
                    res.append(ch)
            dec_str = "".join(res)
            # When the ciphertext carries braces, require the decrypt to match the flag prefix
            if "{" in text:
                prefix = ctx.flag_prefix() or "FLAG"
                if not dec_str.lower().startswith(prefix.lower()):
                    continue
            out.extend(ctx.wrap(dec_str, f"affine[a={a},b={b}]"))
    return out


def solve_railfence(ctx: SolveContext) -> list[Candidate]:
    text = ctx.output_text.strip()
    if not text or len(text) < 4:
        return []
    # If the text has newlines or spaces, strip or keep depending on CTF format
    clean = text.replace("\n", "").replace("\r", "")
    n = len(clean)
    out: list[Candidate] = []
    for rails in range(2, min(16, n)):
        pattern = []
        r, delta = 0, 1
        for _ in range(n):
            pattern.append(r)
            if r == 0:
                delta = 1
            elif r == rails - 1:
                delta = -1
            r += delta
        # Reconstruct
        pos_by_rail: dict[int, list[int]] = {i: [] for i in range(rails)}
        for idx, rail in enumerate(pattern):
            pos_by_rail[rail].append(idx)
        pt = [""] * n
        curr = 0
        for rail in range(rails):
            for pos in pos_by_rail[rail]:
                pt[pos] = clean[curr]
                curr += 1
        raw_pt = "".join(pt)
        # Avoid emitting scrambled braces from an already-scrambled ciphertext
        if "{" in clean and not raw_pt.startswith(ctx.flag_prefix() or "FLAG"):
            continue
        out.append(Candidate(raw_pt.encode("utf-8"), f"railfence[rails={rails}]"))
    return out


_ENGLISH_FREQ = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15,
                 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06,
                 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]


def _ioc(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    return sum(text.count(c) * (text.count(c) - 1) for c in set(text)) / (n * (n - 1))


def _vigenere_decrypt(text: str, key: str) -> str:
    out = []
    k = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[k % len(key)].lower()) - 97
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            out.append(ch)
    return "".join(out)


SOLVERS = {
    "caesar_bruteforce": solve_caesar,
    "railfence_bruteforce": solve_railfence,
    "vigenere_ic_break": solve_vigenere,
    "affine_bruteforce": solve_affine,
}
