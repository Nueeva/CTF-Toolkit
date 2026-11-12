"""Statistical fingerprinting of an unknown blob.

Used when the challenge ships no generator script, or ships one stripped of any
recognisable operation: the only remaining evidence is the shape of the data
itself. Each metric is cheap, deterministic and independent of language.
"""

from __future__ import annotations

import math
from collections import Counter

ENGLISH_ORDER = "etaoinshrdlcumwfgypbvkjxqz"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return 0.0
    counts = Counter(data)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def letter_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122) / len(data)


def hex_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if chr(b) in "0123456789abcdefABCDEF") / len(data)


def base64_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    alphabet = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return sum(1 for b in data if b in alphabet) / len(data)


def english_score(text: str) -> float:
    """Log-likelihood style score; higher is more English-looking."""
    low = "".join(c.lower() for c in text if c.isalpha())
    if len(low) < 8:
        return 0.0
    counts = Counter(low)
    total = len(low)
    score = 0.0
    for idx, letter in enumerate(ENGLISH_ORDER):
        expected = (26 - idx) / 351
        observed = counts.get(letter, 0) / total
        score += observed * math.log(max(observed, 1e-6) / expected)
    return score


def classify(data: bytes) -> list[tuple[str, float]]:
    """Plausible cipher families for a blob, best first.

    Scores are relative confidences in [0, 1]; a caller should treat them as an
    ordering hint, never as proof.
    """
    if not data:
        return []
    sample = data[:8192]
    entropy = shannon_entropy(sample)
    ioc = index_of_coincidence(sample)
    printable = printable_ratio(sample)
    letters = letter_ratio(sample)
    hex_ratio_v = hex_ratio(sample)
    b64_ratio_v = base64_ratio(sample)

    out: list[tuple[str, float]] = []

    if printable > 0.95 and hex_ratio_v > 0.98 and len(sample) % 2 == 0:
        out.append(("encoding", 0.85))
    if printable > 0.95 and b64_ratio_v > 0.98 and len(sample) % 4 == 0:
        out.append(("encoding", 0.8))
    if printable > 0.9 and letters > 0.7:
        if ioc > 0.060:
            out.append(("classical", 0.85))
        elif ioc > 0.045:
            out.append(("classical", 0.55))
        elif ioc < 0.045:
            out.append(("classical", 0.35))
    if printable < 0.7 and entropy > 7.0:
        out.append(("stream_cipher", 0.5))
    if printable < 0.9 and entropy > 6.0 and ioc < 0.01:
        out.append(("xor", 0.45))

    merged: dict[str, float] = {}
    for cat, score in out:
        merged[cat] = max(merged.get(cat, 0.0), score)
    return sorted(merged.items(), key=lambda kv: -kv[1])


def describe(data: bytes) -> dict:
    sample = data[:8192]
    return {
        "bytes": len(sample),
        "entropy": round(shannon_entropy(sample), 4),
        "ioc": round(index_of_coincidence(sample), 5),
        "printable": round(printable_ratio(sample), 4),
        "letters": round(letter_ratio(sample), 4),
        "hex": round(hex_ratio(sample), 4),
        "base64": round(base64_ratio(sample), 4),
        "english": round(english_score(sample.decode("latin-1")), 4),
    }
