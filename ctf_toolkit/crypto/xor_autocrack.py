"""Statistical auto-cracking for XOR ciphers (xortool-style).

The rest of the toolkit only handles repeating-key XOR when the key (or a
known-plaintext crib) is already known. This module recovers the key from
ciphertext alone:

- ``crack_single_byte_xor`` brute-forces all 256 key bytes and keeps the
  plaintext that scores best against English letter frequencies.
- ``guess_key_lengths`` ranks candidate key lengths by the average
  index of coincidence of the columns they induce: columns at the true
  key length (or a multiple) are mono-alphabetic, so their IoC stays
  near the English value (~0.066) instead of the random one (~0.0385);
  among equally explaining lengths the shortest (fundamental) period
  is ranked first.
- ``crack_repeating_key_xor`` combines both: for each candidate length it
  solves every column as a single-byte XOR, scores the assembled
  plaintext, and returns the best result with the key reduced to its
  shortest period.

Pure stdlib, fully deterministic (no randomness).
"""

from __future__ import annotations

import math

# English letter frequencies in percent (a..z), standard reference table.
_ENGLISH_FREQ = (
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
    0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
    6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
)

_MIN_CT_LEN = 32


def _english_chi2(data: bytes) -> float:
    """Chi-squared distance of the letter distribution from English.

    Lower is more English-like. Non-letter printable characters are
    ignored by the statistic itself but incur a small per-byte penalty;
    non-printable bytes incur a heavy penalty so random decryptions lose.
    """
    counts = [0] * 26
    letters = 0
    penalty = 0.0
    for b in data:
        if 97 <= b <= 122:
            counts[b - 97] += 1
            letters += 1
        elif 65 <= b <= 90:
            counts[b - 65] += 1
            letters += 1
        elif b in (9, 10, 13) or 32 <= b <= 126:
            penalty += 0.5
        else:
            penalty += 25.0
    if letters == 0:
        return float("inf")
    chi2 = 0.0
    for i, observed in enumerate(counts):
        expected = _ENGLISH_FREQ[i] * letters / 100.0
        chi2 += (observed - expected) ** 2 / expected
    return chi2 / letters + penalty / max(len(data), 1)


# Approximate English bigram probabilities for the most common pairs.
# A frequency-only score cannot tell perfect English from English with a
# few percent of its letters replaced; bigrams are position-sensitive,
# so a wrong key byte visibly breaks the pairs around it.
_BIGRAM_PROB = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "re": 0.0185, "on": 0.0176, "at": 0.0149, "en": 0.0145, "nd": 0.0135,
    "ti": 0.0134, "es": 0.0132, "or": 0.0128, "te": 0.0120, "of": 0.0117,
    "ed": 0.0117, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095, "se": 0.0093,
    "ha": 0.0093, "as": 0.0087, "ou": 0.0087, "io": 0.0083, "le": 0.0083,
    "ve": 0.0083, "co": 0.0079, "me": 0.0079, "de": 0.0076, "hi": 0.0076,
    "ri": 0.0073, "ro": 0.0073, "ic": 0.0070, "ne": 0.0069, "ea": 0.0069,
    "ra": 0.0069, "ce": 0.0065, "li": 0.0062, "ch": 0.0060,
    "ll": 0.0058, "be": 0.0058, "ma": 0.0057, "si": 0.0055, "om": 0.0055,
    "ur": 0.0054,
}
_BIGRAM_FLOOR = 0.001


def _score(data: bytes) -> float:
    """English-likeness score; higher is better.

    Combines an average bigram log-probability over the letter stream
    (position-sensitive) with a small letter-frequency chi-squared term
    (global shape). Non-printable decryptions are heavily penalized via
    the chi-squared helper.
    """
    letters = bytes(b + 32 if 65 <= b <= 90 else b for b in data if 65 <= b <= 90 or 97 <= b <= 122)
    pairs = len(letters) - 1
    if pairs > 0:
        total = 0.0
        for i in range(pairs):
            pair = letters[i : i + 2].decode("ascii")
            total += math.log10(_BIGRAM_PROB.get(pair, _BIGRAM_FLOOR))
        bigram_avg = total / pairs
    else:
        bigram_avg = math.log10(_BIGRAM_FLOOR)
    return bigram_avg - 0.2 * _english_chi2(data)


def _xor_with_byte(data: bytes, key_byte: int) -> bytes:
    return bytes(b ^ key_byte for b in data)


def crack_single_byte_xor(ct: bytes) -> tuple[int, bytes, float]:
    """Brute-force a single-byte XOR key.

    Returns ``(key_byte, plaintext, score)`` for the key whose decryption
    looks most like English.
    """
    best_key = 0
    best_pt = _xor_with_byte(ct, 0)
    best_score = _score(best_pt)
    for key_byte in range(1, 256):
        pt = _xor_with_byte(ct, key_byte)
        score = _score(pt)
        if score > best_score:
            best_key, best_pt, best_score = key_byte, pt, score
    return best_key, best_pt, best_score


def _index_of_coincidence(column: bytes) -> float:
    n = len(column)
    if n < 2:
        return 0.0
    counts = [0] * 256
    for b in column:
        counts[b] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


# Index of coincidence of uniformly random bytes: 1/26 over the alphabet
# a single-byte XOR preserves, vs ~0.066 for English text.
_RANDOM_IOC = 1 / 26


def guess_key_lengths(ct: bytes, max_keylen: int = 40, top: int = 5) -> list[int]:
    """Rank candidate repeating-XOR key lengths, best first.

    Each length is scored by the average index of coincidence of its
    columns: when the length equals the true key length (or a multiple),
    every column is a single-byte XOR of English, whose IoC stays near
    the English value (~0.066) instead of the random one (~0.0385).
    Lengths scoring at least halfway from the random baseline to the
    best score are treated as explaining the data; they are returned
    first in ascending order so the fundamental period leads its
    (equally scoring) multiples. The rest follow by score descending.
    """
    max_keylen = min(max_keylen, len(ct) // 2)
    scores: dict[int, float] = {}
    for length in range(1, max_keylen + 1):
        iocs = [
            _index_of_coincidence(ct[offset::length])
            for offset in range(length)
        ]
        scores[length] = sum(iocs) / len(iocs)
    if not scores:
        return []
    threshold = _RANDOM_IOC + 0.5 * (max(scores.values()) - _RANDOM_IOC)
    preferred = sorted(length for length, s in scores.items() if s >= threshold)
    rest = sorted(
        (length for length, s in scores.items() if s < threshold),
        key=lambda length: (-scores[length], length),
    )
    return (preferred + rest)[:top]


def _shortest_period(key: bytes) -> bytes:
    """Reduce a key to its shortest repeating period (b"KEYKEY" -> b"KEY")."""
    for period in range(1, len(key) + 1):
        if (key[:period] * (len(key) // period + 1))[: len(key)] == key:
            return key[:period]
    return key


def crack_repeating_key_xor(
    ct: bytes, max_keylen: int = 40
) -> tuple[bytes, bytes, float]:
    """Fully auto-crack a repeating-key XOR ciphertext.

    Tries the top candidate key lengths from :func:`guess_key_lengths`,
    solves each column as a single-byte XOR, and returns
    ``(key, plaintext, score)`` for the highest-scoring assembly. The key
    is reduced to its shortest period. Raises ``ValueError`` when the
    ciphertext is shorter than 32 bytes.
    """
    if len(ct) < _MIN_CT_LEN:
        raise ValueError(
            f"ciphertext too short to crack reliably: {len(ct)} < {_MIN_CT_LEN} bytes"
        )
    candidates = guess_key_lengths(ct, max_keylen=max_keylen, top=8)
    if 1 not in candidates:
        candidates.append(1)

    best_key = b""
    best_pt = b""
    best_score = float("-inf")
    for length in candidates:
        key = bytes(
            crack_single_byte_xor(ct[offset::length])[0]
            for offset in range(length)
        )
        pt = bytes(b ^ key[i % length] for i, b in enumerate(ct))
        score = _score(pt)
        if score > best_score:
            best_key, best_pt, best_score = key, pt, score
    return _shortest_period(best_key), best_pt, best_score
