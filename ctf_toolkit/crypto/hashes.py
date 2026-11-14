from __future__ import annotations

import hashlib


def digest(data: bytes, algorithm: str) -> str:
    algo = algorithm.lower()
    if algo not in {"md5", "sha1", "sha256"}:
        raise ValueError("unsupported hash algorithm")
    return hashlib.new(algo, data).hexdigest()


LENGTH_EXTENSION_NOTE = (
    "Length extension tersedia: ctf_toolkit.crypto.length_extension"
    " (length_extend/md5_extend) dan ctf_toolkit.crypto.length_extension_md"
    " (length_extension dengan sweep panjang secret)."
)

def crack_numeric_hash(target_hash: str, max_digits: int = 6, algorithm: str = "md5") -> str | None:
    """
    Brute-force a numeric PIN or token up to `max_digits` (e.g. 6-digit PIN) for a given hash.
    """
    algo = algorithm.lower()
    target = target_hash.strip().lower()
    limit = 10 ** max_digits

    for i in range(limit):
        pin = f"{i:0{max_digits}d}".encode("ascii")
        if hashlib.new(algo, pin).hexdigest() == target:
            return pin.decode("ascii")
    return None


def crack_wordlist_hash(target_hash: str, wordlist: list[str], algorithm: str = "sha256") -> str | None:
    """Find pre-image in wordlist matching target hex digest."""
    algo = algorithm.lower()
    target = target_hash.strip().lower()
    for word in wordlist:
        if hashlib.new(algo, word.encode("utf-8")).hexdigest() == target:
            return word
    return None


def crack_crc32_4byte(target_crc: int, candidates: list[str] | None = None) -> str | None:
    """
    Recover a short word or 4-byte ASCII pre-image matching a target 32-bit CRC32 checksum.
    Uses candidate wordlist first, then falls back to mathematical 4-byte GF(2) CRC32 inversion.
    """
    import zlib

    target = target_crc & 0xFFFFFFFF
    if candidates:
        for word in candidates:
            if (zlib.crc32(word.encode("utf-8")) & 0xFFFFFFFF) == target:
                return word

    # Algebraic 4-byte CRC32 inversion (IEEE 802.3 polynomial 0xEDB88320)
    poly = 0xEDB88320
    crc = target ^ 0xFFFFFFFF
    for _ in range(32):
        if crc & 0x80000000:
            crc = ((crc << 1) & 0xFFFFFFFF) ^ ((poly << 1) | 1) & 0xFFFFFFFF
        else:
            crc = (crc << 1) & 0xFFFFFFFF
    raw = (crc ^ 0xFFFFFFFF).to_bytes(4, "little")
    try:
        return raw.decode("latin-1")
    except Exception:
        return None
