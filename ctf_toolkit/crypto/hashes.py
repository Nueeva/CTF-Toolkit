from __future__ import annotations

import hashlib


def digest(data: bytes, algorithm: str) -> str:
    algo = algorithm.lower()
    if algo not in {"md5", "sha1", "sha256"}:
        raise ValueError("unsupported hash algorithm")
    return hashlib.new(algo, data).hexdigest()


LENGTH_EXTENSION_NOTE = (
    "Length-extension attack helper belum diimplementasikan; gunakan library khusus jika dibutuhkan."
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

