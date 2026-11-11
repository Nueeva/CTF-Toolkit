from __future__ import annotations

import re
from typing import Any

# Standard hash length and character set mapping
HASH_SIGNATURES: list[dict[str, Any]] = [
    {"name": "CRC32", "length": 8, "regex": r"^[0-9a-fA-F]{8}$", "algos": ["CRC-32", "Adler-32"]},
    {"name": "MD5", "length": 32, "regex": r"^[0-9a-fA-F]{32}$", "algos": ["MD5", "MD4", "NTLM", "RIPEMD-128"]},
    {"name": "SHA-1", "length": 40, "regex": r"^[0-9a-fA-F]{40}$", "algos": ["SHA-1", "RIPEMD-160", "MySQL 4.1+"]},
    {"name": "SHA-224 / SHA3-224", "length": 56, "regex": r"^[0-9a-fA-F]{56}$", "algos": ["SHA-224", "SHA3-224"]},
    {"name": "SHA-256 / BLAKE2s", "length": 64, "regex": r"^[0-9a-fA-F]{64}$", "algos": ["SHA-256", "SHA3-256", "BLAKE2s", "SM3"]},
    {"name": "SHA-384 / SHA3-384", "length": 96, "regex": r"^[0-9a-fA-F]{96}$", "algos": ["SHA-384", "SHA3-384"]},
    {"name": "SHA-512 / BLAKE2b", "length": 128, "regex": r"^[0-9a-fA-F]{128}$", "algos": ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]},
]


def identify_hash_format(hash_str: str) -> list[dict[str, Any]]:
    """
    Intelligent hash format identifier (like Hash-Identifier / Name-That-Hash).
    Returns list of probable matching hash algorithms with confidence scores.
    """
    clean = hash_str.strip()
    results: list[dict[str, Any]] = []

    # Check bcrypt / Unix crypt signatures
    if clean.startswith("$2a$") or clean.startswith("$2b$") or clean.startswith("$2y$"):
        return [{"category": "Password Hash", "algorithm": "Bcrypt", "confidence": 0.99}]
    if clean.startswith("$6$"):
        return [{"category": "Linux Shadow", "algorithm": "SHA-512 Crypt", "confidence": 0.99}]
    if clean.startswith("$5$"):
        return [{"category": "Linux Shadow", "algorithm": "SHA-256 Crypt", "confidence": 0.99}]
    if clean.startswith("$1$"):
        return [{"category": "Linux Shadow", "algorithm": "MD5 Crypt", "confidence": 0.99}]
    if clean.startswith("$argon2"):
        return [{"category": "Password Hash", "algorithm": "Argon2", "confidence": 0.99}]

    # Hex length matching
    for sig in HASH_SIGNATURES:
        if len(clean) == sig["length"] and re.match(sig["regex"], clean):
            for algo in sig["algos"]:
                results.append({
                    "category": "Raw Digest",
                    "algorithm": algo,
                    "bit_length": sig["length"] * 4,
                    "confidence": 0.85 if algo in ("MD5", "SHA-1", "SHA-256", "SHA-512") else 0.60,
                })

    return results


def identify_cipher_text(text: str) -> dict[str, Any]:
    """
    Heuristic analyzer that profiles arbitrary ciphertext to identify:
    - Base encodings (Base64, Base32, Base58, Base85, Hex)
    - Morse code, Binary, Octal, A1Z26
    - Classical substitution / transposition ciphers via Index of Coincidence (IoC)
    """
    clean = text.strip()
    res: dict[str, Any] = {
        "length": len(clean),
        "likely_types": [],
        "ioc": 0.0,
        "entropy": 0.0,
    }

    if not clean:
        return res

    import math
    from collections import Counter

    # Calculate Shannon Entropy
    freqs = Counter(clean)
    ent = 0.0
    for cnt in freqs.values():
        p = cnt / len(clean)
        ent -= p * math.log2(p)
    res["entropy"] = round(ent, 3)

    # Calculate Index of Coincidence (for alphabetic text)
    alpha = [c.upper() for c in clean if c.isalpha()]
    if len(alpha) > 1:
        cnts = Counter(alpha)
        n = len(alpha)
        ioc = sum(c * (c - 1) for c in cnts.values()) / (n * (n - 1))
        res["ioc"] = round(ioc, 4)
        if 0.060 <= ioc <= 0.075:
            res["likely_types"].append("Monoalphabetic Substitution / Caesar / Transposition (English-like IoC ~0.067)")
        elif 0.038 <= ioc <= 0.050:
            res["likely_types"].append("Polyalphabetic Cipher (Vigenère / Beaufort / Random IoC ~0.040)")

    # Heuristic encoding matches
    if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0:
        res["likely_types"].append("Hexadecimal (Base16)")
    if re.fullmatch(r"[01\s]+", clean) and len(clean.replace(" ", "")) >= 8:
        res["likely_types"].append("Binary (Base2)")
    if re.fullmatch(r"[A-Za-z0-9+/=]+", clean) and len(clean) % 4 == 0 and len(clean) >= 4:
        res["likely_types"].append("Base64")
    if re.fullmatch(r"[A-Z2-7=]+", clean) and len(clean) >= 8:
        res["likely_types"].append("Base32")
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", clean) and len(clean) >= 20:
        res["likely_types"].append("Base58 (Bitcoin)")
    if clean.startswith("<~") and clean.endswith("~>"):
        res["likely_types"].append("ASCII85 / Adobe Base85")
    if re.fullmatch(r"[.\- /_\n]+", clean) and ("." in clean and "-" in clean):
        res["likely_types"].append("Morse Code")
    if re.fullmatch(r"(?:\d{1,2}[ -/,\.]?)+", clean) and any(sep in clean for sep in ("-", " ", ",")):
        res["likely_types"].append("A1Z26 / Number Positional")

    return res
