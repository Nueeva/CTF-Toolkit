from __future__ import annotations

import base64
import codecs
import re


def base32_decode_autopad(text: str) -> bytes:
    """Decode Base32 string with automatic padding calculation and whitespace stripping."""
    clean = re.sub(r"[^A-Za-z2-7=]", "", text.strip())
    # Remove existing padding
    unpadded = clean.rstrip("=")
    # Calculate required padding
    pad_len = (8 - (len(unpadded) % 8)) % 8
    padded = unpadded + ("=" * pad_len)
    return base64.b32decode(padded.encode("ascii"), casefold=True)


def rot13(text: str) -> str:
    """Perform ROT-13 symmetric substitution."""
    return codecs.decode(text, "rot_13")


def smart_decode(text: str) -> dict[str, str]:
    """Attempt multiple standard encodings on a string and return successful decodes."""
    results: dict[str, str] = {}
    clean = text.strip()

    # Hex
    try:
        hex_cand = clean[2:] if clean.startswith("0x") else clean
        hex_bytes = bytes.fromhex(hex_cand)
        results["hex"] = hex_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base64
    try:
        b64_pad = clean + ("=" * ((4 - len(clean) % 4) % 4))
        b64_bytes = base64.b64decode(b64_pad)
        if any(32 <= b <= 126 for b in b64_bytes):
            results["base64"] = b64_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base32
    try:
        b32_bytes = base32_decode_autopad(clean)
        if any(32 <= b <= 126 for b in b32_bytes):
            results["base32"] = b32_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # ROT13
    r13 = rot13(clean)
    if r13 != clean:
        results["rot13"] = r13

    return results
