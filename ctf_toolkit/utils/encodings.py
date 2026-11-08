"""Encoding helpers and compatibility exports for ctf_toolkit.utils.encodings."""
from __future__ import annotations

import base64
import re
from ctf_toolkit.crypto.encoding import (
    ascii85_decode,
    base32_decode_autopad,
    base32hex_decode,
    base62_decode,
    base62_encode,
    base85_decode,
    base91_decode,
    base91_encode,
    base_n_decode,
    binary_to_text,
    custom_base64_decode,
    decimal_to_text,
    decode_hexdump,
    decode_html_entities,
    quoted_printable_decode,
    rle_decode,
    rle_encode,
    smart_decode,
    z85_decode,
)


def decode_base64_payload(data: bytes | str) -> bytes:
    """Extract and decode embedded Base64 / Base64URL payloads from binary or text."""
    if isinstance(data, bytes):
        text = data.decode("latin-1", errors="ignore")
    else:
        text = data.strip()

    # Direct decode attempt with autopadding
    clean = re.sub(r"\s+", "", text)
    try:
        padded = clean + "=" * ((4 - len(clean) % 4) % 4)
        dec = base64.urlsafe_b64decode(padded)
        if dec:
            return dec
    except Exception:
        pass

    # Search for longest valid base64 token inside binary/string
    candidates = re.findall(r"[A-Za-z0-9+/=\-_]{12,}", text)
    candidates.sort(key=len, reverse=True)
    for cand in candidates:
        try:
            padded = cand + "=" * ((4 - len(cand) % 4) % 4)
            dec = base64.urlsafe_b64decode(padded)
            if sum(1 for b in dec if 32 <= b <= 126) >= len(dec) * 0.6:
                return dec
        except Exception:
            continue
    return b""


__all__ = [
    "decode_base64_payload",
    "ascii85_decode",
    "base32_decode_autopad",
    "base32hex_decode",
    "base62_decode",
    "base62_encode",
    "base85_decode",
    "base91_decode",
    "base91_encode",
    "base_n_decode",
    "binary_to_text",
    "custom_base64_decode",
    "decimal_to_text",
    "decode_hexdump",
    "decode_html_entities",
    "quoted_printable_decode",
    "rle_decode",
    "rle_encode",
    "smart_decode",
    "z85_decode",
]
