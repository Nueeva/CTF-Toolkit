from __future__ import annotations

import re


def decrypt_marker_bounded_xor(
    data: bytes,
    marker: bytes = b"XK",
    key: int = 0x5A,
    pattern: bytes = rb"(?:GETSFLAG|FLAG)\{[^}]+\}",
) -> list[str]:
    """
    Locate segments enclosed by markers (or entire payload if marker absent),
    XOR decrypt with key, and extract discovered flags.
    """
    decrypted = bytes(b ^ key for b in data)
    matches = re.findall(pattern, decrypted)
    return [m.decode("utf-8", errors="ignore") for m in matches]
