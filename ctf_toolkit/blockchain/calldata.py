from __future__ import annotations

import re


def parse_calldata(raw_hex: str) -> dict[str, object]:
    """Parse Ethereum ABI-encoded calldata to extract selector, address/int parameters, and strings."""
    clean = raw_hex.strip()
    if clean.startswith("0x") or clean.startswith("0X"):
        clean = clean[2:]

    if len(clean) % 2 != 0:
        clean = "0" + clean

    raw_bytes = bytes.fromhex(clean)
    selector = raw_bytes[:4].hex() if len(raw_bytes) >= 4 else ""
    body = raw_bytes[4:]

    # Extract 32-byte words
    words: list[str] = []
    for i in range(0, len(body), 32):
        chunk = body[i : i + 32]
        words.append(chunk.hex())

    # Extract printable ASCII strings
    ascii_strings = [
        s.decode("latin1", errors="ignore")
        for s in re.findall(rb"[\x20-\x7e]{4,}", raw_bytes)
    ]

    return {
        "selector": f"0x{selector}",
        "raw_length": len(raw_bytes),
        "word_count": len(words),
        "words": words,
        "ascii_strings": ascii_strings,
    }
