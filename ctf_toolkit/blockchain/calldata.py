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


def decode_calldata_charcodes(raw_hex: str) -> str:
    """Decode calldata consisting of uint256 array of ASCII character codes."""
    parsed = parse_calldata(raw_hex)
    words = parsed.get("words", [])
    if len(words) < 2:
        return ""
    # Usually words[0] is offset (0x20), words[1] is count
    try:
        count = int(words[1], 16)
        char_words = words[2 : 2 + count]
    except Exception:
        char_words = words[2:]

    chars = []
    for w in char_words:
        val = int(w, 16)
        if 0 < val <= 255:
            chars.append(chr(val))
    return "".join(chars)


def reassemble_calldata_slices(raw_hex: str) -> str:
    """Extract and concatenate string slices from ABI-encoded calldata."""
    clean = raw_hex.strip()
    if clean.startswith("0x") or clean.startswith("0X"):
        clean = clean[2:]
    raw_bytes = bytes.fromhex(clean)
    body = raw_bytes[4:] if len(raw_bytes) >= 4 else raw_bytes

    # Scan for 32-byte words that have length followed by ASCII
    parts = []
    i = 0
    while i < len(body):
        word = body[i : i + 32]
        if len(word) == 32:
            val = int.from_bytes(word, "big")
            if 0 < val <= 32 and i + 32 < len(body):
                data_word = body[i + 32 : i + 64]
                ascii_slice = data_word[:val]
                if all(0x20 <= b <= 0x7e for b in ascii_slice):
                    parts.append(ascii_slice.decode("latin1"))
                    i += 64
                    continue
        i += 32
    return "".join(parts)
