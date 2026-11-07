from __future__ import annotations

import re


def decode_event_log_data(data_hex: str) -> dict[str, object]:
    """Decode EVM event log data field into structured ABI words and extracted strings."""
    clean_hex = data_hex.strip()
    if clean_hex.startswith("0x") or clean_hex.startswith("0X"):
        clean_hex = clean_hex[2:]

    if len(clean_hex) % 64 != 0:
        padding_needed = 64 - (len(clean_hex) % 64)
        clean_hex = clean_hex + ("0" * padding_needed)

    words: list[str] = [clean_hex[i : i + 64] for i in range(0, len(clean_hex), 64)]
    extracted_strings: list[str] = []

    try:
        raw_bytes = bytes.fromhex(clean_hex)
        ascii_matches = re.findall(b"[ -~]{4,}", raw_bytes)
        extracted_strings = [m.decode("utf-8", errors="ignore") for m in ascii_matches]
    except Exception:
        pass

    return {
        "word_count": len(words),
        "words": words,
        "extracted_strings": extracted_strings,
        "hex_length": len(clean_hex),
    }
