from __future__ import annotations

import re


def decode_storage_slot_string(slot_hex: str) -> str:
    """Decode a Solidity storage slot containing a packed short string (< 32 bytes)."""
    clean_hex = slot_hex.strip()
    if clean_hex.startswith("0x") or clean_hex.startswith("0X"):
        clean_hex = clean_hex[2:]

    # Pad to 64 hex characters (32 bytes) if needed
    if len(clean_hex) < 64:
        clean_hex = clean_hex.zfill(64)

    raw_bytes = bytes.fromhex(clean_hex)
    lowest_byte = raw_bytes[-1]

    # In Solidity:
    # If the lowest bit of the last byte is 0, it's a short string:
    # length = lowest_byte // 2
    if lowest_byte % 2 == 0 and lowest_byte > 0:
        str_len = lowest_byte // 2
        if str_len <= 31:
            try:
                return raw_bytes[:str_len].decode("utf-8")
            except Exception:
                pass

    # Fallback: extract any printable ascii string of length >= 4
    matches = re.findall(b"[ -~]{4,}", raw_bytes)
    if matches:
        return matches[0].decode("utf-8", errors="ignore")

    return ""


def decode_storage_multislot_string(slots: list[str]) -> str:
    """Concatenate and decode multiple 32-byte storage slot hex strings into a continuous string."""
    combined = bytearray()
    for s in slots:
        clean = s.strip()
        if clean.startswith("0x") or clean.startswith("0X"):
            clean = clean[2:]
        if len(clean) < 64:
            clean = clean.ljust(64, "0")
        combined.extend(bytes.fromhex(clean))
    # Extract string up to null or valid printable
    clean_bytes = bytes(combined).rstrip(b"\x00")
    m = re.findall(rb"[\x20-\x7e]{4,}", clean_bytes)
    return m[0].decode("utf-8", errors="ignore") if m else clean_bytes.decode("utf-8", errors="ignore")

