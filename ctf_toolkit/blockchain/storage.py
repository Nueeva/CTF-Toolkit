from __future__ import annotations

import re
from Crypto.Hash import keccak


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


def compute_mapping_storage_slot(key: int | str | bytes, slot: int) -> str:
    """Compute the EVM storage slot for mapping(key => value) at slot `slot`.

    Formula: keccak256(padded_key ++ padded_slot)
    """
    if isinstance(key, int):
        k_bytes = key.to_bytes(32, "big")
    elif isinstance(key, str):
        if key.startswith("0x") or key.startswith("0X"):
            raw = bytes.fromhex(key[2:])
            if len(raw) < 32:
                k_bytes = raw.rjust(32, b"\x00")
            else:
                k_bytes = raw[:32]
        else:
            k_bytes = key.encode("utf-8").ljust(32, b"\x00")
    elif isinstance(key, (bytes, bytearray)):
        if len(key) < 32:
            k_bytes = bytes(key).rjust(32, b"\x00")
        else:
            k_bytes = bytes(key)[:32]
    else:
        k_bytes = bytes(32)

    s_bytes = slot.to_bytes(32, "big")
    k = keccak.new(digest_bits=256, data=k_bytes + s_bytes).digest()
    return "0x" + k.hex()


def compute_array_storage_slot(slot: int, index: int = 0, element_slots: int = 1) -> str:
    """Compute the EVM storage slot for a dynamic array element at index `index`.

    Formula: keccak256(padded_slot) + index * element_slots
    """
    s_bytes = slot.to_bytes(32, "big")
    base_int = int.from_bytes(keccak.new(digest_bits=256, data=s_bytes).digest(), "big")
    target_int = base_int + (index * element_slots)
    return "0x" + f"{target_int:064x}"


def extract_packed_storage_locator(slot_hex: str, offset_bytes: int, width_bytes: int) -> int:
    """Extract packed integer value from an EVM storage slot word."""
    clean = slot_hex.strip()
    if clean.startswith("0x") or clean.startswith("0X"):
        clean = clean[2:]
    clean = clean.zfill(64)
    raw = bytes.fromhex(clean)
    start = 32 - offset_bytes - width_bytes
    end = 32 - offset_bytes
    return int.from_bytes(raw[start:end], "big")
