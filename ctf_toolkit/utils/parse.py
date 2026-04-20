from __future__ import annotations

import base64
import binascii
import re
from typing import Optional


def parse_int(value: str) -> int:
    data = value.strip().lower()
    if data.startswith("0x"):
        return int(data, 16)
    return int(data, 10)


def parse_bytes(value: str, mode: str = "auto") -> bytes:
    text = value.strip()
    parse_mode = mode.lower()

    if parse_mode == "raw":
        return text.encode("utf-8")
    if parse_mode == "hex":
        return binascii.unhexlify(text)
    if parse_mode == "base64":
        return base64.b64decode(text)

    if parse_mode != "auto":
        raise ValueError("unknown parse mode")

    lowered = text.lower()
    if lowered.startswith("hex:"):
        return binascii.unhexlify(text[4:].strip())
    if lowered.startswith("b64:"):
        return base64.b64decode(text[4:].strip())
    if lowered.startswith("raw:"):
        return text[4:].encode("utf-8")

    try:
        return binascii.unhexlify(text)
    except (ValueError, binascii.Error):
        pass

    try:
        return base64.b64decode(text)
    except (ValueError, binascii.Error):
        pass

    return text.encode("utf-8")


def parse_positive_int(value: str, default: Optional[int] = None) -> Optional[int]:
    value = value.strip()
    if not value:
        return default
    num = int(value)
    if num < 0:
        raise ValueError("must be >= 0")
    return num


def parse_byte_list(text: str) -> bytes:
    raw = text.strip()
    if not raw:
        return b""

    tokens = [token for token in re.split(r"[\s,]+", raw) if token]
    parsed: list[int] = []

    for token in tokens:
        normalized = token.strip().lower()
        if not normalized:
            continue
        try:
            value = int(normalized, 16) if normalized.startswith("0x") else int(normalized, 10)
        except ValueError as exc:
            raise ValueError(f"token byte tidak valid: '{token}' (gunakan angka dec atau 0x..)") from exc
        if not 0 <= value <= 255:
            raise ValueError(f"nilai byte di luar rentang 0..255: {value}")
        parsed.append(value)

    return bytes(parsed)
