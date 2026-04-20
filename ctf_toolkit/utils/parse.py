from __future__ import annotations

import base64
import binascii
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
