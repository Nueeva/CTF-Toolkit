from __future__ import annotations

import re


def decode_charcodes(data: list[int] | str) -> str:
    """Convert an array of character codes (ASCII/Unicode integers) into text."""
    if isinstance(data, list):
        return "".join([chr(n) for n in data if isinstance(n, int)])

    # Extract all digits from string input e.g. "[71, 69, 84]" or "71, 69, 84"
    numbers = [int(n) for n in re.findall(r"\b\d+\b", str(data))]
    return "".join([chr(n) for n in numbers])


def encode_charcodes(text: str) -> list[int]:
    """Convert a string into a list of ordinal character codes."""
    return [ord(c) for c in text]
